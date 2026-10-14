#!/usr/bin/env python3
"""Translate competition-platform cell and scope exports to infra contracts."""

import argparse
import csv
import io
import ipaddress
import os
import pathlib
import re
import sys
import tempfile

import yaml


APPLICATION_RE = re.compile(r"APP0[1-9]")
NAMESPACE_RE = re.compile(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?")
ENTERPRISES = {"enta": "ENT-A", "entb": "ENT-B"}
CELL_FIELDS = {
    "name",
    "enterprise",
    "code",
    "kind",
    "enabled",
    "service",
    "team",
    "service_ip",
}
PLATFORM_SCOPE_FIELDS = {
    "red_team",
    "red_cell",
    "enterprise",
    "target_cell",
    "target_namespace",
    "target_service_ip",
    "wg_range",
    "round_active",
    "notes",
}
INFRA_SCOPE_FIELDS = [
    "team_id",
    "source_cidr",
    "enterprise",
    "application",
    "namespace",
    "target_ip",
    "active",
    "notes",
]


class ExportError(ValueError):
    """An export does not satisfy the shared platform/infrastructure contract."""


def expected_ip(enterprise, application):
    offset = 10 if enterprise == "ENT-A" else 20
    return ipaddress.ip_address(f"10.108.0.{offset + int(application[-2:])}")


def read_platform_cells(path):
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ExportError(f"cannot read platform cells export: {exc}") from exc
    if not isinstance(document, dict) or not isinstance(document.get("cells"), list):
        raise ExportError("platform cells export must contain a cells list")

    cells = []
    seen_keys = set()
    seen_namespaces = set()
    seen_ips = set()
    for number, row in enumerate(document["cells"], start=1):
        if not isinstance(row, dict):
            raise ExportError(f"platform cell {number} must be a mapping")
        if row.get("kind") == "ai":
            continue
        if row.get("kind") != "app":
            raise ExportError(f"platform cell {number} has an unsupported kind")
        missing = CELL_FIELDS - row.keys()
        if missing:
            raise ExportError(
                f"platform cell {number} is missing fields: {', '.join(sorted(missing))}"
            )

        platform_enterprise = row["enterprise"]
        enterprise = (
            ENTERPRISES.get(platform_enterprise)
            if isinstance(platform_enterprise, str)
            else None
        )
        application = row["code"]
        namespace = row["name"]
        if (
            enterprise is None
            or not isinstance(application, str)
            or not APPLICATION_RE.fullmatch(application)
        ):
            raise ExportError(f"platform cell {number} has an invalid enterprise or application")
        expected_namespace = f"jengasec-{enterprise.lower()}-{application.lower()}"
        if not isinstance(namespace, str) or not NAMESPACE_RE.fullmatch(namespace):
            raise ExportError(f"platform cell {number} has an invalid Kubernetes namespace")
        if namespace != expected_namespace:
            raise ExportError(
                f"{enterprise}/{application} namespace must be {expected_namespace}"
            )
        if not isinstance(row["enabled"], bool):
            raise ExportError(f"{namespace}.enabled must be true or false")
        if not isinstance(row["service"], str) or not row["service"].strip():
            raise ExportError(f"{namespace}.service must be a non-empty string")
        if not isinstance(row["team"], str) or not re.fullmatch(
            r"JS26-B-[0-9]{3}", row["team"]
        ):
            raise ExportError(f"{namespace}.team must be a blue team identifier")
        try:
            address = ipaddress.ip_address(row["service_ip"])
        except (ValueError, TypeError):
            raise ExportError(f"{namespace}.service_ip must be an IPv4 address") from None
        required_ip = expected_ip(enterprise, application)
        if address.version != 4 or address != required_ip:
            raise ExportError(f"{namespace}.service_ip must be {required_ip}")

        key = (enterprise, application)
        if key in seen_keys or namespace in seen_namespaces or address in seen_ips:
            raise ExportError(f"duplicate application, namespace, or service IP at {namespace}")
        seen_keys.add(key)
        seen_namespaces.add(namespace)
        seen_ips.add(address)
        cells.append({
            "namespace": namespace,
            "enterprise": enterprise,
            "application": application,
            "reserved_ip": str(address),
            "optional": application in {"APP08", "APP09"},
            "enabled": row["enabled"],
            "service": row["service"],
            "team": row["team"],
        })

    if len(cells) != 18:
        raise ExportError(f"expected 18 application cells, found {len(cells)}")
    for application in (f"APP{number:02}" for number in range(1, 10)):
        if (("ENT-A", application) in seen_keys) != (("ENT-B", application) in seen_keys):
            raise ExportError(f"{application} must be present in both enterprises")
        left = next(
            cell for cell in cells
            if cell["enterprise"] == "ENT-A" and cell["application"] == application
        )
        right = next(
            cell for cell in cells
            if cell["enterprise"] == "ENT-B" and cell["application"] == application
        )
        if left["enabled"] != right["enabled"]:
            raise ExportError(f"{application} must be enabled symmetrically")
    cells.sort(key=lambda cell: (cell["enterprise"], cell["application"]))
    return {"cells": cells}


def read_platform_scope(path, cells_document):
    try:
        with path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            if set(reader.fieldnames or ()) != PLATFORM_SCOPE_FIELDS:
                raise ExportError(
                    "platform scope export columns do not match the documented contract"
                )
            rows = list(reader)
    except OSError as exc:
        raise ExportError(f"cannot read platform scope export: {exc}") from exc
    if not rows:
        raise ExportError("platform scope export contains no assignments")

    cells = {
        (cell["enterprise"], cell["application"]): cell
        for cell in cells_document["cells"]
    }
    converted = []
    for number, row in enumerate(rows, start=2):
        platform_enterprise = row["enterprise"]
        enterprise = (
            ENTERPRISES.get(platform_enterprise)
            if isinstance(platform_enterprise, str)
            else None
        )
        application = row["target_cell"]
        if (
            enterprise is None
            or not isinstance(application, str)
            or not APPLICATION_RE.fullmatch(application)
        ):
            raise ExportError(f"platform scope row {number} has an unsupported target")
        cell = cells.get((enterprise, application))
        if cell is None:
            raise ExportError(f"platform scope row {number} targets an unexported cell")
        if row["target_namespace"] != cell["namespace"]:
            raise ExportError(f"platform scope row {number} has a mismatched target namespace")
        try:
            source = ipaddress.ip_network(row["wg_range"], strict=True)
            target_ip = ipaddress.ip_address(row["target_service_ip"])
        except (TypeError, ValueError) as exc:
            raise ExportError(f"platform scope row {number} has an invalid address: {exc}") from exc
        if source.version != 4 or target_ip.version != 4:
            raise ExportError(f"platform scope row {number} addresses must be IPv4")
        if target_ip != ipaddress.ip_address(cell["reserved_ip"]):
            raise ExportError(f"platform scope row {number} has a mismatched target service IP")
        if row["round_active"] not in {"true", "false"}:
            raise ExportError(f"platform scope row {number}.round_active must be true or false")
        if not row["red_team"]:
            raise ExportError(f"platform scope row {number} is missing red_team")
        converted.append({
            "team_id": row["red_team"],
            "source_cidr": str(source),
            "enterprise": enterprise,
            "application": application,
            "namespace": cell["namespace"],
            "target_ip": str(target_ip),
            "active": row["round_active"],
            "notes": row["notes"],
        })
    return converted


def write_atomic(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = pathlib.Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--cells", type=pathlib.Path, required=True, help="platform cells.yaml export"
    )
    parser.add_argument(
        "--scope", type=pathlib.Path, required=True,
        help="platform scope-assignments.csv export",
    )
    parser.add_argument("--cells-output", type=pathlib.Path, required=True)
    parser.add_argument("--scope-output", type=pathlib.Path, required=True)
    args = parser.parse_args()

    inputs = {args.cells.resolve(), args.scope.resolve()}
    outputs = {args.cells_output.resolve(), args.scope_output.resolve()}
    if len(outputs) != 2 or inputs & outputs:
        raise ExportError("input and output paths must be distinct")
    cells = read_platform_cells(args.cells)
    scope = read_platform_scope(args.scope, cells)
    cells_yaml = yaml.safe_dump(cells, sort_keys=False, allow_unicode=False)
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=INFRA_SCOPE_FIELDS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(scope)
    write_atomic(args.cells_output, cells_yaml)
    write_atomic(args.scope_output, output.getvalue())
    print(f"imported {len(cells['cells'])} cells and {len(scope)} scope assignments")


if __name__ == "__main__":
    try:
        main()
    except ExportError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
