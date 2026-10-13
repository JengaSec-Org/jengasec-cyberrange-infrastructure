#!/usr/bin/env python3
"""Apply imported platform scope assignments to existing application releases."""

import argparse
import csv
import ipaddress
import os
import pathlib
import re
import subprocess
import sys
import tempfile

import yaml


ROOT = pathlib.Path(__file__).resolve().parent.parent
CELLS_FILE = pathlib.Path(__file__).resolve().parent / "cells.yaml"
SCOPE_FILE = ROOT / "contracts" / "scope-assignments.csv"
CHART = ROOT / "charts" / "cell"
STAFF_CIDR = "10.63.0.0/24"
BLUE_TEAM_RE = re.compile(r"JS26-B-([0-9]{3})")
RED_TEAM_RE = re.compile(r"JS26-R-([0-9]{3})")
AI_RED_TEAM_RE = re.compile(r"JS26-AIR-([0-9]{3})")
SCOPE_FIELDS = {
    "team_id",
    "source_cidr",
    "enterprise",
    "application",
    "namespace",
    "target_ip",
    "active",
    "notes",
}


class ScopeError(ValueError):
    """Imported scope data cannot safely be applied."""


def blue_team_cidr(team_id):
    match = BLUE_TEAM_RE.fullmatch(team_id) if isinstance(team_id, str) else None
    if match is None:
        raise ScopeError(f"invalid application owner team identifier: {team_id!r}")
    team_number = int(match.group(1))
    if not 1 <= team_number <= 18:
        raise ScopeError(f"blue team number must be between 001 and 018: {team_id}")
    return f"10.61.{team_number}.0/24"


def read_scope_inputs(cells_path, scope_path):
    try:
        cells_doc = yaml.safe_load(cells_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ScopeError(f"cannot read imported cells: {exc}") from exc
    if not isinstance(cells_doc, dict) or not isinstance(cells_doc.get("cells"), list):
        raise ScopeError("imported cells must contain a cells list")

    allowlists = {}
    for cell in cells_doc["cells"]:
        if not isinstance(cell, dict):
            raise ScopeError("each imported cell must be a mapping")
        if not isinstance(cell.get("enabled"), bool):
            raise ScopeError("each imported cell must have an enabled boolean")
        namespace = cell.get("namespace")
        if not isinstance(namespace, str) or not namespace:
            raise ScopeError("each imported cell must have a namespace")
        if not cell["enabled"]:
            continue
        enterprise = cell.get("enterprise")
        application = cell.get("application")
        team_id = cell.get("team")
        reserved_ip = cell.get("reserved_ip")
        if enterprise not in {"ENT-A", "ENT-B"} or not isinstance(application, str):
            raise ScopeError(f"{namespace} has an invalid enterprise or application")
        try:
            address = ipaddress.ip_address(reserved_ip)
        except (TypeError, ValueError):
            raise ScopeError(f"{namespace}.reserved_ip must be a valid IP address") from None
        if address.version != 4:
            raise ScopeError(f"{namespace}.reserved_ip must be IPv4")
        if namespace in allowlists:
            raise ScopeError(f"duplicate enabled cell namespace: {namespace}")
        allowlists[namespace] = {
            "enterprise": enterprise,
            "application": application,
            "target_ip": reserved_ip,
            "ranges": {STAFF_CIDR, blue_team_cidr(team_id)},
        }
    if not allowlists:
        raise ScopeError("there are no enabled application cells to scope")

    try:
        with scope_path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            if set(reader.fieldnames or ()) != SCOPE_FIELDS:
                raise ScopeError("scope CSV columns do not match the infrastructure contract")
            assignments = list(reader)
    except OSError as exc:
        raise ScopeError(f"cannot read imported scope assignments: {exc}") from exc

    for number, row in enumerate(assignments, start=2):
        if row["active"] not in {"true", "false"}:
            raise ScopeError(f"scope row {number}.active must be true or false")
        namespace = row["namespace"]
        cell = allowlists.get(namespace)
        if cell is None:
            raise ScopeError(f"scope row {number} targets a disabled or unknown cell")
        if (
            row["enterprise"] != cell["enterprise"]
            or row["application"] != cell["application"]
            or row["target_ip"] != cell["target_ip"]
        ):
            raise ScopeError(f"scope row {number} does not match cell {namespace}")
        try:
            source_range = ipaddress.ip_network(row["source_cidr"], strict=True)
            target_ip = ipaddress.ip_address(row["target_ip"])
        except (TypeError, ValueError) as exc:
            raise ScopeError(f"scope row {number} has an invalid address: {exc}") from exc
        if source_range.version != 4 or target_ip.version != 4:
            raise ScopeError(f"scope row {number} must use IPv4 addresses")
        team_id = row["team_id"]
        red_match = RED_TEAM_RE.fullmatch(team_id) if isinstance(team_id, str) else None
        ai_red_match = (
            AI_RED_TEAM_RE.fullmatch(team_id) if isinstance(team_id, str) else None
        )
        if red_match:
            team_number = int(red_match.group(1))
            expected_range = f"10.60.{team_number}.0/24"
            if not 1 <= team_number <= 54:
                raise ScopeError(f"scope row {number} has an invalid Red team number")
        elif ai_red_match:
            team_number = int(ai_red_match.group(1))
            expected_range = f"10.64.{team_number}.0/24"
            if not 1 <= team_number <= 6:
                raise ScopeError(f"scope row {number} has an invalid AI Red team number")
        else:
            raise ScopeError(f"scope row {number} has an invalid Red team identifier")
        if source_range != ipaddress.ip_network(expected_range):
            raise ScopeError(
                f"scope row {number}.source_cidr must be {expected_range} for {team_id}"
            )
        if row["active"] == "true":
            cell["ranges"].add(str(source_range))

    return allowlists


def apply_scope(allowlists, chart, helm_bin, dry_run=False):
    for namespace, cell in allowlists.items():
        values = {
            "ingress": {"allowedRanges": sorted(cell["ranges"])}
        }
        with tempfile.TemporaryDirectory(prefix="jengasec-scope-") as temporary_dir:
            values_path = pathlib.Path(temporary_dir) / "scope-values.yaml"
            values_path.write_text(
                yaml.safe_dump(values, sort_keys=False), encoding="utf-8"
            )
            command = [
                helm_bin,
                "upgrade",
                namespace,
                str(chart),
                "--namespace",
                namespace,
                "--reuse-values",
                "--values",
                str(values_path),
            ]
            if dry_run:
                command.append("--dry-run=client")
            else:
                command.append("--wait")
            print(f"{'would update' if dry_run else 'updating'} {namespace}")
            subprocess.run(command, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cells", type=pathlib.Path, default=CELLS_FILE)
    parser.add_argument("--scope", type=pathlib.Path, default=SCOPE_FILE)
    parser.add_argument("--chart", type=pathlib.Path, default=CHART)
    parser.add_argument("--helm", default=os.environ.get("HELM_BIN", "helm"))
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    allowlists = read_scope_inputs(args.cells, args.scope)
    apply_scope(allowlists, args.chart, args.helm, dry_run=args.dry_run)
    print(f"processed {len(allowlists)} enabled application cells")


if __name__ == "__main__":
    try:
        main()
    except (ScopeError, OSError, subprocess.CalledProcessError) as exc:
        print(f"scope update failed: {exc}", file=sys.stderr)
        sys.exit(1)
