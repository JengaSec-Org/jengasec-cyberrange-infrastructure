#!/usr/bin/env python3
"""Apply imported platform scope assignments to existing application releases."""

import argparse
import csv
import http.client
import ipaddress
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

import yaml

from import_platform_exports import (
    ExportError,
    read_platform_cells,
    read_platform_scope,
)


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
DEFAULT_PLATFORM_BASE = "https://jengasec.com"


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

    try:
        with scope_path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            if set(reader.fieldnames or ()) != SCOPE_FIELDS:
                raise ScopeError("scope CSV columns do not match the infrastructure contract")
            assignments = list(reader)
    except OSError as exc:
        raise ScopeError(f"cannot read imported scope assignments: {exc}") from exc
    return build_allowlists(cells_doc["cells"], assignments)


def build_allowlists(cells, assignments):
    allowlists = {}
    for cell in cells:
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
        red_match = (
            RED_TEAM_RE.fullmatch(team_id) if isinstance(team_id, str) else None
        )
        ai_red_match = (
            AI_RED_TEAM_RE.fullmatch(team_id) if isinstance(team_id, str) else None
        )
        if red_match:
            valid_pool = ipaddress.ip_network("10.60.0.0/16")
            pool_max = 54
        elif ai_red_match:
            valid_pool = ipaddress.ip_network("10.64.0.0/16")
            pool_max = 6
        else:
            raise ScopeError(f"scope row {number} has an invalid Red team identifier")
        subnet_number = int(str(source_range.network_address).split(".")[2])
        if (
            source_range.prefixlen != 24
            or not source_range.subnet_of(valid_pool)
            or not 1 <= subnet_number <= pool_max
        ):
            raise ScopeError(
                f"scope row {number}.source_cidr must be a /24 within {valid_pool} "
                f"with a team number from 1 to {pool_max}"
            )
        if row["active"] == "true":
            cell["ranges"].add(str(source_range))

    return allowlists


def read_live_scope_inputs(base_url, token, competition_id):
    if not token:
        raise ScopeError("JENGASEC_DEPLOY_TOKEN is required to fetch live scope exports")
    try:
        competition = int(competition_id)
    except (TypeError, ValueError):
        raise ScopeError("JENGASEC_COMPETITION_ID must be a positive integer") from None
    if competition < 1:
        raise ScopeError("JENGASEC_COMPETITION_ID must be a positive integer")

    parsed_base = urllib.parse.urlsplit(base_url)
    if parsed_base.scheme not in {"http", "https"} or not parsed_base.netloc:
        raise ScopeError("JENGASEC_BASE must be an absolute HTTP(S) URL")
    url = (
        f"{base_url.rstrip('/')}/deployments/api/range-exports/"
        f"?competition={competition}"
    )
    request = urllib.request.Request(
        url, headers={"X-Deploy-Token": token}, method="GET"
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read(5 * 1024 * 1024 + 1)
    except urllib.error.HTTPError as exc:
        raise ScopeError(
            f"platform export request failed with HTTP {exc.code}"
        ) from exc
    except (
        http.client.HTTPException,
        urllib.error.URLError,
        TimeoutError,
        OSError,
    ) as exc:
        raise ScopeError(f"could not fetch platform scope exports: {exc}") from exc
    if len(body) > 5 * 1024 * 1024:
        raise ScopeError("platform scope export response exceeds 5 MiB")
    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ScopeError(f"platform returned invalid scope export JSON: {exc}") from exc
    if (
        not isinstance(payload, dict)
        or not isinstance(payload.get("cells_yaml"), str)
        or not isinstance(payload.get("scope_csv"), str)
    ):
        raise ScopeError("platform returned an invalid scope export response")

    with tempfile.TemporaryDirectory(prefix="jengasec-platform-export-") as temporary:
        directory = pathlib.Path(temporary)
        cells_path = directory / "cells.yaml"
        scope_path = directory / "scope.csv"
        cells_path.write_text(payload["cells_yaml"], encoding="utf-8")
        scope_path.write_text(payload["scope_csv"], encoding="utf-8", newline="")
        try:
            cells = read_platform_cells(cells_path)
            assignments = read_platform_scope(scope_path, cells)
        except ExportError as exc:
            raise ScopeError(f"invalid platform scope exports: {exc}") from exc

        return build_allowlists(cells["cells"], assignments)


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

    competition = os.environ.get("JENGASEC_COMPETITION_ID")
    if competition is not None:
        allowlists = read_live_scope_inputs(
            os.environ.get("JENGASEC_BASE", DEFAULT_PLATFORM_BASE),
            os.environ.get("JENGASEC_DEPLOY_TOKEN", ""),
            competition,
        )
        print(f"loaded scope exports for competition {competition}")
    else:
        allowlists = read_scope_inputs(args.cells, args.scope)
    apply_scope(allowlists, args.chart, args.helm, dry_run=args.dry_run)
    print(f"processed {len(allowlists)} enabled application cells")


if __name__ == "__main__":
    try:
        main()
    except (ScopeError, OSError, subprocess.CalledProcessError) as exc:
        print(f"scope update failed: {exc}", file=sys.stderr)
        sys.exit(1)
