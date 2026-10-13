#!/usr/bin/env python3
"""
what:    Calculate a stable fingerprint for OBS VM release source files
owner:   Observability
usage:   ./scripts/fingerprint-observability-release.py
reads:   tracked observability deployment source below the repository root
changes: nothing; safe to run again
runbook: runbooks/observability.md
"""

import hashlib
import pathlib


ROOT = pathlib.Path(__file__).resolve().parents[1]
DIRECTORIES = (
    "contracts",
    "observability/grafana",
    "observability/loki",
    "observability/prometheus",
    "observability/otel",
    "observability/tests/fixtures/sources",
    "observability/tests/fixtures/website-feed",
    "observability/vector",
)
FILES = (
    "observability/compose.production.yaml",
    "observability/tests/fixtures/access/access-principals.csv",
    "observability/tests/fixtures/attribution/applications.csv",
    "observability/tests/fixtures/attribution/ip-allocations.csv",
    "observability/tests/fixtures/attribution/scope-assignments.csv",
    "scripts/_lib.sh",
    "scripts/cells.yaml",
    "scripts/export-observability-evidence.py",
    "scripts/provision-grafana-access.py",
    "scripts/refresh-observability-state.sh",
    "scripts/render-grafana-dashboards.py",
    "scripts/render-observability-lookups.py",
    "scripts/render-vector-catalogue.py",
    "scripts/sync-observability-lookups.sh",
    "scripts/wait-observability-stack.sh",
)


def included_files():
    paths = {ROOT / value for value in FILES}
    for directory in DIRECTORIES:
        paths.update(
            path
            for path in (ROOT / directory).rglob("*")
            if path.is_file()
            and "__pycache__" not in path.parts
            and path.suffix != ".pyc"
        )
    return sorted(paths, key=lambda path: path.relative_to(ROOT).as_posix())


def main():
    digest = hashlib.sha256()
    for path in included_files():
        relative = path.relative_to(ROOT).as_posix().encode()
        content = path.read_bytes()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    print(digest.hexdigest())


if __name__ == "__main__":
    main()
