#!/usr/bin/env python3
"""
what:    Calculate a stable fingerprint for OBS VM release source files
owner:   Observability
usage:   ./scripts/fingerprint-observability-release.py
reads:   tracked observability deployment source below the repository root
changes: optional private source archive; no repository changes
runbook: runbooks/observability.md
"""

import argparse
import hashlib
import io
import os
import pathlib
import tarfile
import tempfile


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
    "observability/provisioning",
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
    "scripts/provision-infrastructure-grafana.py",
    "scripts/refresh-provisioning-observability.py",
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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=pathlib.Path)
    args = parser.parse_args()
    if args.archive and args.archive.resolve().is_relative_to(ROOT):
        raise SystemExit("write the release archive outside the repository")
    digest = hashlib.sha256()
    members = []
    for path in included_files():
        if path.is_symlink():
            raise SystemExit("release source must contain regular files")
        relative = path.relative_to(ROOT).as_posix().encode()
        content = path.read_bytes()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
        mode = 0o755 if relative.startswith(b"scripts/") and path.suffix in {".py", ".sh"} else 0o644
        members.append((relative.decode(), content, mode))
    if args.archive:
        with tempfile.NamedTemporaryFile(dir=args.archive.parent, delete=False) as handle:
            temporary = pathlib.Path(handle.name)
        try:
            with tarfile.open(temporary, "w:gz") as archive:
                for relative, content, mode in members:
                    info = tarfile.TarInfo(relative)
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    info.mode = mode
                    info.size = len(content)
                    archive.addfile(info, io.BytesIO(content))
            os.replace(temporary, args.archive)
        finally:
            temporary.unlink(missing_ok=True)
    print(digest.hexdigest())


if __name__ == "__main__":
    main()
