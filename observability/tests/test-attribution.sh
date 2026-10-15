#!/usr/bin/env bash
# Validate positive and negative platform attribution snapshots.
# Owner: Observability. Run in the contract-tests image.
# Changes: creates temporary lookup files only.
set -euo pipefail

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

rendered="$(mktemp -d)"
cleanup() {
  rm -r -- "$rendered"
}
trap cleanup EXIT

python scripts/render-observability-lookups.py \
  --ip-allocations observability/tests/fixtures/attribution/ip-allocations.csv \
  --applications observability/tests/fixtures/attribution/applications.csv \
  --scope-assignments observability/tests/fixtures/attribution/scope-assignments.csv \
  --access-principals observability/tests/fixtures/access/access-principals.csv \
  --output-dir "$rendered" \
  --now 2026-10-10T12:00:30Z

[[ "$(wc -l <"$rendered/applications.csv")" -eq 19 ]] \
  || fail "expected all 18 application instances"
grep -q '^1,2026-10-10T12:00:00Z,ENT-A/APP01,10.108.0.11,ENT-A,APP01,jengasec-ent-a-app01,Internet Banking Portal,jengasec-ent-a-app01/app' \
  "$rendered/applications.csv"
grep -q '^10.60.1.10,JS26-P-0001,JS26-R-001,red-app,active$' \
  "$rendered/ip-allocations.csv"
grep -q '^10.60.1.10,ENT-A,APP01,jengasec-ent-a-app01,10.108.0.11,true$' \
  "$rendered/scope-assignments.csv"
grep -q '^1,2026-10-10T12:00:00Z,JS26-P-0002,blue_team,JS26-B-001,ENT-A,APP01,jengasec-ent-a-app01$' \
  "$rendered/access-principals.csv"

if python scripts/render-observability-lookups.py \
  --ip-allocations observability/tests/fixtures/attribution/ip-allocations-invalid.csv \
  --applications observability/tests/fixtures/attribution/applications.csv \
  --scope-assignments observability/tests/fixtures/attribution/scope-assignments.csv \
  --access-principals observability/tests/fixtures/access/access-principals.csv \
  --output-dir "$rendered/invalid" \
  --now 2026-10-10T12:00:30Z >/dev/null 2>&1; then
  fail "invalid participant allocation was accepted"
fi

python - "$rendered" <<'PY'
import csv
import json
import pathlib
import subprocess
import sys

workspace = pathlib.Path(sys.argv[1]) / "validity"
fixtures = pathlib.Path("observability/tests/fixtures")
clock = "2099-01-01T00:00:00Z"
cases = [
    ("startup-clock", None, {}, {}, 1, 1),
    ("future-clock", clock, {}, {}, 1, 1),
    ("allocation-start", clock, {"valid_from": clock}, {}, 1, 1),
    ("future-allocation", clock, {"valid_from": "2100-01-01T00:00:00Z"}, {}, 0, 0),
    ("expired-allocation", clock, {"valid_until": clock}, {}, 0, 0),
    ("revoked-allocation", clock, {"status": "revoked"}, {}, 0, 0),
    ("reserved-allocation", clock, {"status": "reserved"}, {}, 0, 0),
    ("scope-start", clock, {}, {"valid_from": clock}, 1, 1),
    ("future-scope", clock, {}, {"valid_from": "2100-01-01T00:00:00Z"}, 1, 0),
    ("expired-scope", clock, {}, {"valid_until": clock}, 1, 0),
    ("inactive-scope", clock, {}, {"active": "false"}, 1, 0),
]

for name, now, allocation_changes, scope_changes, allocations, scopes in cases:
    case = workspace / name
    case.mkdir(parents=True)
    for filename, changes in (
        ("ip-allocations.csv", allocation_changes),
        ("scope-assignments.csv", scope_changes),
    ):
        with (fixtures / "attribution" / filename).open(newline="") as handle:
            reader = csv.DictReader(handle)
            fields = reader.fieldnames
            # Isolate one allocation/scope pair for the validity boundary cases.
            rows = [next(reader)]
        rows[0].update(changes)
        with (case / filename).open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)

    output = case / "output"
    command = [
        sys.executable, "scripts/render-observability-lookups.py",
        "--ip-allocations", str(case / "ip-allocations.csv"),
        "--scope-assignments", str(case / "scope-assignments.csv"),
        "--applications", str(fixtures / "attribution/applications.csv"),
        "--access-principals", str(fixtures / "access/access-principals.csv"),
        "--output-dir", str(output),
    ]
    if now is not None:
        command.extend(["--now", now])
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    assert result.returncode == 0, f"{name}: {result.stderr}"
    for filename, expected in (
        ("ip-allocations.csv", allocations),
        ("scope-assignments.csv", scopes),
    ):
        with (output / filename).open(newline="") as handle:
            actual = len(list(csv.DictReader(handle)))
        assert actual == expected, f"{name}: {filename}: {actual} != {expected}"
    snapshot = json.loads((output / "attribution-snapshot.json").read_text())
    assert snapshot["allocations"] == allocations, name
    assert snapshot["scopes"] == scopes, name
PY

echo "attribution lookup fixtures passed"
