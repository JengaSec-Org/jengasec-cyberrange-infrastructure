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

echo "attribution lookup fixtures passed"
