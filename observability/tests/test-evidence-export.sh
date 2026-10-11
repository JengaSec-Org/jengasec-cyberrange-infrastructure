#!/usr/bin/env bash
# Validate deterministic, sanitized evidence-pack generation.
# Owner: Observability. Run in the contract-tests image.
# Changes: creates temporary evidence files only.
set -euo pipefail

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

workspace="$(mktemp -d)"
cleanup() {
  rm -r -- "$workspace"
}
trap cleanup EXIT

finding="contracts/fixtures/evidence/valid/finding.json"
telemetry="observability/tests/fixtures/evidence/telemetry.ndjson"
export_root="$workspace/exports"
pack="$export_root/finding-observability-smoke"

python scripts/export-observability-evidence.py \
  --finding "$finding" \
  --telemetry-file "$telemetry" \
  --output-root "$export_root" \
  --exported-at 2026-10-10T09:20:00Z

check-jsonschema \
  --schemafile contracts/evidence-pack.schema.json \
  "$pack/manifest.json"

line_number=0
while IFS= read -r event; do
  line_number=$((line_number + 1))
  printf '%s\n' "$event" >"$workspace/event.json"
  check-jsonschema \
    --schemafile contracts/telemetry-event.schema.json \
    "$workspace/event.json"
done <"$pack/telemetry.ndjson"
[[ "$line_number" -eq 2 ]] || fail "expected two associated telemetry rows"

python - "$pack/telemetry.ndjson" <<'PY' \
  || fail "export omitted attribution or integrity hashes"
import json
import pathlib
import re
import sys

events = [json.loads(line) for line in pathlib.Path(sys.argv[1]).read_text().splitlines()]
assert len(events) == 2
assert all(
    event["actor"]["participant_id"] == "JS26-P-0004"
    and event["actor"]["team_id"] == "JS26-R-002"
    and event["actor"]["team_label"] == "red-app"
    for event in events
)
assert all(
    re.fullmatch(r"sha256:[a-f0-9]{64}", event["integrity_hash"])
    for event in events
)
PY

[[ ! -s "$pack/platform-audit.ndjson" ]] \
  || fail "platform audit boundary was not empty"
[[ ! -s "$pack/competition-events.ndjson" ]] \
  || fail "competition event boundary was not empty"
(
  cd "$pack"
  sha256sum --check --status SHA256SUMS
) || fail "evidence checksums did not verify"

[[ "$(stat --format '%a' "$pack")" == "700" ]] \
  || fail "evidence directory is not owner-only"
while IFS= read -r path; do
  [[ "$(stat --format '%a' "$path")" == "600" ]] \
    || fail "evidence file is not owner-only: $path"
done < <(find "$pack" -maxdepth 1 -type f -print)

before="$(find "$pack" -maxdepth 1 -type f -printf '%f:%i:%T@\n' | sort)"
python scripts/export-observability-evidence.py \
  --finding "$finding" \
  --telemetry-file "$telemetry" \
  --output-root "$export_root" \
  --exported-at 2026-10-10T09:20:00Z >/dev/null
after="$(find "$pack" -maxdepth 1 -type f -printf '%f:%i:%T@\n' | sort)"
[[ "$before" == "$after" ]] || fail "identical export rewrote the evidence pack"

python - "$finding" "$workspace/missing-finding.json" <<'PY'
import json
import pathlib
import sys

finding = json.loads(pathlib.Path(sys.argv[1]).read_text())
finding["telemetry_event_ids"] = [
    "evt_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
]
finding["correlation_ids"] = []
pathlib.Path(sys.argv[2]).write_text(json.dumps(finding) + "\n")
PY
if python scripts/export-observability-evidence.py \
  --finding "$workspace/missing-finding.json" \
  --telemetry-file "$telemetry" \
  --output-root "$workspace/missing" >/dev/null 2>&1; then
  fail "missing cited telemetry was accepted"
fi

python - "$workspace/sensitive.ndjson" <<'PY'
import json
import pathlib
import sys

source = pathlib.Path("contracts/fixtures/telemetry/valid/attributed-request.json")
event = json.loads(source.read_text())
event["actor"]["user_id"] = "person@example.invalid"
pathlib.Path(sys.argv[1]).write_text(json.dumps(event) + "\n")
PY
if python scripts/export-observability-evidence.py \
  --finding "$finding" \
  --telemetry-file "$workspace/sensitive.ndjson" \
  --output-root "$workspace/sensitive" >/dev/null 2>&1; then
  fail "sensitive telemetry was accepted"
fi

if python scripts/export-observability-evidence.py \
  --finding contracts/fixtures/evidence/invalid/path-traversal-finding.json \
  --telemetry-file "$telemetry" \
  --output-root "$workspace/outside" >/dev/null 2>&1; then
  fail "unsafe finding identifier was accepted"
fi

echo "evidence export fixtures passed"
