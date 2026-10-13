#!/usr/bin/env bash
# Validate dashboard rendering, access plans, and untracked test credentials.
# Owner: Observability. Run in the contract-tests image.
# Changes: creates temporary files only.
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

python scripts/render-grafana-dashboards.py \
  --applications observability/tests/fixtures/attribution/applications.csv \
  --output-dir "$workspace/dashboards"

dashboard_count="$(find "$workspace/dashboards" -type f -name '*.json' | wc -l)"
[[ "$dashboard_count" -eq 18 ]] || fail "expected 18 application dashboards"

python scripts/provision-grafana-access.py \
  --access-principals observability/tests/fixtures/access/access-principals.csv \
  --applications observability/tests/fixtures/attribution/applications.csv \
  --dashboards-dir "$workspace/dashboards" \
  --plan-output "$workspace/access-plan.json" \
  --dry-run

python - "$workspace/access-plan.json" "$workspace/dashboards" \
  observability/grafana/dashboards/jengasec-observability.json \
  <<'PY'
import json
import pathlib
import sys

plan = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
dashboards = pathlib.Path(sys.argv[2])
staff_dashboard = json.loads(
    pathlib.Path(sys.argv[3]).read_text(encoding="utf-8")
)
assert len(plan["applications"]) == 18
assert plan["staff"]["members"] == ["JS26-P-9001", "JS26-P-9002"]
app01 = next(
    item
    for item in plan["applications"]
    if item["enterprise"] == "ENT-A" and item["application"] == "APP01"
)
assert app01["members"] == ["JS26-P-0002", "JS26-P-0003"]
app02 = next(
    item
    for item in plan["applications"]
    if item["enterprise"] == "ENT-A" and item["application"] == "APP02"
)
assert app02["members"] == []
dashboard = json.loads(
    (dashboards / "jengasec-ent-a-app01.json").read_text(encoding="utf-8")
)
assert dashboard["uid"] == "jengasec-ent-a-app01"
assert all("jengasec-ent-a-app01" in target["expr"]
           for panel in dashboard["panels"]
           for target in panel["targets"])

required_staff_panels = {
    "Events received",
    "Refused traffic",
    "Quarantined inputs",
    "Unknown attribution",
    "Active alerts",
    "Pipeline targets",
    "Ingestion rate by source",
    "Events by application",
    "Severity distribution",
    "Delivery by destination",
    "Target health",
    "Refused and out-of-scope events",
    "Recent security events",
}
assert staff_dashboard["uid"] == "jengasec-observability"
assert staff_dashboard["time"]["from"] == "now-1h"
assert required_staff_panels == {
    panel["title"] for panel in staff_dashboard["panels"]
}
assert {panel["datasource"]["uid"] for panel in staff_dashboard["panels"]} == {
    "loki", "prometheus"
}
PY

if python scripts/provision-grafana-access.py \
  --access-principals observability/tests/fixtures/access/access-principals-invalid.csv \
  --applications observability/tests/fixtures/attribution/applications.csv \
  --dashboards-dir "$workspace/dashboards" \
  --dry-run >/dev/null 2>&1; then
  fail "invalid Grafana access scope was accepted"
fi

python scripts/prepare-observability-runtime.py \
  --runtime-dir "$workspace/runtime" \
  --access-principals observability/tests/fixtures/access/access-principals.csv
python scripts/prepare-observability-runtime.py \
  --runtime-dir "$workspace/runtime" \
  --access-principals observability/tests/fixtures/access/access-principals.csv
[[ "$(stat --format=%a "$workspace/runtime/grafana-admin-password")" == "600" ]]
[[ "$(stat --format=%a "$workspace/runtime/grafana-user-passwords.json")" == "600" ]]
python - "$workspace/runtime/grafana-user-passwords.json" <<'PY'
import json
import pathlib
import sys

passwords = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert len(passwords) == 4
assert len(set(passwords.values())) == 4
PY

echo "Grafana dashboard and access fixtures passed"
