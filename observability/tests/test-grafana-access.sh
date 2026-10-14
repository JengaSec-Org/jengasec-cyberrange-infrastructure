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
import importlib.util
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

assert staff_dashboard["uid"] == "jengasec-observability"
assert staff_dashboard["time"]["from"] == "now-1h"
health = next(panel for panel in staff_dashboard["panels"] if panel["type"] == "row")
assert health["collapsed"] is True
panels = [p for p in staff_dashboard["panels"] if p["type"] != "row"] + health["panels"]
assert len({panel["id"] for panel in panels}) == len(panels)
assert not any("jengasec_test_" in target["expr"]
               for panel in panels for target in panel.get("targets", []))
variables = {v["name"]: v for v in staff_dashboard["templating"]["list"]}
assert {"red-app", "blue-app", "red-ai", "blue-ai", "unknown", "unattributed"} <= {
    option["value"] for option in variables["role"]["options"]
}
for name in ("team", "participant", "correlation", "event_id"):
    assert variables[name]["type"] == "textbox"
    assert variables[name]["current"]["value"] == ""

spec = importlib.util.spec_from_file_location("access", "scripts/provision-grafana-access.py")
access = importlib.util.module_from_spec(spec)
spec.loader.exec_module(access)
staff_loki = access.loki_datasource("staff")
assert staff_loki["secureJsonData"]["httpHeaderValue1"] == "staff"
assert {field["matcherRegex"] for field in staff_loki["jsonData"]["derivedFields"]} == {
    "^event_id$", "^request_id$", "^trace_id$"
}
app_loki = access.loki_datasource("jengasec-ent-a-app01")
assert "derivedFields" not in app_loki["jsonData"]
assert app_loki["secureJsonData"]["httpHeaderValue1"] == "application-jengasec-ent-a-app01"
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
