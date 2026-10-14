#!/usr/bin/env python3
"""Check staff queries against synthetic records through real Loki/Prometheus.

Owner: Observability. Called by smoke-observability.sh in the contract image.
Emits a labelled synthetic batch; no application or competition actions occur.
"""

import argparse
import json
from pathlib import Path
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

import jsonschema


def get(url, parameters=None, tenant=None):
    if parameters:
        url += "?" + urllib.parse.urlencode(parameters)
    headers = {"X-Scope-OrgID": tenant} if tenant else {}
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        raise AssertionError(f"Query failed ({error.code}): {error.read().decode()}") from error


def all_panels(dashboard):
    for panel in dashboard["panels"]:
        if panel["type"] == "row":
            yield from panel.get("panels", [])
        else:
            yield panel


def interpolate(expression, values):
    def variable(match):
        name, formatter = match.groups()
        value = values[name]
        if formatter == "doublequote":
            return json.dumps(value)
        # Grafana escapes RegExp metacharacters, then quotes for LogQL strings.
        escaped = re.sub(r"([\\^$.*+?()\[\]{}|])", r"\\\1", value)
        return ".*" if value == "$__all" else escaped.replace("\\", "\\\\")
    expression = re.sub(r"\$\{([a-z_]+):(doublequote|regex)\}", variable, expression)
    return (expression.replace("$__range", "5m").replace("$__rate_interval", "1m")
            .replace("$__interval", "10s"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--loki-url", required=True)
    parser.add_argument("--prometheus-url", required=True)
    parser.add_argument("--source-url", required=True)
    args = parser.parse_args()
    dashboard = json.loads(Path("observability/grafana/dashboards/jengasec-observability.json").read_text())
    panels = {panel["id"]: panel for panel in all_panels(dashboard)}
    defaults = {variable["name"]: "$__all" if variable["type"] == "custom" else ""
                for variable in dashboard["templating"]["list"]}
    marker = "staff-smoke-" + uuid.uuid4().hex
    emitted = get(args.source_url + "/emit-staff", {"marker": marker})
    assert emitted["synthetic"] is True
    defaults["correlation"] = emitted["trace_id"]
    start = time.time() - 300

    def query(panel, overrides=None):
        values = {**defaults, **(overrides or {})}
        target = panel["targets"][0]
        expression = interpolate(target["expr"], values)
        ranged = target.get("queryType") == "range"
        parameters = {"query": expression}
        if ranged:
            parameters.update(start=f"{start:.3f}", end=f"{time.time():.3f}", step="10", limit="300")
        else:
            parameters["time"] = f"{time.time():.3f}"
        loki = panel["datasource"]["uid"] == "loki"
        base = args.loki_url + "/loki/api/v1" if loki else args.prometheus_url + "/api/v1"
        result = get(base + ("/query_range" if ranged else "/query"), parameters, "staff" if loki else None)
        assert result["status"] == "success", (panel["title"], result)
        return result["data"]["result"]

    def scalar(panel_id, overrides=None):
        return sum(float(item["value"][1]) for item in query(panels[panel_id], overrides))

    def lines(overrides=None):
        return [(stream["stream"], value[1]) for stream in query(panels[8], overrides)
                for value in stream["values"]]

    # Wait for the real collector path; inspect original records for schema/evidence.
    records = []
    raw_query = ('{namespace=~"jengasec-ent-(a|b)-app0[1-9]"} | json | trace_id='
                 + json.dumps(emitted["trace_id"]))
    for _ in range(60):
        result = get(args.loki_url + "/loki/api/v1/query_range",
                     {"query": raw_query, "start": f"{start:.3f}", "limit": 100}, "staff")
        records = [json.loads(value[1]) for stream in result["data"]["result"] for value in stream["values"]]
        if len(records) == emitted["events"]:
            break
        time.sleep(1)
    assert len(records) == 15, f"Expected 15 synthetic records, found {len(records)}"
    schema = json.loads(Path("contracts/telemetry-event.schema.json").read_text())
    validator = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
    for record in records:
        validator.validate(record)
    roles = {record.get("actor", {}).get("team_label", "unattributed") for record in records}
    assert roles == {"red-app", "blue-app", "red-ai", "blue-ai", "unknown", "unattributed"}, roles

    for panel in panels.values():
        if panel.get("targets"):
            query(panel)
    for panel_id, expected in {2: 4, 3: 5, 4: 1, 5: 1, 6: 1, 7: 5}.items():
        actual = scalar(panel_id)
        assert actual == expected, (panels[panel_id]["title"], actual, expected)
    assert len(lines()) == 15
    for filters, expected in [
        ({"role": "red-app"}, 6), ({"role": "blue-app"}, 2),
        ({"role": "red-ai"}, 2), ({"role": "blue-ai"}, 2),
        ({"role": "unknown"}, 2), ({"role": "unattributed"}, 1),
        ({"team": "JS26-B-001"}, 2), ({"participant": "JS26-P-0101"}, 2),
        ({"enterprise": "ENT-B", "application": "APP03"}, 5),
        ({"source": "ids"}, 1), ({"event": "privilege_change"}, 1),
        ({"severity": "high"}, 3), ({"outcome": "error"}, 1),
        ({"verdict": "refused"}, 1),
        ({"correlation": emitted["requests"]["red-app"]}, 6),
        ({"event_id": records[0]["event_id"]}, 1),
        ({"team": "JS26-R-001.*"}, 0),
        ({"team": 'absent" or actor_team_id!="'}, 0),
        ({"participant": "absent\\value"}, 0),
    ]:
        actual = len(lines(filters))
        assert actual == expected, (filters, actual, expected)
    assert scalar(3, {"role": "red-app"}) == 1, "Ingress must not double-count a request"
    assert scalar(4, {"role": "blue-app"}) == 0, "Empty error selection must stay empty"
    assert scalar(2, {"role": "unattributed"}) == 0, "System events must not invent participants"
    print("Staff dashboard: native queries, four roles, filters, correlation and request counts passed")


if __name__ == "__main__":
    main()
