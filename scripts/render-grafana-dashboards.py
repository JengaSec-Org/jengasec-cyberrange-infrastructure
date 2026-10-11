#!/usr/bin/env python3
"""Render one read-only Grafana dashboard per application.

Owner: Observability. Run with --applications and --output-dir.
Changes: atomically replaces OBS-generated application dashboard files.
"""

import argparse
import csv
import json
import os
import pathlib
import re
import tempfile


APPLICATION = re.compile(r"^APP0[1-9]$")


def fail(message):
    raise SystemExit(message)


def dashboard(enterprise, application, namespace, service_name):
    title = f"{enterprise} {application} — {service_name}"
    return {
        "annotations": {"list": []},
        "editable": False,
        "fiscalYearStartMonth": 0,
        "graphTooltip": 1,
        "id": None,
        "links": [],
        "panels": [
            {
                "datasource": {"type": "prometheus", "uid": "prometheus"},
                "fieldConfig": {"defaults": {}, "overrides": []},
                "gridPos": {"h": 8, "w": 24, "x": 0, "y": 0},
                "id": 1,
                "options": {
                    "legend": {
                        "calcs": [],
                        "displayMode": "list",
                        "placement": "bottom",
                        "showLegend": True,
                    },
                    "tooltip": {"mode": "single", "sort": "none"},
                },
                "targets": [
                    {
                        "editorMode": "code",
                        "expr": f'count({{namespace="{namespace}"}})',
                        "legendFormat": "metric series",
                        "range": True,
                        "refId": "A",
                    }
                ],
                "title": "Application metric series",
                "type": "timeseries",
            },
            {
                "datasource": {"type": "loki", "uid": "loki"},
                "gridPos": {"h": 12, "w": 16, "x": 0, "y": 8},
                "id": 2,
                "options": {
                    "dedupStrategy": "none",
                    "enableLogDetails": True,
                    "showLabels": False,
                    "showTime": True,
                    "sortOrder": "Descending",
                    "wrapLogMessage": True,
                },
                "targets": [
                    {
                        "direction": "backward",
                        "editorMode": "code",
                        "expr": f'{{namespace="{namespace}"}} | json',
                        "queryType": "range",
                        "refId": "A",
                    }
                ],
                "title": "Application events",
                "type": "logs",
            },
            {
                "datasource": {"type": "loki", "uid": "loki"},
                "gridPos": {"h": 12, "w": 8, "x": 16, "y": 8},
                "id": 3,
                "options": {
                    "dedupStrategy": "none",
                    "enableLogDetails": True,
                    "showLabels": False,
                    "showTime": True,
                    "sortOrder": "Descending",
                    "wrapLogMessage": True,
                },
                "targets": [
                    {
                        "direction": "backward",
                        "editorMode": "code",
                        "expr": (
                            f'{{namespace="{namespace}"}} | json '
                            '| verdict="refused"'
                        ),
                        "queryType": "range",
                        "refId": "A",
                    }
                ],
                "title": "Refused traffic",
                "type": "logs",
            },
        ],
        "refresh": "5s",
        "schemaVersion": 41,
        "tags": ["jengasec", "observability", enterprise, application],
        "templating": {"list": []},
        "time": {"from": "now-15m", "to": "now"},
        "timezone": "browser",
        "title": title,
        "uid": f"jengasec-{enterprise.lower()}-{application.lower()}",
        "version": 1,
    }


def write_atomic(path, document):
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as handle:
        temporary = pathlib.Path(handle.name)
        json.dump(document, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary, 0o644)
    os.replace(temporary, path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--applications", type=pathlib.Path, required=True)
    parser.add_argument("--output-dir", type=pathlib.Path, required=True)
    args = parser.parse_args()

    with args.applications.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    if len(rows) != 18:
        fail("application export must contain all 18 application instances")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    expected = set()
    for row in rows:
        enterprise = row["enterprise"]
        application = row["application"]
        namespace = row["namespace"]
        if enterprise not in {"ENT-A", "ENT-B"}:
            fail("application export contains an invalid enterprise")
        if not APPLICATION.fullmatch(application):
            fail("application export contains an invalid application")
        if namespace != f"jengasec-{enterprise.lower()}-{application.lower()}":
            fail("application export contains a non-canonical namespace")
        path = args.output_dir / f"{namespace}.json"
        if path.name in expected:
            fail("application export contains a duplicate namespace")
        expected.add(path.name)
        write_atomic(
            path,
            dashboard(enterprise, application, namespace, row["service_name"]),
        )

    for stale in args.output_dir.glob("jengasec-ent-*-app*.json"):
        if stale.name not in expected:
            stale.unlink()
    print(f"rendered {len(expected)} application dashboards")


if __name__ == "__main__":
    main()
