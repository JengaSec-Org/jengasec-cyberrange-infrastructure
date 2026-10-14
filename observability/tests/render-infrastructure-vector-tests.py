#!/usr/bin/env python3
"""Render Vector's native contract tests without starting ingestion services."""

import hashlib
import json
import pathlib
import sys

import yaml


root = pathlib.Path(__file__).resolve().parents[2]
source = yaml.safe_load((root / "observability/vector/vector.yaml").read_text())
normalizer = source["transforms"]["normalized_infrastructure"]
normalizer["inputs"] = ["fixture"]
config = {
    "sources": {"fixture": {"type": "stdin"}},
    "transforms": {"normalized_infrastructure": normalizer},
    "sinks": {"discard": {"type": "blackhole", "inputs": ["normalized_infrastructure", "normalized_infrastructure.dropped"]}},
    "tests": [],
}
for status in ("valid", "invalid"):
    for path in sorted((root / "contracts/fixtures/infrastructure" / status).glob("*.json")):
        fixture = json.loads(path.read_text())
        case = {
            "name": status + "-" + path.stem,
            "inputs": [{"insert_at": "normalized_infrastructure", "type": "log", "log_fields": {"raw_message": json.dumps(fixture), "source_hint": "https"}}],
        }
        if status == "valid":
            identity = "infra_" + hashlib.sha256((fixture["resource_id"] + "\n" + fixture["source_event_id"]).encode()).hexdigest()
            case["outputs"] = [{"extract_from": "normalized_infrastructure", "conditions": [{"type": "vrl", "source": f'assert_eq!(.event_id, "{identity}")\nassert_eq!(.record_family, "infrastructure_telemetry")\nassert_eq!(.resource_id, "test-host")\nassert!(!exists(.application))\nassert!(starts_with(string!(.integrity_hash), "sha256:"))'}]}]
        else:
            case["no_outputs_from"] = ["normalized_infrastructure"]
        config["tests"].append(case)
sys.stdout.write(yaml.safe_dump(config, sort_keys=False))
