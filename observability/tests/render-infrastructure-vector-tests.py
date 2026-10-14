#!/usr/bin/env python3
"""Render Vector's native contract tests without starting ingestion services."""

import copy
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
prepare = copy.deepcopy(source["transforms"]["prepare_infrastructure_http"])
prepare["inputs"] = ["fixture"]
config["transforms"]["prepare_infrastructure_http"] = prepare
config["transforms"]["normalized_infrastructure"]["inputs"].append("prepare_infrastructure_http")
quarantine = copy.deepcopy(source["transforms"]["quarantine_invalid"])
quarantine["inputs"] = ["normalized_infrastructure.dropped"]
config["transforms"]["quarantine_invalid"] = quarantine
metrics = copy.deepcopy(source["transforms"]["quarantine_metrics"])
metrics["inputs"] = ["quarantine_invalid"]
config["transforms"]["quarantine_metrics"] = metrics
config["sinks"]["discard"]["inputs"].append("quarantine_metrics")
for environment, expected in (("validation", "validation"), ("unexpected", "unclassified")):
    rejected = json.loads((root / "contracts/fixtures/infrastructure/valid/host-service.json").read_text())
    rejected["environment"] = environment
    rejected["unrecognized_field"] = "rejection-fixture"
    config["tests"].append({
        "name": "quarantine-environment-" + environment,
        "inputs": [{"insert_at": "prepare_infrastructure_http", "type": "log",
                    "log_fields": {"message": json.dumps(rejected)}}],
        "outputs": [{"extract_from": "quarantine_metrics", "conditions": [{"type": "vrl", "source":
            'assert_eq!(.tags.environment, "' + expected + '")\nassert!(.tags.environment != "live")'}]}],
        "no_outputs_from": ["normalized_infrastructure"],
    })
sys.stdout.write(yaml.safe_dump(config, sort_keys=False))
