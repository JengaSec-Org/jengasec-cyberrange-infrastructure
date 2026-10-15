#!/usr/bin/env python3
"""Render Vector's native contract tests without starting ingestion services."""

import copy
import hashlib
import json
import pathlib
import sys
from datetime import datetime, timedelta, timezone

import yaml


root = pathlib.Path(__file__).resolve().parents[2]
source = yaml.safe_load((root / "observability/vector/vector.yaml").read_text())
normalizer = source["transforms"]["normalized_infrastructure"]
normalizer["inputs"] = ["fixture"]
updates = source["transforms"]["infrastructure_attribution_updates"]
updates["inputs"] = ["fixture"]
config = {
    "sources": {"fixture": {"type": "stdin"}},
    "enrichment_tables": {"infrastructure_attribution": {"type": "memory", "ttl": 300}},
    "transforms": {"normalized_infrastructure": normalizer, "infrastructure_attribution_updates": updates},
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

now = datetime.now(timezone.utc)
fresh = {"contract_version": "infrastructure-attribution/1.0", "identity_source": "jengasec_provisioning",
         "mapping_state": "native_only", "authorization": "none", "state": "fresh",
         "captured_at": (now - timedelta(seconds=10)).isoformat().replace("+00:00", "Z"),
         "expires_at": (now + timedelta(seconds=250)).isoformat().replace("+00:00", "Z"),
         "snapshot_hash": "sha256:" + "1" * 64,
         "allocations": [{"ip_address": "192.0.2.10", "participant_id": "9007199254740993", "team_id": "2", "role": "red_participant"}]}
for name, update, condition in (
    ("native-fresh", fresh, 'assert_eq!(.__status__.state, "fresh")\nassert_eq!(."192.0.2.10".participant_id, "9007199254740993")'),
    ("native-unavailable", {**fresh, "state": "unavailable", "allocations": []}, 'assert_eq!(length(keys(.)), 1)\nassert_eq!(.__status__.state, "unavailable")'),
    ("native-reject-authority", {**fresh, "authorization": "allow"}, None),
    ("native-reject-personal-data", {**fresh, "allocations": [{**fresh["allocations"][0], "email": "DO_NOT_EXPORT"}]}, None),
    ("native-reject-stale-identities", {**fresh, "state": "stale"}, None),
    ("native-reject-duplicate", {**fresh, "allocations": fresh["allocations"] * 2}, None),
):
    case = {"name": name, "inputs": [{"insert_at": "infrastructure_attribution_updates", "type": "log", "log_fields": {"message": json.dumps(update)}}]}
    if condition:
        case["outputs"] = [{"extract_from": "infrastructure_attribution_updates", "conditions": [{"type": "vrl", "source": condition}]}]
    else:
        case["no_outputs_from"] = ["infrastructure_attribution_updates"]
    config["tests"].append(case)
sys.stdout.write(yaml.safe_dump(config, sort_keys=False))
