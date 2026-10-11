#!/usr/bin/env python3
"""
what:    Validate JengaSec schemas, fixtures, event mappings and cell identifiers
owner:   Observability with the named contract owners
usage:   ./scripts/validate-contracts.py
reads:   contracts/, scripts/cells.yaml
changes: nothing
safe to run again: yes
runbook: runbooks/contract-validation.md
"""

import csv
import ipaddress
import json
import pathlib
import shutil
import subprocess
import sys

import yaml


ROOT = pathlib.Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "contracts"
FIXTURES = CONTRACTS / "fixtures"


class ContractError(Exception):
    """A readable contract validation failure."""


def load_json(path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def load_yaml(path):
    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def schema_check(schema, instance):
    command = shutil.which("check-jsonschema")
    if command is None:
        raise ContractError(
            "check-jsonschema is missing; install contracts/requirements.txt"
        )
    result = subprocess.run(
        [command, "--schemafile", str(schema), str(instance)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode == 0, (result.stdout + result.stderr).strip()


def walk_keys(value):
    if isinstance(value, dict):
        for key, child in value.items():
            yield str(key).lower()
            yield from walk_keys(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_keys(child)


def mappings_for(catalogue, application):
    mappings = list(catalogue["common"])
    mappings.extend(catalogue["briefs"][application]["events"])
    return {row["event"]: row for row in mappings}


def logging_semantic_errors(event, catalogue):
    errors = []
    enterprise = event.get("enterprise", "")
    application = event.get("application", "")
    namespace = event.get("namespace", "")
    if enterprise in {"ENT-A", "ENT-B"} and application in catalogue["briefs"]:
        expected_namespace = (
            f"jengasec-{enterprise.lower()}-{application.lower()}"
        )
        if namespace != expected_namespace:
            errors.append(f"namespace must be {expected_namespace}")

        mapping = mappings_for(catalogue, application).get(event.get("event"))
        if mapping is None:
            errors.append("event is not listed for the application")
        else:
            allowed_detail = set(mapping.get("detail", []))
            actual_detail = set((event.get("detail") or {}).keys())
            unexpected = actual_detail - allowed_detail
            if unexpected:
                errors.append(
                    "detail keys are not catalogued: " + ", ".join(sorted(unexpected))
                )

    sensitive = set(catalogue["never_log_keys"])
    rejected = sensitive.intersection(walk_keys(event))
    if rejected:
        errors.append("sensitive keys present: " + ", ".join(sorted(rejected)))
    return errors


def validate_catalogue(catalogue, telemetry_schema):
    event_types = set(catalogue["event_types"])
    schema_types = set(telemetry_schema["properties"]["event_type"]["enum"])
    if event_types != schema_types:
        missing = sorted(event_types - schema_types)
        extra = sorted(schema_types - event_types)
        raise ContractError(
            f"catalogue/schema event_type mismatch; missing={missing}, extra={extra}"
        )

    sensitive = set(catalogue["never_log_keys"])
    if catalogue["never_log_keys"] != sorted(sensitive):
        raise ContractError("never_log_keys must be unique and sorted")

    groups = [("common", catalogue["common"])]
    groups.extend(
        (f"briefs.{code}", brief["events"])
        for code, brief in catalogue["briefs"].items()
    )
    groups.extend(
        (f"source_events.{source}", rows)
        for source, rows in catalogue["source_events"].items()
    )
    for name, rows in groups:
        seen = set()
        for row in rows:
            if row["event"] in seen:
                raise ContractError(f"duplicate raw event {row['event']} in {name}")
            seen.add(row["event"])
            if row["event_type"] not in event_types:
                raise ContractError(
                    f"unknown event_type {row['event_type']} in {name}"
                )
            forbidden_detail = sensitive.intersection(row.get("detail", []))
            if forbidden_detail:
                raise ContractError(
                    f"sensitive detail keys in {name}: {sorted(forbidden_detail)}"
                )

    for application, brief in catalogue["briefs"].items():
        raw_names = [row["event"] for row in catalogue["common"] + brief["events"]]
        duplicates = sorted({name for name in raw_names if raw_names.count(name) > 1})
        if duplicates:
            raise ContractError(
                f"ambiguous raw events for {application}: {', '.join(duplicates)}"
            )


def expected_application_ip(enterprise, application):
    number = int(application[-2:])
    base = 10 if enterprise == "ENT-A" else 20
    return ipaddress.ip_address(f"10.108.0.{base + number}")


def validate_cells(cells_document, catalogue):
    cells = cells_document.get("cells", [])
    if len(cells) != 18:
        raise ContractError(f"expected 18 application instances, found {len(cells)}")

    seen_namespaces = set()
    seen_ips = set()
    by_key = {}
    for cell in cells:
        enterprise = cell["enterprise"]
        application = cell["application"]
        namespace = cell["namespace"]
        key = (enterprise, application)
        if key in by_key:
            raise ContractError(f"duplicate application instance {key}")
        by_key[key] = cell

        expected_namespace = f"jengasec-{enterprise.lower()}-{application.lower()}"
        if namespace != expected_namespace:
            raise ContractError(f"{key} namespace must be {expected_namespace}")
        if namespace in seen_namespaces:
            raise ContractError(f"duplicate namespace {namespace}")
        seen_namespaces.add(namespace)

        address = ipaddress.ip_address(str(cell["reserved_ip"]))
        if address != expected_application_ip(enterprise, application):
            raise ContractError(f"{key} has unexpected reserved IP {address}")
        if address in seen_ips:
            raise ContractError(f"duplicate reserved IP {address}")
        seen_ips.add(address)

        brief = catalogue["briefs"][application]
        if cell["service"] != brief["service"]:
            raise ContractError(f"{key} service differs from event catalogue")
        if bool(cell["optional"]) != bool(brief.get("optional", False)):
            raise ContractError(f"{key} optional flag differs from event catalogue")

    for application in catalogue["briefs"]:
        left = by_key[("ENT-A", application)]
        right = by_key[("ENT-B", application)]
        if left["enabled"] != right["enabled"]:
            raise ContractError(f"{application} must be enabled symmetrically")

    return by_key


def validate_scope(cells):
    path = CONTRACTS / "scope-assignments.example.csv"
    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    required = {
        "team_id",
        "source_cidr",
        "enterprise",
        "application",
        "namespace",
        "target_ip",
        "active",
        "notes",
    }
    if set(rows[0]) != required:
        raise ContractError("scope example columns do not match the contract")
    for row in rows:
        ipaddress.ip_network(row["source_cidr"])
        key = (row["enterprise"], row["application"])
        if key not in cells:
            raise ContractError(f"scope target does not exist: {key}")
        cell = cells[key]
        if row["namespace"] != cell["namespace"]:
            raise ContractError(f"scope namespace differs for {key}")
        if ipaddress.ip_address(row["target_ip"]) != ipaddress.ip_address(
            str(cell["reserved_ip"])
        ):
            raise ContractError(f"scope target IP differs for {key}")


def validate_fixtures(catalogue):
    logging_schema = CONTRACTS / "logging-contract.schema.json"
    telemetry_schema = CONTRACTS / "telemetry-event.schema.json"

    for path in sorted((FIXTURES / "logging" / "valid").glob("*.json")):
        valid, output = schema_check(logging_schema, path)
        semantic = logging_semantic_errors(load_json(path), catalogue)
        if not valid or semantic:
            raise ContractError(
                f"valid logging fixture failed: {path.name}: {output} {semantic}"
            )

    for path in sorted((FIXTURES / "logging" / "invalid").glob("*.json")):
        valid, _ = schema_check(logging_schema, path)
        semantic = logging_semantic_errors(load_json(path), catalogue)
        if valid and not semantic:
            raise ContractError(f"invalid logging fixture passed: {path.name}")

    for path in sorted((FIXTURES / "telemetry" / "valid").glob("*.json")):
        valid, output = schema_check(telemetry_schema, path)
        if not valid:
            raise ContractError(
                f"valid telemetry fixture failed: {path.name}: {output}"
            )

    for path in sorted((FIXTURES / "telemetry" / "invalid").glob("*.json")):
        valid, _ = schema_check(telemetry_schema, path)
        if valid:
            raise ContractError(f"invalid telemetry fixture passed: {path.name}")

    evidence_schemas = {
        "finding.json": CONTRACTS / "observability-finding.schema.json",
        "manifest.json": CONTRACTS / "evidence-pack.schema.json",
        "path-traversal-finding.json": (
            CONTRACTS / "observability-finding.schema.json"
        ),
        "missing-file-manifest.json": CONTRACTS / "evidence-pack.schema.json",
    }
    for path in sorted((FIXTURES / "evidence" / "valid").glob("*.json")):
        valid, output = schema_check(evidence_schemas[path.name], path)
        if not valid:
            raise ContractError(
                f"valid evidence fixture failed: {path.name}: {output}"
            )
    for path in sorted((FIXTURES / "evidence" / "invalid").glob("*.json")):
        valid, _ = schema_check(evidence_schemas[path.name], path)
        if valid:
            raise ContractError(f"invalid evidence fixture passed: {path.name}")


def main():
    catalogue_path = CONTRACTS / "telemetry-event-catalogue.yaml"
    catalogue_schema = CONTRACTS / "telemetry-event-catalogue.schema.json"
    valid, output = schema_check(catalogue_schema, catalogue_path)
    if not valid:
        raise ContractError(f"catalogue schema validation failed: {output}")

    catalogue = load_yaml(catalogue_path)
    telemetry_schema = load_json(CONTRACTS / "telemetry-event.schema.json")
    validate_catalogue(catalogue, telemetry_schema)
    cells = validate_cells(load_yaml(ROOT / "scripts" / "cells.yaml"), catalogue)
    validate_scope(cells)
    validate_fixtures(catalogue)
    print(
        "contracts valid: "
        f"catalogue v{catalogue['version']} ({catalogue['status']}), "
        "18 application instances, positive and negative fixtures"
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ContractError, KeyError, ValueError, yaml.YAMLError) as exc:
        print(f"contract validation failed: {exc}", file=sys.stderr)
        sys.exit(1)
