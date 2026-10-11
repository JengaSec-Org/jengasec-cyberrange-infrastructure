#!/usr/bin/env python3
"""Validate platform view exports and render Vector lookup snapshots."""

import argparse
import csv
import datetime
import ipaddress
import json
import os
import pathlib
import re
import tempfile


TEAM_ID = re.compile(r"^JS26-[A-Z]+-[0-9]{3}$")
PARTICIPANT_ID = re.compile(r"^JS26-P-[0-9]{4,6}$")
APPLICATION = re.compile(r"^APP0[1-9]$")
TEAM_LABELS = {"red-app", "blue-app", "red-ai", "blue-ai", "staff", "judge"}

IP_ALLOCATION_FIELDS = {
    "contract_version",
    "updated_at",
    "allocation_id",
    "ip_address",
    "kind",
    "participant_id",
    "team_id",
    "team_label",
    "namespace",
    "status",
    "valid_from",
    "valid_until",
}
APPLICATION_FIELDS = {
    "contract_version",
    "updated_at",
    "application_instance_id",
    "enterprise",
    "application",
    "namespace",
    "service_name",
    "ip_address",
    "status",
    "optional",
    "enabled",
    "image_digest",
}
SCOPE_FIELDS = {
    "contract_version",
    "updated_at",
    "team_id",
    "source_cidr",
    "enterprise",
    "application",
    "namespace",
    "target_ip",
    "active",
    "valid_from",
    "valid_until",
}
ACCESS_FIELDS = {
    "contract_version",
    "updated_at",
    "participant_id",
    "role",
    "team_id",
    "enterprise",
    "application",
    "namespace",
}


def fail(message):
    raise SystemExit(message)


def read_rows(path, required_fields):
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        fields = set(reader.fieldnames or [])
        missing = required_fields - fields
        if missing:
            fail(f"{path}: missing columns: {', '.join(sorted(missing))}")
        rows = list(reader)
    if not rows:
        fail(f"{path}: export contains no rows")
    for number, row in enumerate(rows, start=2):
        if row["contract_version"] != "1":
            fail(f"{path}:{number}: unsupported contract_version")
    return rows


def parse_time(value, context, optional=False):
    if not value:
        if optional:
            return None
        fail(f"{context}: timestamp is required")
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        fail(f"{context}: invalid timestamp")
    if parsed.tzinfo is None:
        fail(f"{context}: timestamp must include a timezone")
    return parsed.astimezone(datetime.timezone.utc)


def parse_bool(value, context):
    if value == "true":
        return True
    if value == "false":
        return False
    fail(f"{context}: expected true or false")


def active_at(row, now):
    valid_from = parse_time(row["valid_from"], "valid_from")
    valid_until = parse_time(row["valid_until"], "valid_until", optional=True)
    return valid_from <= now and (valid_until is None or now < valid_until)


def write_atomic(path, rows, fieldnames, mode):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", newline="", encoding="utf-8", dir=path.parent, delete=False
    ) as handle:
        temp_path = pathlib.Path(handle.name)
        writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temp_path, mode)
    os.replace(temp_path, path)


def write_json_atomic(path, document, mode):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as handle:
        temp_path = pathlib.Path(handle.name)
        json.dump(document, handle, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temp_path, mode)
    os.replace(temp_path, path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip-allocations", type=pathlib.Path, required=True)
    parser.add_argument("--applications", type=pathlib.Path, required=True)
    parser.add_argument("--scope-assignments", type=pathlib.Path, required=True)
    parser.add_argument("--access-principals", type=pathlib.Path, required=True)
    parser.add_argument("--output-dir", type=pathlib.Path, required=True)
    parser.add_argument("--now")
    parser.add_argument("--file-mode", default="0640")
    args = parser.parse_args()

    now = (
        parse_time(args.now, "--now")
        if args.now
        else datetime.datetime.now(datetime.timezone.utc)
    )
    try:
        mode = int(args.file_mode, 8)
    except ValueError:
        fail("--file-mode must be an octal mode")

    allocation_rows = read_rows(args.ip_allocations, IP_ALLOCATION_FIELDS)
    application_rows = read_rows(args.applications, APPLICATION_FIELDS)
    scope_rows = read_rows(args.scope_assignments, SCOPE_FIELDS)
    access_rows = read_rows(args.access_principals, ACCESS_FIELDS)
    all_rows = [*allocation_rows, *application_rows, *scope_rows, *access_rows]
    updated_times = [
        parse_time(row["updated_at"], "updated_at") for row in all_rows
    ]
    applications = []
    application_index = {}
    application_ips = set()
    for row in application_rows:
        enterprise = row["enterprise"]
        application = row["application"]
        namespace = row["namespace"]
        ip_address = str(ipaddress.ip_address(row["ip_address"]))
        if enterprise not in {"ENT-A", "ENT-B"} or not APPLICATION.fullmatch(application):
            fail("application export contains an invalid identifier")
        expected_namespace = f"jengasec-{enterprise.lower()}-{application.lower()}"
        if namespace != expected_namespace:
            fail(f"{namespace}: non-canonical application namespace")
        if row["application_instance_id"] != f"{enterprise}/{application}":
            fail(f"{namespace}: invalid application_instance_id")
        parse_bool(row["optional"], f"{namespace}.optional")
        parse_bool(row["enabled"], f"{namespace}.enabled")
        key = (enterprise, application)
        if key in application_index or ip_address in application_ips:
            fail("application export contains a duplicate identifier or address")
        rendered = {
            "contract_version": row["contract_version"],
            "updated_at": row["updated_at"],
            "application_instance_id": row["application_instance_id"],
            "ip_address": ip_address,
            "enterprise": enterprise,
            "application": application,
            "namespace": namespace,
            "service_name": row["service_name"],
            "asset": f"{namespace}/app",
            "status": row["status"],
            "optional": row["optional"],
            "enabled": row["enabled"],
            "image_digest": row["image_digest"],
        }
        applications.append(rendered)
        application_index[key] = rendered
        application_ips.add(ip_address)
    if len(applications) != 18:
        fail("application export must contain all 18 application instances")

    access_principals = []
    access_keys = set()
    for row in access_rows:
        participant_id = row["participant_id"]
        role = row["role"]
        if not PARTICIPANT_ID.fullmatch(participant_id):
            fail("access export contains an invalid participant identifier")
        if role not in {"blue_team", "red_team", "judge", "staff"}:
            fail("access export contains an invalid role")
        if role in {"judge", "staff"}:
            if any(row[field] for field in ("team_id", "enterprise", "application", "namespace")):
                fail("global access row contains application scope")
        else:
            if not TEAM_ID.fullmatch(row["team_id"]):
                fail("application access row contains an invalid team identifier")
            app_record = application_index.get((row["enterprise"], row["application"]))
            if app_record is None or row["namespace"] != app_record["namespace"]:
                fail("access export references an unknown application")
        key = (participant_id, role, row["namespace"])
        if key in access_keys:
            fail("access export contains a duplicate principal scope")
        access_keys.add(key)
        access_principals.append(
            {
                "contract_version": "1",
                "updated_at": row["updated_at"],
                "participant_id": participant_id,
                "role": role,
                "team_id": row["team_id"],
                "enterprise": row["enterprise"],
                "application": row["application"],
                "namespace": row["namespace"],
            }
        )

    allocations = []
    allocation_ips = set()
    for row in allocation_rows:
        if row["kind"] not in {"participant", "application", "spare"}:
            fail("IP allocation export contains an invalid kind")
        if row["status"] not in {"reserved", "active", "revoked"}:
            fail("IP allocation export contains an invalid status")
        if row["status"] != "active" or not active_at(row, now):
            continue
        ip_address = str(ipaddress.ip_address(row["ip_address"]))
        if row["kind"] != "participant":
            continue
        if not PARTICIPANT_ID.fullmatch(row["participant_id"]):
            fail(f"{ip_address}: active participant has an invalid identifier")
        if not TEAM_ID.fullmatch(row["team_id"]):
            fail(f"{ip_address}: active participant has an invalid team identifier")
        if row["team_label"] not in TEAM_LABELS:
            fail(f"{ip_address}: active participant has an invalid team label")
        if ip_address in allocation_ips:
            fail("IP allocation export contains a duplicate active address")
        allocations.append(
            {
                "ip_address": ip_address,
                "participant_id": row["participant_id"],
                "team_id": row["team_id"],
                "team_label": row["team_label"],
                "status": "active",
            }
        )
        allocation_ips.add(ip_address)

    scopes = []
    scope_keys = set()
    for row in scope_rows:
        if not parse_bool(row["active"], "scope.active") or not active_at(row, now):
            continue
        if not TEAM_ID.fullmatch(row["team_id"]):
            fail("scope export contains an invalid team identifier")
        network = ipaddress.ip_network(row["source_cidr"], strict=True)
        app_key = (row["enterprise"], row["application"])
        application_record = application_index.get(app_key)
        if application_record is None:
            fail("scope export references an unknown application")
        if (
            row["namespace"] != application_record["namespace"]
            or str(ipaddress.ip_address(row["target_ip"]))
            != application_record["ip_address"]
        ):
            fail("scope export disagrees with the application export")
        for allocation in allocations:
            if allocation["team_id"] != row["team_id"]:
                continue
            if ipaddress.ip_address(allocation["ip_address"]) not in network:
                continue
            key = (*app_key, allocation["ip_address"])
            if key in scope_keys:
                fail("scope export contains a duplicate effective assignment")
            scopes.append(
                {
                    "source_ip": allocation["ip_address"],
                    "enterprise": row["enterprise"],
                    "application": row["application"],
                    "namespace": row["namespace"],
                    "target_ip": application_record["ip_address"],
                    "active": "true",
                }
            )
            scope_keys.add(key)

    applications.sort(key=lambda row: ipaddress.ip_address(row["ip_address"]))
    allocations.sort(key=lambda row: ipaddress.ip_address(row["ip_address"]))
    scopes.sort(key=lambda row: (row["source_ip"], row["enterprise"], row["application"]))
    access_principals.sort(
        key=lambda row: (row["participant_id"], row["namespace"], row["role"])
    )
    write_atomic(
        args.output_dir / "applications.csv",
        applications,
        (
            "contract_version",
            "updated_at",
            "application_instance_id",
            "ip_address",
            "enterprise",
            "application",
            "namespace",
            "service_name",
            "asset",
            "status",
            "optional",
            "enabled",
            "image_digest",
        ),
        mode,
    )
    write_atomic(
        args.output_dir / "ip-allocations.csv",
        allocations,
        ("ip_address", "participant_id", "team_id", "team_label", "status"),
        mode,
    )
    write_atomic(
        args.output_dir / "scope-assignments.csv",
        scopes,
        ("source_ip", "enterprise", "application", "namespace", "target_ip", "active"),
        mode,
    )
    write_atomic(
        args.output_dir / "access-principals.csv",
        access_principals,
        (
            "contract_version",
            "updated_at",
            "participant_id",
            "role",
            "team_id",
            "enterprise",
            "application",
            "namespace",
        ),
        mode,
    )
    write_json_atomic(
        args.output_dir / "attribution-snapshot.json",
        {
            "contract_version": 1,
            "generated_at": now.isoformat().replace("+00:00", "Z"),
            "source_updated_at": max(updated_times).isoformat().replace("+00:00", "Z"),
            "applications": len(applications),
            "allocations": len(allocations),
            "scopes": len(scopes),
            "access_principals": len(access_principals),
        },
        mode,
    )
    print(
        f"rendered {len(applications)} applications, {len(allocations)} active "
        f"participant allocations, {len(scopes)} effective scopes and "
        f"{len(access_principals)} access principals"
    )


if __name__ == "__main__":
    main()
