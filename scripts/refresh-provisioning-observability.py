#!/usr/bin/env python3
"""Publish read-only, native provisioning attribution snapshots.

Owner: Observability. This format cannot grant access or populate the legacy
competition identity views. PostgreSQL source ownership stays with Platform.
"""

import argparse
import configparser
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
MAX_BYTES = 8 * 1024 * 1024
MAX_ROWS = 10000
MAX_TOTAL_ROWS = 20000
TABLES = ("participants", "teams", "allocations", "targets", "assignments", "event_windows")
SOURCE_FIELDS = {
    "participants": {"participant_id", "team_id", "role", "eligible", "status", "created_at", "updated_at"},
    "teams": {"team_id", "category", "side", "created_at"},
    "allocations": {"allocation_id", "participant_id", "vpn_address", "interface_name", "status", "allocated_at", "last_changed_at"},
    "targets": {"target_id", "owner_team_id", "category", "namespace", "endpoint_ip", "protocol", "ports", "enabled"},
    "assignments": {"assignment_id", "red_team_id", "target_id", "starts_at", "ends_at"},
    "event_windows": {"event_id", "starts_at", "ends_at"},
}
PRIMARY_KEYS = dict(zip(TABLES, ("participant_id", "team_id", "allocation_id", "target_id", "assignment_id", "event_id")))


class SnapshotError(ValueError):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def utc_now():
    return datetime.now(timezone.utc)


def timestamp(value, nullable=False):
    if value is None and nullable:
        return None
    if not isinstance(value, str) or len(value) > 40:
        raise SnapshotError("invalid_source")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None:
            raise ValueError("timezone required")
        return result.astimezone(timezone.utc)
    except (ValueError, OverflowError) as error:
        raise SnapshotError("invalid_source") from error


def iso(value):
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def identifier(value, nullable=False):
    if value is None and nullable:
        return None
    if not isinstance(value, str) or not re.fullmatch(r"[1-9][0-9]{0,18}", value) or int(value) > 2**63 - 1:
        raise SnapshotError("invalid_source")
    return value


def boolean(value):
    if type(value) is not bool:
        raise SnapshotError("invalid_source")
    return value


def enum(value, values):
    if not isinstance(value, str) or value not in {*values, "unknown"}:
        raise SnapshotError("invalid_source")
    return value


def address(value, allow_unknown=False):
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 45:
        raise SnapshotError("invalid_source")
    try:
        if "%" in value:
            raise ValueError("scoped address")
        return str(ipaddress.ip_address(value))
    except ValueError as error:
        if allow_unknown:
            return None
        raise SnapshotError("invalid_source") from error


def named(value, pattern, maximum):
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > maximum or not re.fullmatch(pattern, value):
        raise SnapshotError("invalid_source")
    return value


def window_state(start, end, now):
    if start is not None and end is not None and start >= end:
        raise SnapshotError("invalid_source")
    if end is not None and now >= end:
        return "expired"
    if start is not None and now < start:
        return "pending"
    return "active" if start is not None and end is not None else "unknown"


def build_snapshot(source, *, now=None, max_age=120, transport="local_peer", database="jengasec"):
    now = now or utc_now()
    if not 30 <= max_age <= 300 or transport not in {"local_peer", "tls"}:
        raise SnapshotError("invalid_configuration")
    if not isinstance(source, dict) or set(source) != {"captured_at", "read_only", "tls", "database", *TABLES}:
        raise SnapshotError("invalid_source")
    if source["read_only"] is not True or source["database"] != database or type(source["tls"]) is not bool:
        raise SnapshotError("read_only_boundary_failed")
    if transport == "tls" and source["tls"] is not True:
        raise SnapshotError("tls_required")
    captured = timestamp(source["captured_at"])
    try:
        expires = captured + timedelta(seconds=max_age)
    except OverflowError as error:
        raise SnapshotError("source_clock_or_age") from error
    if captured > now + timedelta(seconds=5) or expires <= now:
        raise SnapshotError("source_clock_or_age")
    records = {}
    row_count = 0
    for table in TABLES:
        rows = source[table]
        if not isinstance(rows, list) or len(rows) > MAX_ROWS:
            raise SnapshotError("source_limit_exceeded")
        row_count += len(rows)
        if row_count > MAX_TOTAL_ROWS:
            raise SnapshotError("source_limit_exceeded")
        seen = set()
        records[table] = []
        for row in rows:
            if not isinstance(row, dict) or set(row) != SOURCE_FIELDS[table]:
                raise SnapshotError("invalid_source")
            item = dict(row)
            for key in item:
                if key.endswith("_id"):
                    item[key] = identifier(item[key], key in {"team_id", "owner_team_id"} and table in {"participants", "targets"})
                elif key.endswith("_at"):
                    value = timestamp(item[key], table == "assignments")
                    item[key] = iso(value) if value else None
            primary = item[PRIMARY_KEYS[table]]
            if primary in seen:
                raise SnapshotError("duplicate_identity")
            seen.add(primary)
            if table == "participants":
                enum(item["role"], {"blue_participant", "red_participant", "judge", "infrastructure_staff"})
                enum(item["status"], {"pending", "active", "revoked", "expired"})
                boolean(item["eligible"])
                if timestamp(item["created_at"]) > timestamp(item["updated_at"]):
                    raise SnapshotError("invalid_source")
            elif table == "teams":
                enum(item["category"], {"application", "ai"})
                enum(item["side"], {"red", "blue"})
            elif table == "allocations":
                item["vpn_address"] = address(item["vpn_address"])
                item["interface_name"] = named(item["interface_name"], r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}", 15)
                enum(item["status"], {"reserved", "active", "revoked", "expired"})
                if timestamp(item["allocated_at"]) > timestamp(item["last_changed_at"]):
                    raise SnapshotError("invalid_source")
            elif table == "targets":
                enum(item["category"], {"application", "ai", "infrastructure"})
                enum(item["protocol"], {"tcp", "udp", "icmp", "icmpv6", "sctp", "any"})
                item["namespace"] = named(item["namespace"], r"[a-z0-9]([-a-z0-9]*[a-z0-9])?", 63)
                item["endpoint_ip"] = address(item["endpoint_ip"], allow_unknown=True)
                boolean(item["enabled"])
                ports = item["ports"]
                if not isinstance(ports, list) or len(ports) > 64 or any(type(port) is not int or not 0 <= port <= 65535 for port in ports):
                    raise SnapshotError("invalid_source")
                if len(ports) != len(set(ports)):
                    raise SnapshotError("invalid_source")
                item["ports"] = sorted(ports)
            elif table in {"assignments", "event_windows"}:
                item["window_state"] = window_state(timestamp(item["starts_at"], True), timestamp(item["ends_at"], True), captured)
            for field in ("created_at", "updated_at", "allocated_at", "last_changed_at"):
                if field in item and timestamp(item[field]) > captured + timedelta(seconds=5):
                    raise SnapshotError("source_clock_or_age")
            records[table].append(item)
        records[table].sort(key=lambda item: int(item[PRIMARY_KEYS[table]]))
    participants = {row["participant_id"]: row for row in records["participants"]}
    teams = {row["team_id"]: row for row in records["teams"]}
    targets = {row["target_id"]: row for row in records["targets"]}
    for row in records["participants"]:
        if row["team_id"] is not None and row["team_id"] not in teams:
            raise SnapshotError("invalid_reference")
    for row in records["targets"]:
        if row["owner_team_id"] is not None and row["owner_team_id"] not in teams:
            raise SnapshotError("invalid_reference")
    active_addresses = set()
    allocated_participants = set()
    for row in records["allocations"]:
        participant = participants.get(row["participant_id"])
        if participant is None or row["participant_id"] in allocated_participants:
            raise SnapshotError("invalid_reference")
        allocated_participants.add(row["participant_id"])
        statuses = {row["status"], participant["status"]}
        if "revoked" in statuses:
            state = "revoked"
        elif "expired" in statuses:
            state = "expired"
        elif "unknown" in statuses or participant["role"] == "unknown" or row["vpn_address"] is None or row["interface_name"] is None:
            state = "unknown"
        elif statuses == {"active"} and participant["eligible"]:
            state = "active"
        else:
            state = "inactive"
        row["effective_state"] = state
        if state == "active":
            if row["vpn_address"] in active_addresses:
                raise SnapshotError("duplicate_active_address")
            active_addresses.add(row["vpn_address"])
    for row in records["assignments"]:
        if row["red_team_id"] not in teams or row["target_id"] not in targets:
            raise SnapshotError("invalid_reference")
        if not targets[row["target_id"]]["enabled"]:
            row["window_state"] = "disabled"
        elif teams[row["red_team_id"]]["side"] != "red":
            row["window_state"] = "unknown"
    snapshot = {
        "contract_version": "provisioning/1.0", "identity_source": "jengasec_provisioning",
        "mapping_state": "native_only", "authorization": "none", "read_only": True,
        "source_transport": transport, "captured_at": iso(captured), "generated_at": iso(now),
        "expires_at": iso(expires), "records": records,
        "counts": {table: len(records[table]) for table in TABLES},
    }
    encode(snapshot)
    return snapshot


def encode(document):
    data = (json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
    if len(data) > MAX_BYTES:
        raise SnapshotError("source_limit_exceeded")
    return data


def atomic_write(path, payload, *, mode=0o600):
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".provisioning-", delete=False) as handle:
        temporary = Path(handle.name)
        try:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
            os.chmod(temporary, mode)
            os.replace(temporary, path)
            descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        finally:
            temporary.unlink(missing_ok=True)


def read_bounded(path):
    with path.open("rb") as handle:
        data = handle.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise SnapshotError("source_limit_exceeded")
    return data


def snapshot_hash(payload):
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def refresh(output, fetch, *, now=None, max_age=120, transport="local_peer", database="jengasec"):
    attempted_at = now or utc_now()
    output.mkdir(parents=True, mode=0o700, exist_ok=True)
    if output.is_symlink() or output.stat().st_mode & 0o077:
        raise SnapshotError("private_output_required")
    with (output / "refresh.lock").open("a") as lock:
        os.chmod(lock.name, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise SnapshotError("refresh_already_running") from error
        snapshot_path = output / "provisioning-snapshot.json"
        previous = None
        previous_bytes = None
        if snapshot_path.exists():
            try:
                previous_bytes = read_bounded(snapshot_path)
                previous = json.loads(previous_bytes)
                if not isinstance(previous, dict):
                    previous = None
            except (OSError, ValueError):
                previous = None
        try:
            source = fetch()
            snapshot = build_snapshot(source, now=now or utc_now(), max_age=max_age, transport=transport, database=database)
            payload = encode(snapshot)
        except (SnapshotError, OSError, ValueError, subprocess.SubprocessError) as error:
            reason = error.reason if isinstance(error, SnapshotError) else "source_unavailable"
            status = {
                "contract_version": "provisioning-status/1.0", "authorization": "none",
                "state": "refresh_failed" if previous else "unavailable", "reason": reason,
                "attempted_at": iso(attempted_at), "last_success_at": previous.get("generated_at") if previous else None,
                "expires_at": previous.get("expires_at") if previous else None,
                "snapshot_hash": snapshot_hash(previous_bytes) if previous else None,
                "usable": False,
            }
            # A full disk must not leave the previous success marker usable.
            (output / "provisioning-status.json").unlink(missing_ok=True)
            atomic_write(output / "provisioning-status.json", encode(status))
            raise SnapshotError(reason) from error
        # Invalidate the previous commit marker before replacing its data. A
        # failed publication cannot leave old status claiming that new data is
        # usable. Readers retry an absent or mismatched marker, then fail closed.
        (output / "provisioning-status.json").unlink(missing_ok=True)
        atomic_write(snapshot_path, payload)
        status = {
            "contract_version": "provisioning-status/1.0", "authorization": "none", "state": "fresh",
            "reason": "none", "attempted_at": iso(attempted_at), "last_success_at": snapshot["generated_at"],
            "expires_at": snapshot["expires_at"], "snapshot_hash": snapshot_hash(payload), "usable": True,
        }
        atomic_write(output / "provisioning-status.json", encode(status))
        return snapshot


def read_current(output, *, now=None):
    now = now or utc_now()
    try:
        status = json.loads(read_bounded(output / "provisioning-status.json"))
        payload = read_bounded(output / "provisioning-snapshot.json")
        snapshot = json.loads(payload)
        if not isinstance(status, dict) or not isinstance(snapshot, dict):
            return None, "unavailable"
        if (status.get("contract_version") != "provisioning-status/1.0" or status.get("state") != "fresh"
                or status.get("usable") is not True or status.get("snapshot_hash") != snapshot_hash(payload)
                or status.get("authorization") != "none" or snapshot.get("authorization") != "none"
                or snapshot.get("contract_version") != "provisioning/1.0"
                or snapshot.get("identity_source") != "jengasec_provisioning"
                or snapshot.get("mapping_state") != "native_only"
                or status.get("expires_at") != snapshot.get("expires_at")):
            return None, "stale"
        captured = timestamp(snapshot["captured_at"])
        expires = timestamp(snapshot["expires_at"])
        if not captured <= now < expires or expires - captured > timedelta(seconds=300):
            return None, "expired"
        return snapshot, "fresh"
    except (OSError, ValueError, KeyError, TypeError):
        return None, "unavailable"


def resolve_address(output, value, *, now=None):
    """Resolve only fresh native identity; never return permissions or a verdict."""
    snapshot, state = read_current(output, now=now)
    if snapshot is None:
        return {"state": state, "identity_source": "jengasec_provisioning", "authorization": "none"}
    value = address(value)
    allocation = next((row for row in snapshot["records"]["allocations"]
                       if row["vpn_address"] == value and row["effective_state"] == "active"), None)
    if allocation is None:
        return {"state": "unknown", "identity_source": "jengasec_provisioning", "authorization": "none"}
    participant = next(row for row in snapshot["records"]["participants"] if row["participant_id"] == allocation["participant_id"])
    return {"state": "known", "identity_source": "jengasec_provisioning", "mapping_state": "native_only",
            "authorization": "none", "participant_id": participant["participant_id"], "team_id": participant["team_id"],
            "role": participant["role"], "valid_from": snapshot["captured_at"], "expires_at": snapshot["expires_at"]}


def bounded_command(command, env, query):
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env=env, start_new_session=True)
    result = bytearray()
    errors = 0
    deadline = time.monotonic() + 30
    selector = selectors.DefaultSelector()
    try:
        process.stdin.write(query.encode())
        process.stdin.close()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        while selector.get_map():
            if time.monotonic() > deadline:
                raise SnapshotError("database_timeout")
            for key, _ in selector.select(0.25):
                chunk = os.read(key.fileobj.fileno(), 16384)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if key.data == "stdout":
                    result.extend(chunk)
                    if len(result) > MAX_BYTES:
                        raise SnapshotError("source_limit_exceeded")
                else:
                    errors += len(chunk)
                    if errors > 65536:
                        raise SnapshotError("database_query_failed")
        if process.wait(timeout=2) != 0:
            raise SnapshotError("database_query_failed")
        return json.loads(result)
    finally:
        selector.close()
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        process.stdout.close()
        process.stderr.close()


def fetch_database(*, local_peer, database, service_file=None, service_name="obs_provisioning"):
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,62}", database):
        raise SnapshotError("invalid_configuration")
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "PGCONNECT_TIMEOUT": "5",
           "PGOPTIONS": "-c default_transaction_read_only=on", "PGAPPNAME": "jengasec_observability_snapshot"}
    query = (ROOT / "observability/provisioning/snapshot.sql").read_text()
    command = ["/usr/bin/psql", "--no-psqlrc", "--quiet", "--no-align", "--tuples-only",
               "--no-password", "--set=ON_ERROR_STOP=1", "--dbname=" + database]
    if local_peer:
        command += ["--host=/var/run/postgresql"]
        if os.geteuid() == 0:
            command = ["/usr/sbin/runuser", "--preserve-environment", "-u", "postgres", "--", *command]
        query = query.replace("SET LOCAL statement_timeout", "SET LOCAL ROLE pg_read_all_data;\nSET LOCAL statement_timeout", 1)
    else:
        if service_file is None or service_file.stat().st_mode & 0o077 or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,62}", service_name):
            raise SnapshotError("private_service_file_required")
        config = configparser.ConfigParser(interpolation=None)
        try:
            config.read(service_file)
        except configparser.Error as error:
            raise SnapshotError("invalid_configuration") from error
        if service_name not in config or config[service_name].get("sslmode") != "verify-full":
            raise SnapshotError("tls_required")
        env.update(PGSERVICEFILE=str(service_file.resolve()), PGSERVICE=service_name)
    return bounded_command(command, env, query)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    connection = parser.add_mutually_exclusive_group()
    connection.add_argument("--local-peer", action="store_true")
    connection.add_argument("--service-file", type=Path)
    parser.add_argument("--service-name", default="obs_provisioning")
    parser.add_argument("--database", default="jengasec")
    parser.add_argument("--max-age-seconds", type=int, default=120)
    parser.add_argument("--inspect", action="store_true", help="Read current freshness and counts without querying PostgreSQL")
    args = parser.parse_args()
    if args.inspect:
        snapshot, state = read_current(args.output_dir)
        print(json.dumps({"state": state, "authorization": "none", "counts": snapshot["counts"] if snapshot else None}))
        return
    if not args.local_peer and not args.service_file:
        parser.error("--local-peer or --service-file is required for refresh")
    snapshot = refresh(args.output_dir, lambda: fetch_database(local_peer=args.local_peer, database=args.database,
                       service_file=args.service_file, service_name=args.service_name),
                       max_age=args.max_age_seconds, transport="local_peer" if args.local_peer else "tls", database=args.database)
    print(json.dumps({"state": "fresh", "authorization": "none", "counts": snapshot["counts"]}))


if __name__ == "__main__":
    try:
        main()
    except (SnapshotError, OSError, ValueError, subprocess.SubprocessError):
        # Neither libpq errors nor rejected source data are printed.
        print("Provisioning snapshot refresh failed; no usable attribution was published", file=sys.stderr)
        raise SystemExit(1)
