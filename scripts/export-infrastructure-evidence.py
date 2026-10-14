#!/usr/bin/env python3
"""Export integrity-checked infrastructure records by resource, time and event ID.

Owner: Observability. Creates one private, deterministic evidence pack. This does
not create a competition finding or collect platform audit records.
"""

import argparse
import datetime
import hashlib
import json
import os
import pathlib
import re
import shutil
import tempfile
import urllib.parse
import urllib.request

import jsonschema
from referencing import Registry, Resource

from infrastructure_events import canonical, digest, utc


ROOT = pathlib.Path(__file__).resolve().parents[1]
ID = re.compile(r"^infra_[a-f0-9]{64}$")
RESOURCE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
PACK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def timestamp(value):
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("evidence times must be UTC and end in Z")
    return datetime.datetime.fromisoformat(value[:-1] + "+00:00")


def validator():
    source = json.loads((ROOT / "contracts/infrastructure-source.schema.json").read_text())
    schema = json.loads((ROOT / "contracts/infrastructure-event.schema.json").read_text())
    registry = Registry().with_resource(source["$id"], Resource.from_contents(source))
    return jsonschema.Draft202012Validator(schema, registry=registry, format_checker=jsonschema.FormatChecker())


def verify(record, check):
    try:
        check.validate(record)
    except jsonschema.ValidationError:
        raise ValueError("record does not match the infrastructure schema") from None
    original = dict(record)
    expected_hash = original.pop("integrity_hash")
    if expected_hash != "sha256:" + digest(canonical(original)):
        raise ValueError("infrastructure record integrity failed")
    expected_id = "infra_" + digest(record["resource_id"] + "\n" + record["source_event_id"])
    if record["event_id"] != expected_id:
        raise ValueError("infrastructure event identity failed")


def content_identity(record):
    return canonical({key: value for key, value in record.items() if key not in {"received_ts", "integrity_hash", "provenance"}})


def select(records, resources, start, end, environment, event_ids):
    check = validator()
    selected = {}
    for record in records:
        if record.get("resource_id") not in resources or record.get("environment") != environment:
            continue
        if event_ids and record.get("event_id") not in event_ids:
            continue
        instant = timestamp(record.get("ts"))
        if not start <= instant <= end:
            continue
        verify(record, check)
        identity = record["event_id"]
        previous = selected.get(identity)
        if previous and content_identity(previous) != content_identity(record):
            raise ValueError("event ID resolves to conflicting source records")
        if previous is None or record["received_ts"] < previous["received_ts"]:
            selected[identity] = record
    if event_ids - selected.keys():
        raise ValueError("one or more requested event IDs are missing from the resource window")
    return sorted(selected.values(), key=lambda row: (row["ts"], row["event_id"]))


def read_ndjson(path):
    with path.open() as stream:
        for index, line in enumerate(iter(lambda: stream.readline(16385), "")):
            if index >= 100000:
                raise ValueError("evidence window exceeds 100000 records; narrow the window")
            if len(line) > 16384:
                raise ValueError("oversized infrastructure record")
            if line.strip():
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError("record is not an object")
                yield value


def fetch_loki(url, resources, start, end, environment):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Loki URL must be HTTP(S) without credentials, query or fragment")
    epoch = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
    def nanoseconds(value):
        delta = value - epoch
        return (delta.days * 86400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1000
    cursor = nanoseconds(start)
    end_ns = nanoseconds(end)
    selector = '{record_family="infrastructure_telemetry",environment="' + environment + '",resource_id=~"' + '|'.join(sorted(resources)) + '"}'
    total = 0
    while cursor <= end_ns:
        params = urllib.parse.urlencode({"query": selector, "start": str(cursor), "end": str(end_ns), "direction": "forward", "limit": "5000"})
        request = urllib.request.Request(url.rstrip("/") + "/loki/api/v1/query_range?" + params, headers={"X-Scope-OrgID": "staff"})
        with urllib.request.urlopen(request, timeout=30) as response:
            data = response.read(32 * 1024 * 1024 + 1)
            if len(data) > 32 * 1024 * 1024:
                raise ValueError("oversized Loki response; narrow the window")
            result = json.loads(data)
        if result.get("status") != "success":
            raise ValueError("Loki query failed")
        values = sorted((value for stream in result["data"]["result"] for value in stream["values"]), key=lambda item: int(item[0]))
        if not values:
            return
        if len(values) == 5000:
            # Requery the entire last timestamp; never skip unseen ties.
            latest = int(values[-1][0])
            if latest <= cursor:
                raise ValueError("more than one page shares a timestamp; narrow resource scope")
            page = [value for value in values if int(value[0]) < latest]
        else:
            latest, page = end_ns + 1, values
        for _, line in page:
            if len(line) > 16384:
                raise ValueError("oversized Loki record")
            total += 1
            if total > 100000:
                raise ValueError("evidence window exceeds 100000 records; narrow the window")
            yield json.loads(line)
        cursor = latest


def write_pack(output, pack_id, records, selection, exported_at=None):
    target = output / pack_id
    if output.is_symlink() or target.is_symlink():
        raise ValueError("evidence paths cannot be symbolic links")
    if target.exists() and exported_at is None:
        exported_at = json.loads((target / "manifest.json").read_text())["exported_at"]
    exported_at = utc(timestamp(exported_at)) if exported_at else utc()
    files = {
        "infrastructure-telemetry.ndjson": ("".join(canonical(record) + "\n" for record in records)).encode(),
        "platform-audit.ndjson": b"",
        "competition-events.ndjson": b"",
    }
    manifest = {
        "schema_version": "infrastructure-evidence/1.0",
        "pack_id": pack_id,
        "record_family": "infrastructure_telemetry",
        "selection": selection,
        "exported_at": exported_at,
        "contract_versions": {"infrastructure_telemetry": "infrastructure/1.0", "platform_audit": None, "competition_events": None},
        "files": {name: {"rows": len(data.splitlines()), "sha256": "sha256:" + hashlib.sha256(data).hexdigest()} for name, data in files.items()},
    }
    files["manifest.json"] = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
    files["SHA256SUMS"] = "".join(hashlib.sha256(data).hexdigest() + "  " + name + "\n" for name, data in sorted(files.items())).encode()
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    output.chmod(0o700)
    temporary = pathlib.Path(tempfile.mkdtemp(prefix="." + pack_id + ".", dir=output))
    try:
        for name, data in files.items():
            (temporary / name).write_bytes(data)
            (temporary / name).chmod(0o600)
        if target.exists():
            if not target.is_dir() or {path.name for path in target.iterdir()} != set(files) or any((target / name).is_symlink() or (target / name).read_bytes() != data for name, data in files.items()):
                raise ValueError("existing evidence pack has different content")
            return target
        temporary.rename(target)
        return target
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--resource-id", action="append", required=True)
    parser.add_argument("--start-ts", required=True)
    parser.add_argument("--end-ts", required=True)
    parser.add_argument("--event-id", action="append", default=[])
    parser.add_argument("--environment", choices=["live", "validation", "rehearsal"], default="live")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--telemetry-file", type=pathlib.Path)
    source.add_argument("--loki-url")
    parser.add_argument("--output-root", type=pathlib.Path, required=True)
    parser.add_argument("--pack-id", required=True)
    parser.add_argument("--exported-at")
    args = parser.parse_args()
    os.umask(0o077)
    if not PACK.fullmatch(args.pack_id) or not all(RESOURCE.fullmatch(value) for value in args.resource_id) or not all(ID.fullmatch(value) for value in args.event_id):
        raise ValueError("invalid evidence selector")
    start, end = timestamp(args.start_ts), timestamp(args.end_ts)
    if end < start or (end - start).total_seconds() > 604800:
        raise ValueError("evidence window must be ordered and at most seven days")
    resources, event_ids = set(args.resource_id), set(args.event_id)
    source = read_ndjson(args.telemetry_file) if args.telemetry_file else fetch_loki(args.loki_url, resources, start, end, args.environment)
    records = select(source, resources, start, end, args.environment, event_ids)
    selection = {"resource_ids": sorted(resources), "start_ts": utc(start), "end_ts": utc(end), "environment": args.environment, "event_ids": sorted(event_ids)}
    target = write_pack(args.output_root, args.pack_id, records, selection, args.exported_at)
    print(f"infrastructure evidence: {len(records)} records at {target}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, jsonschema.ValidationError) as exc:
        print(f"infrastructure evidence failed: {exc}", file=os.sys.stderr)
        raise SystemExit(1) from exc
