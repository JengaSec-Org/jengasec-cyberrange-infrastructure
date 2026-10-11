#!/usr/bin/env python3
"""
what:    Export one finding's sanitized, integrity-checked evidence pack
owner:   Observability
usage:   ./scripts/export-observability-evidence.py --help
reads:   one obs_findings_v1 JSON row and Loki or an NDJSON telemetry export
changes: creates one owner-only evidence directory below --output-root
safe to run again: yes; an identical existing export is left unchanged
runbook: runbooks/observability.md
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
import urllib.error
import urllib.parse
import urllib.request

import yaml


ROOT = pathlib.Path(__file__).resolve().parents[1]
EVENT_ID = re.compile(r"^evt_[a-f0-9]{64}$")
FINDING_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
CORRELATION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
EMAIL = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
EXTRA_FORBIDDEN_KEYS = {
    "attachment",
    "attachments",
    "email",
    "email_address",
    "first_name",
    "full_name",
    "last_name",
    "name",
    "phone",
    "phone_number",
    "raw_payload",
    "team_name",
}
FINDING_FIELDS = {
    "contract_version",
    "updated_at",
    "finding_id",
    "enterprise",
    "application",
    "namespace",
    "start_ts",
    "end_ts",
    "telemetry_event_ids",
    "correlation_ids",
}
EVENT_FILES = (
    "telemetry.ndjson",
    "platform-audit.ndjson",
    "competition-events.ndjson",
)


class EvidenceError(Exception):
    """A safe, readable export failure."""


def parse_timestamp(value, field):
    if not isinstance(value, str):
        raise EvidenceError(f"{field} must be a UTC timestamp")
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise EvidenceError(f"{field} must be an RFC 3339 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != datetime.timedelta(0):
        raise EvidenceError(f"{field} must be UTC")
    return parsed


def utc_text(value):
    return value.astimezone(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def load_json(path):
    try:
        with path.open(encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"cannot read JSON from {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise EvidenceError(f"{path} must contain one JSON object")
    return value


def load_finding(path):
    finding = load_json(path)
    if set(finding) != FINDING_FIELDS:
        missing = sorted(FINDING_FIELDS - set(finding))
        extra = sorted(set(finding) - FINDING_FIELDS)
        raise EvidenceError(f"finding fields differ; missing={missing}, extra={extra}")
    if finding["contract_version"] != 1:
        raise EvidenceError("finding contract_version must be 1")
    if not FINDING_ID.fullmatch(str(finding["finding_id"])):
        raise EvidenceError("finding_id is not a safe opaque identifier")
    if finding["enterprise"] not in {"ENT-A", "ENT-B"}:
        raise EvidenceError("finding enterprise is invalid")
    if not re.fullmatch(r"APP0[1-9]", str(finding["application"])):
        raise EvidenceError("finding application is invalid")
    expected_namespace = (
        f'jengasec-{finding["enterprise"].lower()}-'
        f'{finding["application"].lower()}'
    )
    if finding["namespace"] != expected_namespace:
        raise EvidenceError(f"finding namespace must be {expected_namespace}")

    start = parse_timestamp(finding["start_ts"], "start_ts")
    end = parse_timestamp(finding["end_ts"], "end_ts")
    parse_timestamp(finding["updated_at"], "updated_at")
    if start > end:
        raise EvidenceError("finding start_ts must not be after end_ts")

    event_ids = finding["telemetry_event_ids"]
    correlations = finding["correlation_ids"]
    if not isinstance(event_ids, list) or not all(
        isinstance(value, str) and EVENT_ID.fullmatch(value) for value in event_ids
    ):
        raise EvidenceError("telemetry_event_ids contains an invalid event ID")
    if not isinstance(correlations, list) or not all(
        isinstance(value, str) and CORRELATION_ID.fullmatch(value)
        for value in correlations
    ):
        raise EvidenceError("correlation_ids contains an invalid identifier")
    if len(event_ids) != len(set(event_ids)) or len(correlations) != len(
        set(correlations)
    ):
        raise EvidenceError("finding event and correlation IDs must be unique")
    if not event_ids and not correlations:
        raise EvidenceError("finding must cite an event or correlation ID")
    return finding, start, end


def read_ndjson(path):
    records = []
    try:
        with path.open(encoding="utf-8") as handle:
            for number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise EvidenceError(f"{path}:{number} is not a JSON object")
                records.append(value)
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"cannot read NDJSON from {path}: {exc}") from exc
    return records


def timestamp_ns(value):
    parsed = parse_timestamp(value, "event ts")
    return int(parsed.timestamp()) * 1_000_000_000 + parsed.microsecond * 1_000


def validate_loki_url(value):
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise EvidenceError(
            "Loki URL must be HTTP(S) without credentials or query data"
        )
    return value.rstrip("/")


def fetch_loki(finding, start, end, base_url, tenant):
    cursor = timestamp_ns(utc_text(start))
    end_ns = timestamp_ns(utc_text(end))
    records = []
    selector = (
        f'{{enterprise="{finding["enterprise"]}",'
        f'application="{finding["application"]}"}}'
    )
    page_size = 5000

    while cursor <= end_ns:
        query = urllib.parse.urlencode(
            {
                "query": selector,
                "start": str(cursor),
                "end": str(end_ns),
                "direction": "forward",
                "limit": str(page_size),
            }
        )
        request = urllib.request.Request(
            f"{base_url}/loki/api/v1/query_range?{query}",
            headers={"X-Scope-OrgID": tenant},
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = json.load(response)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise EvidenceError(f"Loki query failed: {exc}") from exc
        if payload.get("status") != "success":
            raise EvidenceError("Loki returned an unsuccessful query response")

        values = []
        for stream in payload.get("data", {}).get("result", []):
            values.extend(stream.get("values", []))
        if not values:
            break
        for timestamp, line in values:
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise EvidenceError("Loki returned a non-JSON telemetry line") from exc
            if not isinstance(event, dict):
                raise EvidenceError("Loki returned a non-object telemetry line")
            records.append(event)

        if len(values) < page_size:
            break
        latest = max(int(value[0]) for value in values)
        if latest < cursor:
            raise EvidenceError("Loki pagination did not advance")
        cursor = latest + 1
    return records


def forbidden_keys(catalogue_path):
    try:
        with catalogue_path.open(encoding="utf-8") as handle:
            catalogue = yaml.safe_load(handle)
        configured = catalogue["never_log_keys"]
    except (OSError, KeyError, TypeError, yaml.YAMLError) as exc:
        raise EvidenceError(f"cannot load sensitive-key catalogue: {exc}") from exc
    return {str(value).casefold() for value in configured} | EXTRA_FORBIDDEN_KEYS


def assert_sanitized(value, blocked, path="event"):
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).casefold().replace("-", "_")
            if normalized in blocked or normalized.endswith("_name"):
                raise EvidenceError(f"sensitive field rejected at {path}.{key}")
            assert_sanitized(child, blocked, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            assert_sanitized(child, blocked, f"{path}[{index}]")
    elif isinstance(value, str) and EMAIL.search(value):
        raise EvidenceError(f"email-like value rejected at {path}")


def sanitize_external(value, blocked):
    if isinstance(value, dict):
        clean = {}
        for key, child in value.items():
            normalized = str(key).casefold().replace("-", "_")
            if normalized in blocked or normalized.endswith("_name"):
                continue
            clean[key] = sanitize_external(child, blocked)
        return clean
    if isinstance(value, list):
        return [sanitize_external(child, blocked) for child in value]
    if isinstance(value, str) and EMAIL.search(value):
        return "[redacted]"
    return value


def select_telemetry(records, finding, start, end, blocked):
    cited = set(finding["telemetry_event_ids"])
    correlations = set(finding["correlation_ids"])
    found_cited = set()
    found_correlations = set()
    selected = {}

    for event in records:
        event_id = event.get("event_id")
        request_id = event.get("request_id")
        trace_id = event.get("trace_id")
        matched_correlations = correlations.intersection({request_id, trace_id})
        if event_id not in cited and not matched_correlations:
            continue
        if event.get("schema_version") != "2.0" or event.get("stream") != "telemetry":
            raise EvidenceError(f"selected event {event_id!r} is not telemetry v2")
        if not isinstance(event_id, str) or not EVENT_ID.fullmatch(event_id):
            raise EvidenceError("selected telemetry has an invalid event ID")
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", str(event.get("integrity_hash"))):
            raise EvidenceError(f"selected event {event_id} has no integrity hash")
        for key in ("enterprise", "application", "namespace"):
            if event.get(key) != finding[key]:
                raise EvidenceError(f"selected event {event_id} has the wrong {key}")
        event_time = parse_timestamp(event.get("ts"), f"event {event_id} ts")
        if event_time < start or event_time > end:
            raise EvidenceError(
                f"selected event {event_id} is outside the finding window"
            )
        assert_sanitized(event, blocked)

        encoded = json.dumps(event, sort_keys=True, separators=(",", ":"))
        if event_id in selected and selected[event_id] != encoded:
            raise EvidenceError(
                f"event ID {event_id} resolves to conflicting telemetry"
            )
        selected[event_id] = encoded
        if event_id in cited:
            found_cited.add(event_id)
        found_correlations.update(matched_correlations)

    missing_cited = sorted(cited - found_cited)
    missing_correlations = sorted(correlations - found_correlations)
    if missing_cited or missing_correlations:
        raise EvidenceError(
            "finding references missing telemetry; "
            f"event_ids={missing_cited}, correlation_ids={missing_correlations}"
        )
    if not selected:
        raise EvidenceError("finding selected no telemetry")
    return sorted(
        (json.loads(value) for value in selected.values()),
        key=lambda event: (event["ts"], event["event_id"]),
    )


def canonical_lines(records):
    ordered = sorted(
        records,
        key=lambda value: (
            str(value.get("ts", "")),
            str(value.get("event_id", value.get("id", ""))),
            json.dumps(value, sort_keys=True, separators=(",", ":")),
        ),
    )
    return "".join(
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
        for value in ordered
    )


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def write_private(path, value):
    path.write_bytes(value)
    path.chmod(0o600)


def same_pack(left, right):
    names = {*EVENT_FILES, "manifest.json", "SHA256SUMS"}
    if {path.name for path in left.iterdir()} != names:
        return False
    return all(
        (left / name).is_file()
        and not (left / name).is_symlink()
        and (right / name).is_file()
        and (left / name).read_bytes() == (right / name).read_bytes()
        for name in names
    )


def existing_export_time(target):
    manifest_path = target / "manifest.json"
    if not manifest_path.is_file():
        return None
    manifest = load_json(manifest_path)
    value = manifest.get("exported_at")
    parse_timestamp(value, "existing manifest exported_at")
    return value


def build_pack(args, finding, telemetry, platform_audit, competition, exported_at):
    files = {
        "telemetry.ndjson": canonical_lines(telemetry).encode(),
        "platform-audit.ndjson": canonical_lines(platform_audit).encode(),
        "competition-events.ndjson": canonical_lines(competition).encode(),
    }
    manifest = {
        "schema_version": "1.0",
        "finding": {
            "finding_id": finding["finding_id"],
            "enterprise": finding["enterprise"],
            "application": finding["application"],
            "namespace": finding["namespace"],
            "start_ts": finding["start_ts"],
            "end_ts": finding["end_ts"],
            "telemetry_event_ids": finding["telemetry_event_ids"],
            "correlation_ids": finding["correlation_ids"],
        },
        "contract_versions": {
            "evidence_pack": "1.0",
            "finding": 1,
            "telemetry": "2.0",
            "platform_audit": args.platform_audit_contract_version,
            "competition_events": args.competition_contract_version,
        },
        "exported_at": exported_at,
        "files": {
            name: {
                "rows": len(content.splitlines()),
                "sha256": f"sha256:{sha256_bytes(content)}",
            }
            for name, content in files.items()
        },
    }
    manifest_bytes = (
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    ).encode()
    checksums = {**files, "manifest.json": manifest_bytes}
    sums = "".join(
        f"{sha256_bytes(content)}  {name}\n"
        for name, content in sorted(checksums.items())
    ).encode()
    return files, manifest_bytes, sums


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--finding", type=pathlib.Path, required=True)
    telemetry = parser.add_mutually_exclusive_group(required=True)
    telemetry.add_argument("--telemetry-file", type=pathlib.Path)
    telemetry.add_argument("--loki-url")
    parser.add_argument("--loki-tenant", default="staff")
    parser.add_argument("--platform-audit-file", type=pathlib.Path)
    parser.add_argument("--competition-events-file", type=pathlib.Path)
    parser.add_argument("--platform-audit-contract-version")
    parser.add_argument("--competition-contract-version")
    parser.add_argument(
        "--catalogue",
        type=pathlib.Path,
        default=ROOT / "contracts" / "telemetry-event-catalogue.yaml",
    )
    parser.add_argument("--output-root", type=pathlib.Path, required=True)
    parser.add_argument("--exported-at")
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def main():
    args = parse_args()
    os.umask(0o077)
    finding, start, end = load_finding(args.finding)
    blocked = forbidden_keys(args.catalogue)

    if args.telemetry_file:
        telemetry_source = read_ndjson(args.telemetry_file)
    else:
        telemetry_source = fetch_loki(
            finding,
            start,
            end,
            validate_loki_url(args.loki_url),
            args.loki_tenant,
        )
    telemetry = select_telemetry(telemetry_source, finding, start, end, blocked)
    platform_audit = (
        [
            sanitize_external(value, blocked)
            for value in read_ndjson(args.platform_audit_file)
        ]
        if args.platform_audit_file
        else []
    )
    competition = (
        [
            sanitize_external(value, blocked)
            for value in read_ndjson(args.competition_events_file)
        ]
        if args.competition_events_file
        else []
    )
    if platform_audit and not args.platform_audit_contract_version:
        raise EvidenceError(
            "non-empty platform audit export needs its contract version"
        )
    if competition and not args.competition_contract_version:
        raise EvidenceError("non-empty competition export needs its contract version")

    target = args.output_root / finding["finding_id"]
    if args.output_root.is_symlink():
        raise EvidenceError("evidence output root must not be a symbolic link")
    if target.is_symlink():
        raise EvidenceError("evidence target must not be a symbolic link")
    exported_at = args.exported_at or existing_export_time(target)
    if exported_at is None:
        exported_at = utc_text(datetime.datetime.now(datetime.timezone.utc))
    else:
        exported_at = utc_text(parse_timestamp(exported_at, "exported_at"))
    files, manifest, sums = build_pack(
        args, finding, telemetry, platform_audit, competition, exported_at
    )

    if args.dry_run:
        print(
            f'would export {len(telemetry)} telemetry rows for '
            f'{finding["finding_id"]}'
        )
        return 0

    args.output_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    args.output_root.chmod(0o700)
    temporary = pathlib.Path(
        tempfile.mkdtemp(prefix=f'.{finding["finding_id"]}.', dir=args.output_root)
    )
    temporary.chmod(0o700)
    try:
        for name, content in files.items():
            write_private(temporary / name, content)
        write_private(temporary / "manifest.json", manifest)
        write_private(temporary / "SHA256SUMS", sums)

        if target.exists():
            if not target.is_dir() or not same_pack(target, temporary):
                raise EvidenceError(
                    "evidence target already exists with different content"
                )
            target.chmod(0o700)
            for name in {*EVENT_FILES, "manifest.json", "SHA256SUMS"}:
                (target / name).chmod(0o600)
            print(f"evidence pack unchanged: {target}")
            return 0
        temporary.rename(target)
        temporary = None
        print(f"evidence pack written: {target}")
        return 0
    finally:
        if temporary is not None and temporary.exists():
            shutil.rmtree(temporary)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except EvidenceError as exc:
        print(f"evidence export failed: {exc}", file=os.sys.stderr)
        raise SystemExit(1) from exc
