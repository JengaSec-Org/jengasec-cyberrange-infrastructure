"""Read authorized records from the existing bounded Vector handoff spool."""

import base64
import hashlib
import hmac
import os
import re
import stat
from pathlib import Path

from .common import Rejected, canonical, decode_json, digest, integer, timestamp


class Cursors:
    def __init__(self, secret):
        if not isinstance(secret, str) or len(secret) < 32:
            raise Rejected("cursor_secret_required", 503)
        self.secret = secret.encode()

    def encode(self, scope, value):
        raw = canonical({"scope": scope, "value": value})
        signature = hmac.new(self.secret, raw, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(signature + raw).decode().rstrip("=")

    def decode(self, scope, value, default):
        if value is None or value == "":
            return default
        if not isinstance(value, str) or len(value) > 2048:
            raise Rejected("invalid_cursor")
        try:
            raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
            signature, body = raw[:32], raw[32:]
            if not hmac.compare_digest(signature, hmac.new(self.secret, body, hashlib.sha256).digest()):
                raise ValueError()
            parsed = decode_json(body)
            if parsed["scope"] != scope:
                raise ValueError()
            return parsed["value"]
        except (ValueError, KeyError, TypeError):
            raise Rejected("invalid_cursor") from None


class Telemetry:
    FIELDS = ("schema_version", "catalogue_version", "stream", "event_id", "integrity_hash", "ts", "received_ts",
              "enterprise", "application", "namespace", "asset", "source", "event_type", "severity", "outcome", "verdict")

    def __init__(self, directory, authority, cursors):
        self.directory, self.authority, self.cursors = Path(directory), authority, cursors

    def read(self, principal, now, limit=200, cursor=None, since=None, alerts=False):
        integer(limit, 1, 1000)
        scope = principal["team"] + (":alerts" if alerts else ":telemetry")
        since_time = timestamp(since) if since else now - 3600
        if since_time < now - 7 * 86400 or since_time > now + 2:
            raise Rejected("invalid_telemetry_window")
        position = self.cursors.decode(scope, cursor, {"file": "", "offset": 0, "since": since_time})
        if not isinstance(position, dict) or set(position) != {"file", "offset", "since"}:
            raise Rejected("invalid_cursor")
        integer(position["offset"], 0, 2**63 - 1)
        if position["file"] and not re.fullmatch(r"telemetry-[0-9-]{16}\.ndjson", position["file"]):
            raise Rejected("invalid_cursor")
        if not isinstance(position["since"], (int, float)):
            raise Rejected("invalid_cursor")
        # Snapshot freshness is required even when the spool has no records.
        snapshot = self.authority.load(now)
        self.authority.team(snapshot, principal, now)
        filenames = sorted(p.name for p in self.directory.glob("telemetry-*.ndjson")
                           if re.fullmatch(r"telemetry-[0-9-]{16}\.ndjson", p.name))
        if position["file"] and position["file"] not in filenames:
            raise Rejected("telemetry_cursor_expired", 410)
        from datetime import datetime, timezone
        first_file = datetime.fromtimestamp(position["since"], timezone.utc).strftime("telemetry-%Y-%m-%d-%H-%M.ndjson")
        files = [name for name in filenames if name >= (position["file"] or first_file)]
        result, scanned, invalid, byte_count, examined = [], 0, 0, 0, 0
        last = dict(position)
        for name in files:
            if examined >= 64 or byte_count >= 8 * 1024 * 1024 or len(result) >= limit:
                break
            examined += 1
            try:
                fd = os.open(self.directory / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            except FileNotFoundError:
                raise Rejected("telemetry_cursor_expired", 410) from None
            with os.fdopen(fd, "rb") as handle:
                if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                    raise Rejected("invalid_spool_file", 503)
                if name == position["file"]:
                    if os.fstat(handle.fileno()).st_size < position["offset"]:
                        raise Rejected("telemetry_file_truncated", 410)
                    handle.seek(position["offset"])
                last = {"file": name, "offset": handle.tell(), "since": position["since"]}
                while len(result) < limit and byte_count < 8 * 1024 * 1024:
                    start = handle.tell()
                    raw = handle.readline(65537)
                    if not raw:
                        break
                    byte_count += len(raw)
                    if not raw.endswith(b"\n"):
                        if len(raw) <= 65536:
                            handle.seek(start)
                            break  # Vector may still be writing this record.
                        invalid += 1
                        raise Rejected("oversized_spool_record", 503)
                    last["offset"] = handle.tell()
                    scanned += 1
                    try:
                        event = decode_json(raw)
                        if not isinstance(event, dict) or event.get("schema_version") != "2.0" or not re.fullmatch(r"evt_[a-f0-9]{64}", str(event.get("event_id", ""))):
                            raise Rejected("invalid_event")
                        occurred = timestamp(event["ts"])
                        if occurred < position["since"] or occurred > now + 2:
                            continue
                        if alerts and event["event_type"] != "ids_alert":
                            continue
                        matching = [r for r in snapshot["targets"] if r["namespace"] == event["namespace"]
                                    and r["enterprise"] == event["enterprise"] and r["application"] == event["application"]
                                    and self.authority.active(r, occurred)]
                        target = self.authority.unique(matching)
                        self.authority.resolve(principal, target["target_id"], now, at=occurred)
                        public = {field: event[field] for field in self.FIELDS}
                        public["source_integrity_hash"] = public.pop("integrity_hash")
                        public["source_schema_version"] = public["schema_version"]
                        public["schema_version"] = "ai-telemetry/1.0"
                        public["integrity_hash"] = digest(public)
                        result.append(public)
                    except Rejected as error:
                        if error.status == 503:
                            raise
                        if error.code not in ("unresolved_or_ambiguous_identity", "invalid_principal_assignment", "protected_network", "protected_service", "assignment_changed"):
                            invalid += 1
                    except (KeyError, TypeError):
                        invalid += 1
        return {"events": result, "next_cursor": self.cursors.encode(scope, last),
                "coverage": {"scanned_records": scanned, "invalid_records": invalid,
                             "more_available": bool(files) and (examined < len(files) or len(result) >= limit or byte_count >= 8 * 1024 * 1024)}}
