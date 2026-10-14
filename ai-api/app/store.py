"""Event storage shared by /ingest, the sandbox seed and the read endpoints. Every event is checked
against contracts/telemetry-event.schema.json (v2), the single source of truth for the shape.
Attribution (actor.team_id / team_label) is OBS's: this service stores it and never guesses it."""
import base64
import binascii
import hashlib
import json
from datetime import datetime, timezone

from fastapi import HTTPException
from jsonschema import Draft202012Validator, FormatChecker
from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Event


def json_validator(settings, name):
    schema = json.loads((settings.contracts / name).read_text(encoding="utf-8"))
    return Draft202012Validator(schema, format_checker=FormatChecker())


def telemetry_validator(settings):
    return json_validator(settings, "telemetry-event.schema.json")


def parse_ts(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).replace(tzinfo=None)


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def first_error(validator, obj):
    err = next(iter(sorted(validator.iter_errors(obj), key=lambda e: list(e.path))), None)
    if err is None:
        return None
    where = "/".join(map(str, err.path)) or "<root>"
    return f"{where}: {err.message}"


def integrity_ok(event) -> bool:
    """Vector's integrity_hash: SHA-256 of the canonical event without that field (VRL encode_json)."""
    body = {k: v for k, v in event.items() if k != "integrity_hash"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return event.get("integrity_hash") == "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def parse_body(raw: bytes):
    """A JSON array, or NDJSON (Vector's http sink with newline_delimited framing)."""
    text = raw.decode("utf-8").strip()
    if not text:
        return []
    if text.startswith("["):
        return json.loads(text)
    items = []
    for line in text.splitlines():
        line = line.strip()
        if line:
            try:
                items.append(json.loads(line))
            except ValueError:
                items.append(None)          # reported as rejected with its index
    return items


def store_events(db: Session, validator, items, cells):
    """Validate and insert. Returns (accepted, rejected, integrity_mismatches).
    Re-sent event_ids count as accepted and are stored once (Vector retries are harmless)."""
    accepted, rejected, mismatches = 0, [], 0
    seen = set()
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            rejected.append({"index": index, "error": "not a JSON object"})
            continue
        error = first_error(validator, item)
        cell = cells.get(item.get("namespace")) if error is None else None
        if error is None and cell is None:
            error = f"namespace: {item['namespace']} is not in scripts/cells.yaml"
        if error is None and (cell["enterprise"], cell["application"]) != (item["enterprise"], item["application"]):
            error = f"namespace {item['namespace']} is {cell['enterprise']}/{cell['application']}, not {item['enterprise']}/{item['application']}"
        if error:
            rejected.append({"index": index, "error": error})
            continue
        if not integrity_ok(item):
            mismatches += 1                  # kept, but counted: OBS owns the hash and can investigate
        accepted += 1
        if item["event_id"] in seen or db.scalar(select(Event.seq).where(Event.event_id == item["event_id"])):
            continue
        seen.add(item["event_id"])
        actor = item.get("actor") or {}
        db.add(Event(event_id=item["event_id"], enterprise=item["enterprise"], application=item["application"],
                     namespace=item["namespace"], ts=parse_ts(item["ts"]), actor_ip=actor.get("ip"),
                     team_label=actor.get("team_label"), team_id=actor.get("team_id"), body=item))
    db.commit()
    return accepted, rejected, mismatches


def encode_cursor(seq: int) -> str:
    return base64.urlsafe_b64encode(f"s{seq}".encode()).decode().rstrip("=")


def decode_cursor(cursor: str | None) -> int:
    if not cursor:
        return 0
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode()
        if not raw.startswith("s"):
            raise ValueError
        return int(raw[1:])
    except (ValueError, UnicodeDecodeError, binascii.Error):
        raise HTTPException(400, "bad cursor") from None


def visible(team):
    """What a team may read: AI Blue sees every event; AI Red only events whose actor.team_id is its own."""
    return [] if team.is_blue else [Event.team_id == team.team_id]


def events_after(db: Session, team, after: int, limit: int, since: datetime | None = None):
    q = select(Event).where(Event.seq > after, *visible(team))
    if since is not None:
        q = q.where(Event.ts >= since)
    return list(db.scalars(q.order_by(Event.seq).limit(limit)))
