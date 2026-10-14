"""Shared helpers for scenario generators: deterministic clock, the version 2 telemetry envelope
(contracts/telemetry-event.schema.json), and writing events.jsonl + answer-key.yaml.

Events are built the way OBS's Vector normalizer builds them (observability/vector/vector.yaml):
  event_id       = "evt_" + sha256(canonical JSON of the original record)
  integrity_hash = "sha256:" + sha256(canonical JSON of the normalized event without this field)
Attribution follows contracts/address-plan.md and contracts/observability-data-interface.md;
AI team identifiers come from scripts/ai-teams.yaml. Standard library + PyYAML only."""
import hashlib
import ipaddress
import json
import pathlib
import random
from datetime import datetime, timedelta, timezone

import yaml

START = datetime(2026, 10, 10, 9, 0, tzinfo=timezone.utc)   # engagement day one, 12:00 EAT
REPO = pathlib.Path(__file__).resolve().parent.parent
CELLS = {(c["enterprise"], c["application"]): c
         for c in yaml.safe_load((REPO / "scripts/cells.yaml").read_text(encoding="utf-8"))["cells"]}
AI_TEAMS = yaml.safe_load((REPO / "scripts/ai-teams.yaml").read_text(encoding="utf-8"))["teams"]


def canonical(obj):
    """VRL encode_json: object keys sorted, no whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def iso(dt):
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def attribute(ip):
    """participant_id, team_id and team_label for a WireGuard source address (address plan)."""
    addr = ipaddress.ip_address(ip)
    third, fourth = int(ip.split(".")[2]), int(ip.split(".")[3])
    participant = f"JS26-P-{third:02d}{fourth:02d}"
    for t in AI_TEAMS:
        if addr in ipaddress.ip_network(t["wg_range"]):
            label = "red-ai" if t["role"] == "ai-red" else "blue-ai"
            return {"participant_id": participant, "team_id": t["team_id"], "team_label": label}
    for net, label, prefix in (("10.60.0.0/16", "red-app", "R"), ("10.61.0.0/16", "blue-app", "B")):
        if addr in ipaddress.ip_network(net):
            return {"participant_id": participant, "team_id": f"JS26-{prefix}-{third:03d}", "team_label": label}
    if addr in ipaddress.ip_network("10.63.0.0/24"):
        return {"participant_id": participant, "team_label": "staff"}
    return {"team_label": "unknown"}


def parse_cell(cell):
    """'entb-app03' -> ('ENT-B', 'APP03')."""
    ent, _, app = cell.partition("-")
    return f"ENT-{ent[-1].upper()}", app.upper()


def split_endpoint(endpoint):
    if not endpoint:
        return None, None
    method, _, path = endpoint.partition(" ")
    return (method, path) if path else (None, method)


class Scenario:
    def __init__(self, here, seed):
        self.here = pathlib.Path(here)
        self.spec = yaml.safe_load((self.here / "scenario.yaml").read_text(encoding="utf-8"))
        self.rng = random.Random(f"{self.spec['id']}:{seed}")
        self.events = []
        self.malicious = []
        self.n = 0

    def event(self, at, source, event_type, severity, outcome, *, enterprise=None, application=None,
              cell=None, malicious=False, actor=None, endpoint=None, status=None, obj=None, raw_event=None,
              attack=None, metadata=None, verdict=None):
        if cell:                                   # "entb-app03" shorthand
            enterprise, application = parse_cell(cell)
        enterprise = enterprise or self.spec["enterprise"]
        application = application or self.spec["application"]
        metadata = dict(metadata or {})
        status = status or metadata.pop("status", None)
        raw_event = raw_event or metadata.pop("original_event", None)
        query_path = metadata.pop("path", None)
        for k, v in metadata.pop("original", {}).items():   # v2 metadata is flat: what the app reported
            metadata[f"reported_{k}"] = v
        cell = CELLS[(enterprise, application)]
        self.n += 1
        method, path = split_endpoint(endpoint)
        path = query_path or path

        # The record the source wrote; its hash is the stable event_id, exactly as in Vector.
        original = {"scenario": self.spec["id"], "seq": self.n, "ts": iso(at), "source": source,
                    "event": raw_event or event_type, "namespace": cell["namespace"],
                    "src": (actor or {}).get("ip"), "rand": self.rng.getrandbits(64)}

        ev = {
            "schema_version": "2.0",
            "catalogue_version": 1,
            "stream": "telemetry",
            "event_id": "evt_" + sha256(canonical(original)),
            "ts": iso(at),
            "received_ts": iso(at + timedelta(milliseconds=self.rng.randint(80, 900))),
            "enterprise": enterprise,
            "application": application,
            "namespace": cell["namespace"],
            "asset": f"{cell['namespace']}/app" if source == "application" else "gateway",
            "source": source,
            "event_type": event_type,
            "severity": severity,
            "outcome": outcome,
            "verdict": verdict or ("refused" if event_type == "scope_violation" else "allowed"),
            "target": {"ip": cell["reserved_ip"], "enterprise": enterprise, "application": application,
                       "namespace": cell["namespace"], "asset": "app"},
            "request_id": f"req-{self.spec['id']}-{self.n:05d}",
        }
        if raw_event:
            ev["raw_event"] = raw_event
        if actor:
            a = {"ip": actor["ip"], **attribute(actor["ip"])}
            if actor.get("user"):
                a["user_id"] = actor["user"][:128]
            ev["actor"] = a
        if obj:
            ev["target"]["target_id"] = obj[:128]
        if method or path or status:
            ev["http"] = {k: v for k, v in (("method", method), ("path", path), ("status", status)) if v}
        if attack:
            ev["attack_mapping"] = attack
        if metadata:
            ev["metadata"] = metadata
        ev["integrity_hash"] = "sha256:" + sha256(canonical(ev))
        self.events.append(ev)
        if malicious:
            self.malicious.append(ev)
        return ev

    def write(self, out):
        self.events.sort(key=lambda e: (e["ts"], e["event_id"]))
        with open(out, "w", encoding="utf-8", newline="\n") as fh:
            for ev in self.events:
                fh.write(json.dumps(ev, separators=(",", ":"), ensure_ascii=False) + "\n")
        bad = sorted(self.malicious, key=lambda e: e["ts"])
        key = {
            "scenario": self.spec["id"],
            "malicious_event_ids": [e["event_id"] for e in bad],
            "first_detectable_at": bad[0]["ts"] if bad else None,
            "correct_detection": self.spec["expected_detections"],
            "acceptable_responses": self.spec["expected_responses"],
            "unacceptable_responses": self.spec.get("unacceptable_responses", []),
        }
        header = "# Generated by generate.py from scenario.yaml. Used by SCR; never shown to teams. Do not edit by hand.\n"
        (self.here / "answer-key.yaml").write_text(
            header + yaml.safe_dump(key, sort_keys=False, width=100), encoding="utf-8", newline="\n")
        print(f"wrote {len(self.events)} events ({len(bad)} malicious) to {out}")
