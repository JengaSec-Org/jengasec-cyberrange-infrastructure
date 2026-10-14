#!/usr/bin/env python3
"""
what:    Print one valid telemetry v2 event (as OBS's Vector would emit it) for smoke tests and demos
owner:   AIC
usage:   make-test-event.py [--ip 10.60.2.14] [--team-id JS26-R-002] [--label red-app] [--namespace jengasec-ent-a-app01]
                            [--event-type authentication_failure] [--severity medium] [--array]
reads:   nothing (standard library only, so it runs with the system python3)
changes: nothing; prints JSON to stdout
safe to run again: yes (each run gets a fresh event_id)
"""
import argparse
import hashlib
import json
import secrets
from datetime import datetime, timezone


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ip", default="10.60.2.14")
    ap.add_argument("--team-id", default="JS26-R-002")
    ap.add_argument("--label", default="red-app")
    ap.add_argument("--namespace", default="jengasec-ent-a-app01")
    ap.add_argument("--target-ip", default="10.108.0.11")
    ap.add_argument("--event-type", default="authentication_failure")
    ap.add_argument("--severity", default="medium")
    ap.add_argument("--user", default="admin")
    ap.add_argument("--array", action="store_true", help="wrap in a JSON array, ready for POST /ingest")
    a = ap.parse_args()

    enterprise = "ENT-" + a.namespace.split("-")[2].upper()
    application = a.namespace.split("-")[3].upper()
    now = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    ev = {
        "schema_version": "2.0", "catalogue_version": 1, "stream": "telemetry",
        "event_id": "evt_" + hashlib.sha256(secrets.token_bytes(32)).hexdigest(),
        "ts": now, "received_ts": now, "enterprise": enterprise, "application": application,
        "namespace": a.namespace, "asset": f"{a.namespace}/app", "source": "application",
        "raw_event": "login_failure" if a.event_type == "authentication_failure" else None,
        "event_type": a.event_type, "severity": a.severity, "outcome": "failure", "verdict": "allowed",
        "actor": {"ip": a.ip, "team_id": a.team_id, "team_label": a.label, "user_id": a.user},
        "target": {"ip": a.target_ip, "enterprise": enterprise, "application": application, "namespace": a.namespace},
        "http": {"method": "POST", "path": "/login", "status": 401},
    }
    ev = {k: v for k, v in ev.items() if v is not None}
    canonical = json.dumps(ev, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    ev["integrity_hash"] = "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()
    print(json.dumps([ev] if a.array else ev, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
