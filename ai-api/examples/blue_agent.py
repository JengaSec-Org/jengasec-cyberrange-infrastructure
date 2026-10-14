#!/usr/bin/env python3
"""
A deliberately small AI Blue agent, to show the loop every real agent needs: read, detect, decide, act.
Standard library only. NOT a good detector: it is a starting point for AI teams and a test for staff.

  python3 blue_agent.py --api https://10.109.0.30:8443/api/v1 --token jsai_ai01_... --cacert server.crt [--once]

What it does
  1. Pages through /telemetry/events with the cursor (then keeps polling).
  2. Groups authentication failures by actor.team_id over a sliding 15-minute window, ACROSS applications and
     enterprises, so it also catches low-and-slow guessing that a per-address burst rule misses (s04).
  3. Posts one decision per team it flags, with the events as evidence, and an `alert` action.
     It acts on actor.ip (what the gateway saw), never on addresses copied from app log content,
     which an attacker can spoof (s04's X-Forwarded-For trick).
"""
import argparse
import json
import ssl
import sys
import time
import urllib.error
import urllib.request
from collections import defaultdict, deque
from datetime import datetime, timedelta

WINDOW = timedelta(minutes=15)
THRESHOLD = 8


class Api:
    def __init__(self, base, token, cacert=None, insecure=False):
        self.base, self.token = base.rstrip("/"), token
        self.ctx = ssl.create_default_context(cafile=cacert)
        if insecure:
            self.ctx.check_hostname, self.ctx.verify_mode = False, ssl.CERT_NONE

    def call(self, method, path, body=None):
        req = urllib.request.Request(self.base + path, method=method,
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=30) as r:
                return r.status, json.loads(r.read() or b"null")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"null")


def ts(event):
    return datetime.fromisoformat(event["ts"].replace("Z", "+00:00"))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", required=True)
    ap.add_argument("--token", required=True)
    ap.add_argument("--cacert", help="the range's CA or the VM's server.crt")
    ap.add_argument("--insecure", action="store_true", help="skip TLS checks (lab only)")
    ap.add_argument("--once", action="store_true", help="read what is there, decide, and exit")
    a = ap.parse_args()
    api = Api(a.api, a.token, a.cacert, a.insecure)

    failures = defaultdict(deque)       # team -> recent authentication_failure events
    flagged = set()
    cursor = None
    while True:
        status, page = api.call("GET", "/telemetry/events?limit=1000" + (f"&cursor={cursor}" if cursor else ""))
        if status == 429:
            time.sleep(10)
            continue
        if status != 200:
            print(f"events: HTTP {status} {page}", file=sys.stderr)
            return 1
        for ev in page["events"]:
            actor = ev.get("actor") or {}
            team = actor.get("team_id")
            if ev["event_type"] != "authentication_failure" or not team or actor.get("team_label") == "blue-app":
                continue
            q = failures[team]
            q.append(ev)
            while q and ts(ev) - ts(q[0]) > WINDOW:
                q.popleft()
            if len(q) >= THRESHOLD and team not in flagged:
                flagged.add(team)
                decide(api, team, list(q))
        cursor = page["next_cursor"]
        if not page["has_more"]:
            if a.once:
                print(f"done: flagged {sorted(flagged) or 'nothing'}")
                return 0
            time.sleep(5)


def decide(api, team, events):
    ips = sorted({e["actor"]["ip"] for e in events})
    cells = sorted({e["namespace"] for e in events})
    incident = f"inc-{team}-{events[0]['event_id'][:8]}"
    status, action = api.call("POST", "/actions/alert", {
        "target": {"namespace": events[-1]["namespace"], "ip": ips[0]},
        "justification": f"{len(events)} authentication failures from {team} across {', '.join(cells)} in 15 minutes",
        "incident_id": incident, "evidence": [e["event_id"] for e in events]})
    print(f"alert for {team}: HTTP {status} {action}")
    status, decision = api.call("POST", "/decisions", {
        "incident_id": incident,
        "summary": f"Password guessing by {team} from {', '.join(ips)} spread over {len(cells)} application(s); "
                   f"spread-out timing suggests deliberate evasion of per-address rate rules.",
        "attack_mapping": ["T1110.001"], "confidence": 0.7, "severity": "medium",
        "evidence": [e["event_id"] for e in events],
        "actions": [action["action_id"]] if status == 202 else []})
    print(f"decision for {team}: HTTP {status} {decision}")


if __name__ == "__main__":
    raise SystemExit(main())
