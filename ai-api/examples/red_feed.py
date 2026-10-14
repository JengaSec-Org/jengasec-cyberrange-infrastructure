#!/usr/bin/env python3
"""
What an AI Red team sees: its own traffic as the platform recorded it, and the baseline alerts that
traffic triggered (Architecture §3.2). Use it to learn what is being detected. Standard library only.

  python3 red_feed.py --api https://10.109.0.30:8443/api/v1 --token jsai_ri01_... --cacert server.crt
"""
import argparse
import sys
from collections import Counter

from blue_agent import Api


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", required=True)
    ap.add_argument("--token", required=True)
    ap.add_argument("--cacert")
    ap.add_argument("--insecure", action="store_true")
    a = ap.parse_args()
    api = Api(a.api, a.token, a.cacert, a.insecure)

    events, cursor = [], None
    while True:
        status, page = api.call("GET", "/telemetry/events?limit=1000" + (f"&cursor={cursor}" if cursor else ""))
        if status != 200:
            print(f"events: HTTP {status} {page}", file=sys.stderr)
            return 1
        events += page["events"]
        cursor = page["next_cursor"]
        if not page["has_more"]:
            break
    teams = Counter(e["actor"].get("team_id") for e in events)
    print(f"{len(events)} events about your traffic (teams seen: {dict(teams)})")
    for (ns, kind), n in sorted(Counter((e["namespace"], e["event_type"]) for e in events).items()):
        print(f"  {ns:<22} {kind:<24} {n}")

    status, alerts = api.call("GET", "/alerts")
    print(f"{len(alerts)} baseline alert(s) your traffic triggered")
    for al in alerts:
        print(f"  {al['ts']} {al['rule']:<22} {al['namespace']:<22} {al['severity']:<6} {al['summary']}")
    status, _ = api.call("POST", "/decisions", {"incident_id": "x", "summary": "x", "confidence": 0, "evidence": ["x"]})
    print(f"posting a decision as AI Red -> HTTP {status} (403 expected: your output is traffic)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
