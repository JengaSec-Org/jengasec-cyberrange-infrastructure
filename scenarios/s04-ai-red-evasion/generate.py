#!/usr/bin/env python3
"""
what:    AI Red evasion (low-and-slow guessing, X-Forwarded-For spoofing, log poisoning) across both enterprises
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

RED_AI = [f"10.64.1.{n}" for n in range(10, 14)]     # RI-01 members
BLUE_OWNER = "10.61.1.12"                            # ENT-A APP01 owner (App Blue team 1)
BROWSERS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5)",
            "Mozilla/5.0 (X11; Linux x86_64)"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--out", default=str(HERE / "events.jsonl"))
    a = ap.parse_args()
    s = Scenario(HERE, a.seed)
    r = s.rng
    end = 20 * 60

    # Benign: Blue owners check their own apps; ordinary users mistype now and then.
    for cell, owner in (("enta-app01", BLUE_OWNER), ("enta-app03", "10.61.3.10"), ("entb-app03", "10.61.12.11"),
                        ("entb-app02", "10.61.11.10")):
        for _ in range(12):
            at = START + timedelta(seconds=r.randint(0, end))
            s.event(at, "ingress", "http_request", "low", "success", actor={"ip": owner}, cell=cell,
                    endpoint="GET /", metadata={"status": 200, "user_agent": r.choice(BROWSERS)})
    for _ in range(6):
        at = START + timedelta(seconds=r.randint(0, end))
        user = r.choice(["a.wanjiru", "b.kamau", "c.achieng"])
        s.event(at, "application", "authentication_failure", "low", "failure", cell="enta-app03",
                actor={"ip": "10.61.3.11", "user": user}, endpoint="/login", obj=user,
                metadata={"original_event": "login_failure", "reason": "bad_password"})

    # (1) Low and slow: one guess every 40-90 s, rotating members, users and enterprises.
    t = START + timedelta(seconds=30)
    n = 0
    while (t - START).total_seconds() < end - 60:
        t += timedelta(seconds=r.randint(40, 90))
        cell = "enta-app03" if n % 2 == 0 else "entb-app03"
        user = f"cust{r.randint(1000, 9999)}"
        ip = r.choice(RED_AI)
        s.event(t, "ingress", "http_request", "low", "failure", actor={"ip": ip}, cell=cell, endpoint="POST /login",
                malicious=True, metadata={"status": 401, "user_agent": r.choice(BROWSERS)})
        s.event(t + timedelta(milliseconds=18), "application", "authentication_failure", "low", "failure", cell=cell,
                actor={"ip": ip, "user": user}, endpoint="/login", obj=user, malicious=True, attack=["T1110.001"],
                metadata={"original_event": "login_failure", "reason": "bad_password"})
        n += 1

    # (2) X-Forwarded-For spoofing: the app believes the Blue owner sent it; the gateway knows better.
    t = START + timedelta(minutes=7)
    for path in ["/admin", "/accounts/export", "/admin/users", "/accounts/export?all=1"]:
        t += timedelta(seconds=r.randint(8, 20))
        s.event(t, "ingress", "http_request", "medium", "denied", actor={"ip": RED_AI[2]}, cell="enta-app01",
                endpoint=f"GET {path.split('?')[0]}", malicious=True, attack=["T1036"],
                metadata={"status": 403, "user_agent": BROWSERS[0], "x_forwarded_for": BLUE_OWNER})
        s.event(t + timedelta(milliseconds=25), "application", "access_denied", "medium", "denied", cell="enta-app01",
                actor={"ip": RED_AI[2]}, endpoint=path.split("?")[0], malicious=True, attack=["T1036"],
                metadata={"original_event": "permission_denied",
                          "original": {"source_ip": BLUE_OWNER, "event": "permission_denied", "target": path}})

    # (3) Log poisoning: usernames that look like extra JSON fields.
    t = START + timedelta(minutes=12)
    for fake in ['admin","outcome":"success', 'j.doe\\n{"event":"login_success"}', 'x","severity":"low']:
        t += timedelta(seconds=r.randint(15, 40))
        s.event(t, "application", "authentication_failure", "medium", "failure", cell="entb-app02",
                actor={"ip": RED_AI[3], "user": fake}, endpoint="/v1/auth/token", obj=fake, malicious=True,
                attack=["T1565.001"], metadata={"original_event": "login_failure", "reason": "unknown_user"})

    s.write(a.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
