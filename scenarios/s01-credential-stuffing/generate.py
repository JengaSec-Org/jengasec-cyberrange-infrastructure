#!/usr/bin/env python3
"""
what:    Credential stuffing against enta-app03, with benign login noise, as telemetry events
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

RED = {"ip": "10.60.5.14", "team": "JS26-R-005"}
CUSTOMERS = ["a.wanjiru", "b.kamau", "c.achieng", "d.mutua", "e.njeri", "f.omondi", "g.chebet", "h.kiplagat"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--out", default=str(HERE / "events.jsonl"))
    a = ap.parse_args()
    s = Scenario(HERE, a.seed)
    r = s.rng

    # Benign: customers on Blue-side addresses, mostly succeeding, the odd typo.
    for i in range(30):
        at = START + timedelta(seconds=r.randint(0, 600))
        user = r.choice(CUSTOMERS)
        actor = {"ip": f"10.61.3.{r.randint(10, 60)}", "user": user}
        ok = r.random() > 0.15
        s.event(at, "ingress", "http_request", "low", "success" if ok else "failure", actor={"ip": actor["ip"]},
                endpoint="POST /login", metadata={"status": 200 if ok else 401, "user_agent": "Mozilla/5.0"})
        s.event(at + timedelta(milliseconds=20), "application", "authentication_success" if ok else "authentication_failure",
                "low", "success" if ok else "failure", actor=actor, endpoint="/login", obj=user,
                metadata={"original_event": "login_success" if ok else "login_failure"})

    # Attack: 40 different usernames from one address in two minutes.
    t = START + timedelta(minutes=4)
    for n in range(40):
        t += timedelta(milliseconds=r.randint(1500, 3500))
        user = f"leak-{n:02d}@mail.example"
        s.event(t, "ingress", "http_request", "low", "failure", actor=dict(RED), endpoint="POST /login",
                malicious=True, metadata={"status": 401, "user_agent": "python-requests/2.32.3"})
        s.event(t + timedelta(milliseconds=15), "application", "authentication_failure", "low", "failure",
                actor={**RED, "user": user}, endpoint="/login", obj=user, malicious=True, attack=["T1110.004"],
                metadata={"original_event": "login_failure", "reason": "bad_password"})
    t += timedelta(seconds=3)
    s.event(t, "application", "authentication_success", "medium", "success", actor={**RED, "user": "k.otieno"},
            endpoint="/login", obj="k.otieno", malicious=True, attack=["T1078"], metadata={"original_event": "login_success"})
    t += timedelta(seconds=40)
    s.event(t, "application", "account_change", "medium", "success", actor={**RED, "user": "k.otieno"},
            endpoint="/account/password", obj="k.otieno", malicious=True, attack=["T1098"],
            metadata={"original_event": "password_changed"})

    s.write(a.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
