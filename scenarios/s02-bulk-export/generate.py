#!/usr/bin/env python3
"""
what:    Bulk customer export from entb-app06 with a stolen staff login, plus normal staff noise
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

RED = {"ip": "10.60.7.2", "team": "JS26-R-007", "user": "staff-17"}
STAFF = ["staff-03", "staff-08", "staff-11", "staff-17", "staff-22"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--out", default=str(HERE / "events.jsonl"))
    a = ap.parse_args()
    s = Scenario(HERE, a.seed)
    r = s.rng

    # Benign: staff log in from the Blue side and look at a handful of customers each.
    for n, user in enumerate(STAFF):
        ip = f"10.61.13.{n + 20}"
        at = START + timedelta(seconds=r.randint(0, 300))
        s.event(at, "application", "authentication_success", "low", "success", actor={"ip": ip, "user": user},
                endpoint="/staff/login", obj=user, metadata={"original_event": "staff_login"})
        for _ in range(r.randint(3, 7)):
            at += timedelta(seconds=r.randint(20, 120))
            s.event(at, "application", "data_change", "low", "success", actor={"ip": ip, "user": user},
                    endpoint="/customers/view", obj=f"cust-{r.randint(100000, 999999)}",
                    metadata={"original_event": "customer_record_viewed"})
        if r.random() > 0.5:
            s.event(at + timedelta(seconds=30), "application", "data_export", "medium", "success",
                    actor={"ip": ip, "user": user}, endpoint="/export/customers", obj="customer",
                    metadata={"original_event": "record_exported", "count": r.randint(5, 40)})

    # Attack: stolen login from a Red range, one denied big export, then paging under the limit.
    t = START + timedelta(minutes=6)
    s.event(t, "application", "authentication_success", "low", "success", actor=dict(RED), endpoint="/staff/login",
            obj="staff-17", malicious=True, attack=["T1078"], metadata={"original_event": "staff_login"})
    for _ in range(3):
        t += timedelta(seconds=r.randint(5, 15))
        s.event(t, "application", "data_change", "low", "success", actor=dict(RED), endpoint="/customers/view",
                obj=f"cust-{r.randint(100000, 999999)}", malicious=True,
                metadata={"original_event": "customer_record_viewed"})
    t += timedelta(seconds=20)
    s.event(t, "application", "data_export", "high", "denied", actor=dict(RED), endpoint="/export/customers",
            obj="customer", malicious=True, attack=["T1530"],
            metadata={"original_event": "bulk_export", "count": 50000, "reason": "over export limit"})
    for page in range(25):
        t += timedelta(seconds=r.randint(4, 9))
        s.event(t, "ingress", "http_request", "low", "success", actor={"ip": RED["ip"], "team": RED["team"]},
                endpoint="GET /export/customers", malicious=True,
                metadata={"status": 200, "path": f"/export/customers?page={page}&size=200", "user_agent": "curl/8.5.0"})
        s.event(t + timedelta(milliseconds=40), "application", "data_export", "medium", "success", actor=dict(RED),
                endpoint="/export/customers", obj="customer", malicious=True, attack=["T1530", "T1005"],
                metadata={"original_event": "record_exported", "count": 200, "page": page})

    s.write(a.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
