"""Platform baseline alerts: a deliberately simple yardstick AI teams can compare their own
detections with. Computed on read from the stored events, so they never drift from the evidence."""
from collections import defaultdict
from datetime import timedelta

BURST_WINDOW = timedelta(seconds=60)
BURST_COUNT = 5
EVIDENCE_CAP = 50


def _iso(dt):
    return dt.isoformat(timespec="milliseconds") + "Z"


def _alert(alert_id, ts, ev, rule, severity, summary, evidence):
    return {"alert_id": alert_id, "ts": ts, "enterprise": ev.enterprise, "application": ev.application,
            "namespace": ev.namespace, "rule": rule, "severity": severity, "summary": summary, "evidence": evidence}


def baseline_alerts(events):
    """events: Event rows in seq order. Returns alerts newest first."""
    alerts = []
    failures = defaultdict(list)          # (namespace, source ip) -> [Event]
    for ev in events:
        body = ev.body
        if body["event_type"] == "authentication_failure" and ev.actor_ip:
            failures[(ev.namespace, ev.actor_ip)].append(ev)
        if body["severity"] in ("high", "critical"):
            alerts.append(_alert(f"al-sev-{ev.event_id[4:16]}", body["ts"], ev, "high_severity_event", body["severity"],
                                 f"{body['event_type']} ({body['outcome']}) from {ev.actor_ip or 'unknown source'}",
                                 [ev.event_id]))

    for (namespace, ip), evs in failures.items():
        evs.sort(key=lambda e: e.ts)
        start, fired_until = 0, None
        for end, ev in enumerate(evs):
            while ev.ts - evs[start].ts > BURST_WINDOW:
                start += 1
            if end - start + 1 >= BURST_COUNT and (fired_until is None or evs[start].ts > fired_until):
                burst = [e for e in evs[start:] if e.ts - evs[start].ts <= BURST_WINDOW * 3]
                users = {(e.body.get("actor") or {}).get("user_id") for e in burst} - {None}
                alerts.append(_alert(f"al-burst-{burst[0].event_id[4:16]}", _iso(burst[0].ts), burst[0],
                                     "auth_failure_burst", "high" if len(users) >= BURST_COUNT else "medium",
                                     f"{len(burst)} authentication failures from {ip} across {len(users)} users",
                                     [e.event_id for e in burst[:EVIDENCE_CAP]]))
                fired_until = burst[-1].ts
    alerts.sort(key=lambda a: a["ts"], reverse=True)
    return alerts
