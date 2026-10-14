"""Ground-truth scoring for the AI track (Architecture §3.2, §11). OBS attributes every event
(actor.team_label from the platform's ip_allocations), so detections are scored without hand labelling:
red-app and red-ai traffic is attack traffic. These numbers are what the scoring agent and judges start
from; judges decide. An optional (start, end) UTC window scores one engagement day."""
from sqlalchemy import func, select

from .models import Action, Decision, Event

ATTACK = ("red-app", "red-ai")


def _ratio(a, b):
    return round(a / b, 4) if b else None


def _window(column, window):
    if not window:
        return []
    start, end = window
    return [column >= start, column < end]


def _decisions(db, team_code, window):
    return list(db.scalars(select(Decision).where(Decision.team == team_code, *_window(Decision.created_at, window))
                           .order_by(Decision.id)))


def _events(db, event_ids):
    if not event_ids:
        return {}
    return {e.event_id: e for e in db.scalars(select(Event).where(Event.event_id.in_(event_ids)))}


def sender_label(db, ip):
    """The label OBS gave this source address most recently, or None if it never sent anything we saw."""
    return db.scalar(select(Event.team_label).where(Event.actor_ip == ip, Event.team_label.is_not(None))
                     .order_by(Event.seq.desc()).limit(1))


def classify_actions(db, team_code, window=None):
    """Split a team's actions into ones aimed at Red senders, at legitimate ones (false actions), and unverified."""
    out = {"total": 0, "on_attackers": [], "false": [], "unverified": []}
    for a in db.scalars(select(Action).where(Action.team == team_code, Action.status != "halted",
                                             *_window(Action.created_at, window))):
        out["total"] += 1
        ip = (a.target or {}).get("ip")
        row = {"action_id": a.action_id, "type": a.type, "target": a.target, "evidence": a.evidence}
        if not ip:
            out["unverified"].append(row)
            continue
        label = sender_label(db, ip)
        row["sender_label"] = label
        if label in ATTACK:
            out["on_attackers"].append(row)
        elif label is None or label == "unknown":
            out["unverified"].append(row)
        else:
            out["false"].append(row)
    return out


def score_blue(db, team_code, window=None):
    decisions = _decisions(db, team_code, window)
    cited = {e for d in decisions for e in d.body.get("evidence", [])}
    events = _events(db, cited)
    cited_attack = {e for e, ev in events.items() if ev.team_label in ATTACK}
    attack_total = db.scalar(select(func.count(Event.seq)).where(Event.team_label.in_(ATTACK),
                                                                 *_window(Event.ts, window))) or 0
    correlated = substantive = 0
    for d in decisions:
        evs = [events[e] for e in d.body.get("evidence", []) if e in events]
        attackers = [e for e in evs if e.team_label in ATTACK]
        teams = {e.team_id for e in attackers}
        # Correlation: one attacking team tied together across more than one address or application.
        if len(attackers) >= 2 and len(teams) == 1 and len({(e.namespace, e.actor_ip) for e in attackers}) >= 2:
            correlated += 1
        if attackers and len(d.body.get("summary", "")) >= 40:
            substantive += 1
    actions = classify_actions(db, team_code, window)
    return {
        "decisions": len(decisions),
        "evidence_cited": len(cited),
        "evidence_unknown": len(cited - set(events)),
        "evidence_attack": len(cited_attack),
        "precision": _ratio(len(cited_attack), len(events)),
        "recall": _ratio(len(cited_attack), attack_total),
        "attack_events_total": attack_total,
        "correlated_decisions": correlated,
        "substantive_decisions": substantive,
        "actions": actions["total"],
        "false_actions": actions["false"],
        "unverified_actions": actions["unverified"],
    }


def score_red(db, red, paired_blue_code, enabled_apps, window=None):
    """red: the AI Red Team. How much of its traffic did its paired AI Blue miss, and what did it fool it into."""
    own_rows = list(db.scalars(select(Event).where(Event.team_id == red.team_id, *_window(Event.ts, window))))
    own = {e.event_id for e in own_rows}
    cited = set()
    if paired_blue_code:
        cited = {e for d in _decisions(db, paired_blue_code, window) for e in d.body.get("evidence", [])}
    detected = own & cited
    caused = []
    if paired_blue_code:
        for fa in classify_actions(db, paired_blue_code, window)["false"]:
            if own & set(fa.get("evidence") or []):
                caused.append(fa)       # the paired AI Blue acted on a legitimate user, citing this team's traffic
    targets = {e.namespace for e in own_rows}
    return {
        "paired_blue": paired_blue_code,
        "own_events": len(own),
        "detected_by_paired_blue": len(detected),
        "missed_by_paired_blue": len(own - detected),
        "miss_rate": _ratio(len(own - detected), len(own)),
        "false_actions_caused": caused,
        "applications_targeted": len(targets),
        "breadth": _ratio(len(targets), enabled_apps),
    }
