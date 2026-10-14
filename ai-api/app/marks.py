"""Turn ground truth into the website's AI marks and push them to its POST /api/feed.

Criteria and caps are the website's (website repo: docs/CONTRACT-feed.md):
  AI Blue (main, 40): precision 12 · recall 10 · correlation 8 · decisions 6 · safety 4
  AI Red  (main, 40): missed 16 · false 16 · breadth 8
These are PROPOSED marks (Architecture §11: the scoring agent proposes, judges decide). Every push carries a
stable `key` (aic:<criterion>:day<N>), so republishing replaces a mark instead of adding a second one.
"""
import json
import ssl
import urllib.error
import urllib.request
from datetime import date, datetime, timedelta

from .auth import Team
from .scoring import score_blue, score_red

BLUE_CAPS = {"precision": 12, "recall": 10, "correlation": 8, "decisions": 6, "safety": 4}
RED_CAPS = {"missed": 16, "false": 16, "breadth": 8}
FALSE_ACTIONS_FOR_FULL_MARKS = 3       # AI Red: fooling the paired AI Blue three times earns all 16


def day_windows(spec):
    """'1=2026-10-20,2=2026-10-21' -> {1: (start, end)} in naive UTC."""
    out = {}
    for part in filter(None, (p.strip() for p in (spec or "").split(","))):
        n, _, d = part.partition("=")
        start = datetime.combine(date.fromisoformat(d.strip()), datetime.min.time())
        out[int(n)] = (start, start + timedelta(days=1))
    return out


def _m(cap, ratio):
    return round(cap * max(0.0, min(1.0, ratio or 0.0)), 2)


def marks_for(db, state, day=None):
    """Every AI team's proposed marks for one engagement day (or the whole event when day is None)."""
    if state.settings.scoring_mode:
        raise ValueError("website_scoring_authority")
    window = day_windows(state.settings.engagement_days).get(day) if day else None
    if day and window is None:
        raise ValueError(f"day {day} is not in ENGAGEMENT_DAYS")
    enabled_apps = sum(1 for c in state.cells.values() if c.get("enabled")) or 18
    suffix = f"day{day}" if day else "all"
    rows = []
    for code, t in state.teams.items():
        if not t.get("enabled"):
            continue
        if t["role"] == "ai-blue":
            g = score_blue(db, code, window)
            n = g["decisions"]
            values = {
                "precision": (_m(12, g["precision"]), f"{g['evidence_attack']} of {g['evidence_cited'] - g['evidence_unknown']} cited events were attack traffic"),
                "recall": (_m(10, g["recall"]), f"you cited {g['evidence_attack']} of {g['attack_events_total']} attack events"),
                "correlation": (_m(8, g["correlated_decisions"] / n if n else 0), f"{g['correlated_decisions']} of {n} decisions tied one attacker across several sources or apps"),
                "decisions": (_m(6, g["substantive_decisions"] / n if n else 0), f"{g['substantive_decisions']} of {n} decisions cite attack evidence with a reasoned summary"),
                # Safety is earned by taking part: an inactive team scores 0, not a free 4.
                "safety": (_m(4, (1 - len(g["false_actions"]) / g["actions"]) if g["actions"] else (1 if n else 0)),
                           f"{len(g['false_actions'])} of {g['actions']} actions targeted a legitimate user"),
            }
        else:
            red = Team(code, "ai-red", t.get("paired"), t["team_id"])
            g = score_red(db, red, t.get("paired"), enabled_apps, window)
            caused = len(g["false_actions_caused"])
            values = {
                "missed": (_m(16, g["miss_rate"]), f"your paired AI Blue missed {g['missed_by_paired_blue']} of {g['own_events']} of your events"),
                "false": (_m(16, caused / FALSE_ACTIONS_FOR_FULL_MARKS), f"it acted against a legitimate user {caused} time(s) because of your traffic"),
                "breadth": (_m(8, g["breadth"]), f"you reached {g['applications_targeted']} of {enabled_apps} applications"),
            }
        for criterion, (marks, note) in values.items():
            row = {"team": t["team_id"], "stage": "main", "criterion": criterion, "marks": marks,
                   "note": f"AI track (proposed, subject to judges): {note}.", "key": f"aic:{criterion}:{suffix}",
                   "code": code}
            if day:
                row["day"] = day
            rows.append(row)
    return rows


def publish(settings, rows):
    """POST the marks to the website. Returns (http_status, response_json). Raises if not configured."""
    if settings.scoring_mode:
        raise RuntimeError("website_scoring_authority")
    if not (settings.website_feed_url and settings.website_feed_token):
        raise RuntimeError("WEBSITE_FEED_URL and WEBSITE_FEED_TOKEN must both be set")
    body = {"scores": [{k: v for k, v in r.items() if k != "code"} for r in rows]}
    if settings.website_competition:
        body["competition"] = int(settings.website_competition)
    req = urllib.request.Request(settings.website_feed_url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json",
                                          "X-Feed-Token": settings.website_feed_token})
    ctx = ssl.create_default_context(cafile=settings.website_ca_file or None)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            detail = json.loads(e.read() or b"{}")
        except ValueError:
            detail = {"error": e.reason}
        return e.code, detail
