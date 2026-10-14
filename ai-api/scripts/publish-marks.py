#!/usr/bin/env python3
"""
what:    Push proposed AI marks from the AI API to the website's POST /api/feed (via /admin/publish-marks)
owner:   AIC
usage:   publish-marks.py --api https://127.0.0.1:8443/api/v1 [--cacert server.crt] [--day N | --all | --preview]
         With no --day/--all it publishes every engagement day in ENGAGEMENT_DAYS that has started (the timer's mode).
reads:   env ADMIN_TOKEN, WEBSITE_FEED_URL, ENGAGEMENT_DAYS (/etc/jengasec-ai/ai-api.env on the VM)
changes: the website's AI marks for those days (idempotent: each mark has a stable key and is replaced)
safe to run again: yes
"""
import argparse
import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from datetime import date


def call(api, token, ctx, method, path):
    req = urllib.request.Request(api.rstrip("/") + path, method=method, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=60) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"null")


def started_days(spec):
    out = []
    for part in filter(None, (p.strip() for p in spec.split(","))):
        n, _, d = part.partition("=")
        if date.fromisoformat(d.strip()) <= date.today():
            out.append(int(n))
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", required=True)
    ap.add_argument("--cacert")
    ap.add_argument("--day", type=int)
    ap.add_argument("--all", action="store_true", help="one set of marks for the whole event (testing only)")
    ap.add_argument("--preview", action="store_true", help="print the marks, send nothing")
    a = ap.parse_args()
    token = os.environ.get("ADMIN_TOKEN", "")
    if not token:
        print("ADMIN_TOKEN is not set", file=sys.stderr)
        return 2
    ctx = ssl.create_default_context(cafile=a.cacert)

    if a.preview:
        status, rows = call(a.api, token, ctx, "GET", "/admin/marks" + (f"?day={a.day}" if a.day else ""))
        print(json.dumps(rows, indent=2))
        return 0 if status == 200 else 1
    if not (os.environ.get("WEBSITE_FEED_URL") and os.environ.get("WEBSITE_FEED_TOKEN")):
        print("website feed not configured (WEBSITE_FEED_URL / WEBSITE_FEED_TOKEN): nothing to do")
        return 0
    days = [None] if a.all else [a.day] if a.day else started_days(os.environ.get("ENGAGEMENT_DAYS", ""))
    if not days:
        print("no engagement day has started (ENGAGEMENT_DAYS): nothing to do")
        return 0
    worst = 0
    for day in days:
        status, answer = call(a.api, token, ctx, "POST", "/admin/publish-marks" + (f"?day={day}" if day else ""))
        website = (answer or {}).get("website_status")
        rejected = ((answer or {}).get("website_answer") or {}).get("rejected") or []
        print(f"day {day or 'all'}: api {status}, website {website}, sent {(answer or {}).get('sent')}, rejected {len(rejected)}")
        for r in rejected[:5]:
            print(f"  rejected: {r}")
        # The website answers 200 when every mark landed and 202 when some were rejected (e.g. an unknown
        # team_id): both count as a failure here, so `systemctl status jengasec-ai-marks` shows it.
        if status != 200 or website != 200:
            worst = 1
    return worst


if __name__ == "__main__":
    raise SystemExit(main())
