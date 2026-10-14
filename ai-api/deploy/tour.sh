#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# what:   A guided tour of an installed AI API: shows each request an AI team or staff member makes,
#         and what comes back, one step at a time
# owner:  AIC
# usage:  sudo ./tour.sh [--no-pause] [base-url]     default https://127.0.0.1:8443 (or http://127.0.0.1:8000)
# reads:  /etc/jengasec-ai/ai-api.env, /etc/jengasec-ai/team-tokens.txt
# changes:posts a few test events, two shadow actions and decisions as AI-01 (all visible in the export)
# safe to run again: yes
# runbook: runbooks/ai-api-vm.md
# ---------------------------------------------------------------------------
set -euo pipefail
ETC=/etc/jengasec-ai
PAUSE=1
[ "${1:-}" = --no-pause ] && { PAUSE=0; shift; }
[ -r "$ETC/ai-api.env" ] || { echo "run as root on the AI API VM (sudo)" >&2; exit 1; }
# shellcheck disable=SC1091
set -a; . "$ETC/ai-api.env"; set +a
BASE="${1:-}"
if [ -z "$BASE" ]; then
  if curl -fsk https://127.0.0.1:8443/healthz >/dev/null 2>&1; then BASE=https://127.0.0.1:8443; else BASE=http://127.0.0.1:8000; fi
fi
API="$BASE/api/v1"
tok() { awk -v t="$1" '$1==t {print $3}' "$ETC/team-tokens.txt"; }
BLUE=$(tok AI-01); RED=$(tok RI-01)
EX=/opt/jengasec-ai/repo/ai-api/examples
PY=/opt/jengasec-ai/venv/bin/python

B=$'\e[1m'; D=$'\e[2m'; C=$'\e[36m'; N=$'\e[0m'
step() { printf '\n%s━━ %s%s\n' "$B$C" "$1" "$N"; shift; for line in "$@"; do printf '   %s\n' "$line"; done; }
show() { printf '%s$ %s%s\n' "$D" "$1" "$N"; }
wait_key() { [ "$PAUSE" = 1 ] && { read -r -p "   ${D}[Enter] for the next step${N} " _ || true; }; return 0; }
get() { curl -sk -H "Authorization: Bearer $2" "$API$1"; }
post() { curl -sk -w '\n%{http_code}' -X POST -H "Authorization: Bearer $2" -H 'Content-Type: application/json' --data "$3" "$API$1"; }
py() { python3 -c "$1"; }

printf '%sJengaSec AI API tour%s  (%s)\n' "$B" "$N" "$API"
echo "   Two kinds of AI team call this API from their own laptops over WireGuard: AI Blue defends, AI Red attacks."
echo "   The sandbox is preloaded with four scripted scenarios (scenarios/s01 … s04)."
wait_key

step "1. AI Blue reads the telemetry" "AI Blue (AI-01) sees every event for all 18 applications in both enterprises."
show "curl -H 'Authorization: Bearer <AI-01 token>' $API/telemetry/events?limit=1000"
get "/telemetry/events?limit=1000" "$BLUE" | py "
import json,sys,collections
d=json.load(sys.stdin); ev=d['events']
print(f'   {len(ev)} events, has_more={d[\"has_more\"]}, next_cursor={d[\"next_cursor\"]}')
print('   by team_label (who sent it; OBS attributes it from the platform database):', dict(collections.Counter((e.get('actor') or {}).get('team_label','-') for e in ev)))
print('   by application:', dict(collections.Counter(e['enterprise']+' '+e['application'] for e in ev)))
red=[e for e in ev if (e.get('actor') or {}).get('team_label')=='red-app'][0]
print('   one event, as an agent receives it:')
print('\n'.join('     '+l for l in json.dumps(red,indent=2).splitlines()))
"
wait_key

step "2. AI Red sees only its own traffic" "RI-01 is paired with AI-01. It gets the events about its own traffic and nothing from anyone else."
show "curl -H 'Authorization: Bearer <RI-01 token>' $API/telemetry/events"
get "/telemetry/events?limit=1000" "$RED" | py "
import json,sys,collections
ev=json.load(sys.stdin)['events']
print(f'   {len(ev)} events; teams in them:', sorted({e[\"actor\"][\"team_id\"] for e in ev}))
print('   what RI-01 did:', dict(collections.Counter((e['namespace'],e['event_type']) for e in ev)))
"
wait_key

step "3. Assets: what exists" "Every application, its reserved VLAN 108 address and port. AI Red uses this to pick targets."
show "curl -H 'Authorization: Bearer <token>' $API/assets"
get /assets "$BLUE" | py "
import json,sys
for a in json.load(sys.stdin):
    print(f'   {a[\"enterprise\"]} {a[\"application\"]}  {a[\"ip\"]:<12} {a[\"namespace\"]:<22} {a[\"service\"]}{\"\" if a[\"enabled\"] else \"  (disabled)\"}')
"
wait_key

step "4. Baseline alerts" "The platform's own simple rules, a yardstick for the teams' detectors." \
  "Notice that RI-01's low-and-slow guessing (s04) triggers nothing: beating this is the AI Red goal."
get /alerts "$BLUE" | py "
import json,sys
for a in json.load(sys.stdin): print(f'   AI Blue sees: {a[\"rule\"]:<20} {a[\"namespace\"]:<22} {a[\"severity\"]:<6} {a[\"summary\"]}')
"
get /alerts "$RED" | py "import json,sys; print(f'   RI-01 sees {len(json.load(sys.stdin))} alert(s) caused by its own traffic')"
wait_key

step "5. Live: Vector posts an event, an agent streams it" \
  "Opening the live stream as AI Blue, then posting an attack event to /ingest the way the collector will." \
  "It is a telemetry v2 event, already attributed by OBS (team_id JS26-R-002, team_label red-app)."
curl -skN -H "Authorization: Bearer $BLUE" "$API/telemetry/stream" > /tmp/tour.sse 2>/dev/null &
SSE=$!
sleep 1
BATCH=$(python3 /opt/jengasec-ai/repo/ai-api/scripts/make-test-event.py --array)
EV=$(printf '%s' "$BATCH" | python3 -c "import json,sys; print(json.load(sys.stdin)[0]['event_id'])")
show "curl -X POST -H 'Authorization: Bearer <INGEST_TOKEN>' $API/ingest -d '[{...v2 event from 10.60.2.14 to ENT-A APP01...}]'"
post /ingest "$INGEST_TOKEN" "$BATCH" \
  | head -1 | sed 's/^/   ingest answered: /'
sleep 2; kill "$SSE" 2>/dev/null || true; wait "$SSE" 2>/dev/null || true
grep '^data: ' /tmp/tour.sse | tail -1 | cut -c7- | py "
import json,sys
e=json.loads(sys.stdin.read() or '{}')
print('   ...and it arrived on the stream within a second:' if e else '   (nothing arrived on the stream)')
if e: print(f'     {e[\"event_id\"]}  actor={e[\"actor\"]}')
"
wait_key

step "6. AI Blue acts (shadow mode)" "block-ip is authorised, budget-checked and recorded, but NOT applied. Only alert takes effect."
show "curl -X POST $API/actions/block-ip -d '{\"target\":{\"namespace\":\"jengasec-ent-a-app01\",\"ip\":\"10.60.2.14\"},\"justification\":\"...\"}'"
post /actions/block-ip "$BLUE" '{"target":{"namespace":"jengasec-ent-a-app01","ip":"10.60.2.14"},"justification":"failed admin login from a Red range","evidence":["'"$EV"'"]}' \
  | py "import sys; body,code=sys.stdin.read().rsplit('\n',1); print(f'   HTTP {code}: {body}')"
echo "   Acting on someone who is not Red is accepted too, but counts as a false action. Watch step 9."
post /actions/block-ip "$BLUE" '{"target":{"namespace":"jengasec-ent-a-app01","ip":"10.61.1.12"},"justification":"tour: deliberately wrong"}' \
  | py "import sys; body,code=sys.stdin.read().rsplit('\n',1); print(f'   HTTP {code}: blocked 10.61.1.12 (the app'\"'\"'s own Blue owner)')"
show "the same request with the RI-01 token"
post /actions/alert "$RED" '{"target":{"namespace":"jengasec-ent-a-app01"},"justification":"x"}' \
  | py "import sys; body,code=sys.stdin.read().rsplit('\n',1); print(f'   HTTP {code}: {body}')"
wait_key

step "7. AI Blue logs a decision (this is what judges score)"
post /decisions "$BLUE" '{"incident_id":"tour-1","summary":"Red team 2 tried the admin account on ENT-A APP01","confidence":0.8,"severity":"medium","evidence":["'"$EV"'"]}' \
  | py "import sys; body,code=sys.stdin.read().rsplit('\n',1); print(f'   HTTP {code}: {body}')"
wait_key

step "8. A real (tiny) AI Blue agent" "ai-api/examples/blue_agent.py: page through events, group failed logins per team across all apps, alert and decide." \
  "It catches s01's credential stuffing AND RI-01's low-and-slow guessing that the baseline missed."
show "python3 blue_agent.py --api $API --token <AI-01 token> --cacert $ETC/tls/server.crt --once"
CA=(); [[ $BASE == https://* ]] && CA=(--cacert "$ETC/tls/server.crt")
"$PY" "$EX/blue_agent.py" --api "$API" --token "$BLUE" "${CA[@]}" --once 2>&1 | sed 's/^/   /' | cut -c1-160
wait_key

step "9. What the judges and the website get" "One export per team, scored against OBS's attribution labels: no hand labelling." \
  "The same numbers become the website's AI marks (precision, recall, ... missed, false, breadth)."
show "curl -H 'Authorization: Bearer <ADMIN_TOKEN>' $API/admin/export/AI-01"
get /admin/export/AI-01 "$ADMIN_TOKEN" | py "
import json,sys
g=json.load(sys.stdin)['ground_truth']
print(f'   AI-01: {g[\"decisions\"]} decisions citing {g[\"evidence_cited\"]} events, precision {g[\"precision\"]}, recall {g[\"recall\"]} of {g[\"attack_events_total\"]} attack events')
for f in g['false_actions']: print(f'   false action: {f[\"type\"]} on {f[\"target\"][\"ip\"]} ({f[\"sender_label\"]}): acted against a legitimate user')
"
get /admin/export/RI-01 "$ADMIN_TOKEN" | py "
import json,sys
g=json.load(sys.stdin)['ground_truth']
print(f'   RI-01 vs its paired {g[\"paired_blue\"]}: {g[\"missed_by_paired_blue\"]} of {g[\"own_events\"]} events missed (miss rate {g[\"miss_rate\"]}), {len(g[\"false_actions_caused\"])} false action(s) caused, {g[\"applications_targeted\"]} apps reached')
"

show "curl -H 'Authorization: Bearer <ADMIN_TOKEN>' $API/admin/marks   (what would go to the website)"
get /admin/marks "$ADMIN_TOKEN" | py "
import json,sys
for r in json.load(sys.stdin):
    if r['code'] in ('AI-01','RI-01'): print(f'   {r[\"code\"]} -> {r[\"team\"]}: {r[\"criterion\"]:<12} {r[\"marks\"]:>5}  {r[\"note\"][:80]}')
"
if [ -n "${WEBSITE_FEED_URL:-}" ]; then
  echo "   WEBSITE_FEED_URL is set: these are pushed to the website every 5 minutes (jengasec-ai-marks.timer)."
else
  echo "   Not sent anywhere yet: set WEBSITE_FEED_URL and WEBSITE_FEED_TOKEN in $ETC/ai-api.env (docs/ai-integration.md)."
fi

step "Done" "Explore yourself:" \
  "  Browser: $BASE/docs   (interactive API page; click Authorize and paste a token)" \
  "  Tokens:  sudo cat $ETC/team-tokens.txt" \
  "  Logs:    journalctl -u jengasec-ai-api -f" \
  "  Start the sandbox again from scratch:  sudo ./ai-api/deploy/install.sh --reset-db"
