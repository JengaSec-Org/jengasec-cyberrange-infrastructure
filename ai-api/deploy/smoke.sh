#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# what:   End-to-end check of an installed AI API: roles, telemetry, stream, ingest, shadow actions,
#         decisions, kill switch and the judges' export (Architecture §15.3 done-when checks)
# owner:  AIC
# usage:  sudo ./smoke.sh [base-url]        default https://127.0.0.1:8443 (or http://…:8000 after --no-tls)
# reads:  /etc/jengasec-ai/ai-api.env, /etc/jengasec-ai/team-tokens.txt
# changes:posts one test event, one decision and two shadow actions (AI-01's budget goes down by 2),
#         toggles the kill switch on and back off
# safe to run again: yes
# ---------------------------------------------------------------------------
set -euo pipefail
ETC=/etc/jengasec-ai
[ -r "$ETC/ai-api.env" ] || { echo "run as root on the AI API VM" >&2; exit 1; }
# shellcheck disable=SC1091
set -a; . "$ETC/ai-api.env"; set +a
BASE="${1:-}"
if [ -z "$BASE" ]; then
  if curl -fsk https://127.0.0.1:8443/healthz >/dev/null 2>&1; then BASE=https://127.0.0.1:8443; else BASE=http://127.0.0.1:8000; fi
fi
API="$BASE/api/v1"
tok() { awk -v t="$1" '$1==t {print $3}' "$ETC/team-tokens.txt"; }
BLUE=$(tok AI-01); RED=$(tok RI-01)
REPO=/opt/jengasec-ai/repo
RED_ID=$(awk '/code: RI-01/ {for (i=1;i<=NF;i++) if ($i=="team_id:") {gsub(",","",$(i+1)); print $(i+1)}}' "$REPO/scripts/ai-teams.yaml")
[ -n "$BLUE" ] && [ -n "$RED" ] || { echo "AI-01 / RI-01 tokens not in $ETC/team-tokens.txt" >&2; exit 1; }

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  ok    %s\n' "$*"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL  %s\n' "$*"; }
call() { # method path token [json-body] -> prints "status body"
  local m=$1 p=$2 t=$3 b=${4:-}
  if [ -n "$b" ]; then
    curl -sk -o /tmp/smoke.body -w '%{http_code}' -X "$m" -H "Authorization: Bearer $t" -H 'Content-Type: application/json' --data "$b" "$API$p"
  else
    curl -sk -o /tmp/smoke.body -w '%{http_code}' -X "$m" -H "Authorization: Bearer $t" "$API$p"
  fi
}
json() { python3 -c "import json,sys; d=json.load(open('/tmp/smoke.body')); print($1)"; }
expect() { local want=$1 got=$2 what=$3; [ "$got" = "$want" ] && ok "$what" || bad "$what (HTTP $got, wanted $want: $(head -c 200 /tmp/smoke.body))"; }

echo "AI API smoke test against $API"
[ "$(curl -sk -o /dev/null -w '%{http_code}' "$BASE/healthz")" = 200 ] && ok "healthz" || bad "healthz"
expect 401 "$(call GET /telemetry/events nobody)" "unknown token refused"

expect 200 "$(call GET '/telemetry/events?limit=1000' "$BLUE")" "AI Blue reads events"
n_blue=$(json "len(d['events'])"); ents=$(json "sorted({e['enterprise'] for e in d['events']})")
[ "$n_blue" -gt 0 ] && ok "AI Blue sees $n_blue events across $ents" || bad "AI Blue sees no events (is SANDBOX_SEED=1?)"

expect 200 "$(call GET '/telemetry/events?limit=1000' "$RED")" "AI Red reads its feed"
teams=$(json "sorted({e['actor']['team_id'] for e in d['events']})")
[ "$teams" = "['$RED_ID']" ] && ok "AI Red RI-01 ($RED_ID) sees only its own traffic ($(json "len(d['events'])") events)" || bad "AI Red sees $teams"

expect 200 "$(call GET /assets "$BLUE")" "assets"
[ "$(json "len([a for a in d if a['namespace'].startswith('jengasec-')])")" = 18 ] && ok "18 applications with reserved IPs" || bad "assets: $(json "len(d)")"
expect 200 "$(call GET /alerts "$BLUE")" "baseline alerts ($(json "len(d)") now)"

BATCH=$(python3 "$REPO/ai-api/scripts/make-test-event.py" --array)
EV=$(printf '%s' "$BATCH" | python3 -c "import json,sys; print(json.load(sys.stdin)[0]['event_id'])")
expect 202 "$(call POST /ingest "$INGEST_TOKEN" "$BATCH")" "ingest a live v2 event (as OBS's Vector posts it)"
[ "$(json "d['accepted']")" = 1 ] && ok "event accepted" || bad "ingest: $(cat /tmp/smoke.body)"
label=$(curl -sk -H "Authorization: Bearer $BLUE" "$API/telemetry/events?limit=1000&since=$(date -u +%Y-%m-%dT00:00:00Z)" \
  | python3 -c "import json,sys; print([e['actor'] for e in json.load(sys.stdin)['events'] if e['event_id']=='$EV'])")
case "$label" in *JS26-R-002*red-app*|*red-app*JS26-R-002*) ok "live event kept OBS's attribution (JS26-R-002, red-app)" ;; *) bad "attribution: $label" ;; esac

timeout 4 curl -skN -H "Authorization: Bearer $BLUE" "$API/telemetry/stream?cursor=czA" > /tmp/smoke.sse 2>/dev/null || true
grep -q '^data: ' /tmp/smoke.sse && ok "live stream (SSE) delivers events" || bad "stream sent nothing"

expect 202 "$(call POST /actions/block-ip "$BLUE" '{"target":{"namespace":"jengasec-ent-a-app01","ip":"10.60.2.14"},"justification":"smoke test"}')" "AI Blue shadow block-ip"
[ "$(json "d['effective']")" = False ] && ok "block-ip recorded, not applied (shadow mode)" || bad "effective: $(cat /tmp/smoke.body)"
expect 403 "$(call POST /actions/alert "$RED" '{"target":{"namespace":"jengasec-ent-a-app01"},"justification":"x"}')" "AI Red cannot act"
expect 201 "$(call POST /decisions "$BLUE" "{\"incident_id\":\"smoke\",\"summary\":\"smoke test decision\",\"confidence\":0.9,\"evidence\":[\"$EV\"]}")" "AI Blue posts a decision"

expect 200 "$(call POST /admin/kill-switch "$ADMIN_TOKEN" '{"on":true}')" "kill switch on"
expect 423 "$(call POST /actions/alert "$BLUE" '{"target":{"namespace":"jengasec-ent-a-app01"},"justification":"during kill switch"}')" "actions halted while it is on"
expect 200 "$(call POST /admin/kill-switch "$ADMIN_TOKEN" '{"on":false}')" "kill switch off"

expect 200 "$(call GET /admin/export/AI-01 "$ADMIN_TOKEN")" "judges' export for AI-01"
printf '        AI-01 ground truth: precision %s, recall %s, decisions %s
' "$(json "d['ground_truth']['precision']")" "$(json "d['ground_truth']['recall']")" "$(json "d['ground_truth']['decisions']")"


if [ -n "${WEBSITE_FEED_URL:-}" ]; then
  echo "Website link ($WEBSITE_FEED_URL)"
  expect 200 "$(call POST /admin/publish-marks "$ADMIN_TOKEN")" "AI API published its marks"
  # The publish call succeeds even when the website refuses; what counts is the website's own answer.
  ws=$(json "d.get('website_status') or ''")
  case "$ws" in
    2??) ok "the website accepted them (HTTP $ws)" ;;
    404) bad "the website answered 404: DJANGO_FEED_TOKEN is not set there (website vault: vault_django_feed_token, then make platform)" ;;
    403) bad "the website answered 403: WEBSITE_FEED_TOKEN here differs from the website's DJANGO_FEED_TOKEN" ;;
    *)   bad "the website answered ${ws:-nothing}: $(json "d.get('website_answer')")" ;;
  esac
fi
echo "$PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
