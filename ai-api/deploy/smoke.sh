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
set -a
# shellcheck source=/dev/null
. "$ETC/ai-api.env"
set +a
rehearsal_mode="${SCORING_MODE-0}"
case "${rehearsal_mode,,}" in
  0|false|no|off) ;;
  *) printf '%s\n' 'Refusing shadow rehearsal: local SCORING_MODE is not disabled.' >&2; exit 2 ;;
esac
BASE="${1:-}"
if [ -z "$BASE" ]; then
  if curl -fsk https://127.0.0.1:8443/healthz >/dev/null 2>&1; then BASE=https://127.0.0.1:8443; else BASE=http://127.0.0.1:8000; fi
fi
# Probe the selected target, including URL overrides, before loading tokens or writing.
if ! rehearsal_headers=$(curl -q -fsk --connect-timeout 3 --max-time 5 --dump-header - --output /dev/null "$BASE/healthz"); then
  printf '%s\n' 'Refusing shadow rehearsal: cannot confirm the target mode.' >&2
  exit 2
fi
if ! printf '%s\n' "$rehearsal_headers" | awk '
  /^HTTP\// { status = $2; sub(/\r$/, "", status); count = 0; mode = ""; next }
  {
    colon = index($0, ":")
    if (!colon) next
    name = tolower(substr($0, 1, colon - 1))
    gsub(/[ \t]/, "", name)
    if (name == "x-jengasec-scoring-mode") {
      count++
      mode = tolower(substr($0, colon + 1))
      gsub(/^[ \t]+|[ \t\r]+$/, "", mode)
    }
  }
  END { exit !(status == "200" && (count == 0 || (count == 1 && mode == "legacy-shadow"))) }
'; then
  printf '%s\n' 'Refusing shadow rehearsal: target mode is not confirmed legacy.' >&2
  exit 2
fi
unset rehearsal_headers rehearsal_mode
API="$BASE/api/v1"
tok() { awk -v t="$1" '$1==t {print $3}' "$ETC/team-tokens.txt"; }
BLUE=$(tok AI-01); RED=$(tok RI-01)
REPO=/opt/jengasec-ai/repo
RED_ID=$(awk '/code: RI-01/ {for (i=1;i<=NF;i++) if ($i=="team_id:") {gsub(",","",$(i+1)); print $(i+1)}}' "$REPO/scripts/ai-teams.yaml")
if [ -z "$BLUE" ] || [ -z "$RED" ]; then
  echo "AI-01 / RI-01 tokens not in $ETC/team-tokens.txt" >&2
  exit 1
fi

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
expect() {
  local want=$1 got=$2 what=$3
  if [ "$got" = "$want" ]; then ok "$what"; else bad "$what (HTTP $got, wanted $want: $(head -c 200 /tmp/smoke.body))"; fi
}

echo "AI API smoke test against $API"
if [ "$(curl -sk -o /dev/null -w '%{http_code}' "$BASE/healthz")" = 200 ]; then ok "healthz"; else bad "healthz"; fi
expect 401 "$(call GET /telemetry/events nobody)" "unknown token refused"

expect 200 "$(call GET '/telemetry/events?limit=1000' "$BLUE")" "AI Blue reads events"
n_blue=$(json "len(d['events'])"); ents=$(json "sorted({e['enterprise'] for e in d['events']})")
if [ "$n_blue" -gt 0 ]; then ok "AI Blue sees $n_blue events across $ents"; else bad "AI Blue sees no events (is SANDBOX_SEED=1?)"; fi

expect 200 "$(call GET '/telemetry/events?limit=1000' "$RED")" "AI Red reads its feed"
teams=$(json "sorted({e['actor']['team_id'] for e in d['events']})")
if [ "$teams" = "['$RED_ID']" ]; then ok "AI Red RI-01 ($RED_ID) sees only its own traffic ($(json "len(d['events'])") events)"; else bad "AI Red sees $teams"; fi

expect 200 "$(call GET /assets "$BLUE")" "assets"
if [ "$(json "len([a for a in d if a['namespace'].startswith('jengasec-')])")" = 18 ]; then ok "18 applications with reserved IPs"; else bad "assets: $(json "len(d)")"; fi
expect 200 "$(call GET /alerts "$BLUE")" "baseline alerts ($(json "len(d)") now)"

BATCH=$(python3 "$REPO/ai-api/scripts/make-test-event.py" --array)
EV=$(printf '%s' "$BATCH" | python3 -c "import json,sys; print(json.load(sys.stdin)[0]['event_id'])")
expect 202 "$(call POST /ingest "$INGEST_TOKEN" "$BATCH")" "ingest a live v2 event (as OBS's Vector posts it)"
if [ "$(json "d['accepted']")" = 1 ]; then ok "event accepted"; else bad "ingest: $(cat /tmp/smoke.body)"; fi
label=$(curl -sk -H "Authorization: Bearer $BLUE" "$API/telemetry/events?limit=1000&since=$(date -u +%Y-%m-%dT00:00:00Z)" \
  | python3 -c "import json,sys; print([e['actor'] for e in json.load(sys.stdin)['events'] if e['event_id']=='$EV'])")
case "$label" in *JS26-R-002*red-app*|*red-app*JS26-R-002*) ok "live event kept OBS's attribution (JS26-R-002, red-app)" ;; *) bad "attribution: $label" ;; esac

timeout 4 curl -skN -H "Authorization: Bearer $BLUE" "$API/telemetry/stream?cursor=czA" > /tmp/smoke.sse 2>/dev/null || true
if grep -q '^data: ' /tmp/smoke.sse; then ok "live stream (SSE) delivers events"; else bad "stream sent nothing"; fi

expect 202 "$(call POST /actions/block-ip "$BLUE" '{"target":{"namespace":"jengasec-ent-a-app01","ip":"10.60.2.14"},"justification":"smoke test"}')" "AI Blue shadow block-ip"
if [ "$(json "d['effective']")" = False ]; then ok "block-ip recorded, not applied (shadow mode)"; else bad "effective: $(cat /tmp/smoke.body)"; fi
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
  expect 200 "$(call POST /admin/publish-marks "$ADMIN_TOKEN")" "AI marks pushed to the website"
  printf '        website answered %s\n' "$(json "d['website_status'], d['website_answer']")"
fi
echo "$PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
