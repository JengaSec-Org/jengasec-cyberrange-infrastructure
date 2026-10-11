#!/usr/bin/env bash
# Prove a real event reaches Loki and a real metric reaches Prometheus.
# Owner: Observability. Run after start-observability.sh: ./scripts/smoke-observability.sh
# Changes: emits one synthetic event and stores temporary test data.
set -euo pipefail

# shellcheck source=scripts/_lib.sh
. "$(dirname "$0")/_lib.sh"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/observability/compose.yaml"
COMPOSE=(docker compose --file "$COMPOSE_FILE")
HOST="${JENGASEC_OBSERVABILITY_HOST:-127.0.0.1}"
TEST_EMITTER_URL="http://${HOST}:${JENGASEC_TEST_EMITTER_PORT:-8080}"
SOURCE_FIXTURE_URL="http://${HOST}:${JENGASEC_SOURCE_FIXTURE_PORT:-8081}"
LOKI_URL="http://${HOST}:${JENGASEC_LOKI_PORT:-3100}"
PROMETHEUS_URL="http://${HOST}:${JENGASEC_PROMETHEUS_PORT:-9090}"
GRAFANA_URL="http://${HOST}:${JENGASEC_GRAFANA_PORT:-3000}"
TEMP_DIR="$(mktemp -d)"

cleanup() {
  if [[ -n "${TEMP_DIR:-}" && -d "$TEMP_DIR" ]]; then
    rm -r -- "$TEMP_DIR"
  fi
}
trap cleanup EXIT

need curl
need docker
need jq
docker info >/dev/null 2>&1 || die "Docker is not running"

wait_for_http() {
  local description="$1"
  local url="$2"
  local _attempt

  for _attempt in {1..60}; do
    if curl --fail --silent --output /dev/null "$url"; then
      log "$description is ready"
      return 0
    fi
    sleep 1
  done
  die "$description did not become ready: $url"
}

validate_evidence() {
  local schema="$1"
  local evidence_file="$2"

  "${COMPOSE[@]}" run --rm --no-deps --no-TTY --interactive=false \
    --volume "$TEMP_DIR:/evidence:ro" \
    --entrypoint check-jsonschema \
    contract-tests \
    --schemafile "$schema" "/evidence/$evidence_file"
}

wait_for_http "test emitter" "$TEST_EMITTER_URL/healthz"
wait_for_http "source fixture" "$SOURCE_FIXTURE_URL/healthz"
wait_for_http "Loki" "$LOKI_URL/ready"
wait_for_http "Prometheus" "$PROMETHEUS_URL/-/ready"
wait_for_http "Grafana" "$GRAFANA_URL/api/health"

"${COMPOSE[@]}" build --quiet contract-tests

marker="smoke-$(date -u +%Y%m%dT%H%M%S)-$$"
start_ns="$(date +%s)000000000"
curl --fail --silent --show-error \
  "$TEST_EMITTER_URL/emit?marker=$marker" \
  --output "$TEMP_DIR/logging-event.json"
validate_evidence \
  contracts/logging-contract.schema.json \
  logging-event.json
log "test emitter wrote contract-valid marker $marker"

loki_event=""
for _attempt in {1..60}; do
  end_ns="$(date +%s)999999999"
  curl --fail --silent --show-error --get \
    --data-urlencode 'query={enterprise="ENT-A",application="APP01",event_type="http_request"}' \
    --data-urlencode "start=$start_ns" \
    --data-urlencode "end=$end_ns" \
    --data-urlencode 'direction=backward' \
    --data-urlencode 'limit=20' \
    "$LOKI_URL/loki/api/v1/query_range" \
    --output "$TEMP_DIR/loki-response.json"
  loki_event="$(
    jq --compact-output --arg marker "$marker" '
      [
        .data.result[].values[]?[1]
        | fromjson?
        | select(.request_id == $marker)
      ][0] // empty
    ' "$TEMP_DIR/loki-response.json"
  )"
  if [[ -n "$loki_event" ]]; then
    break
  fi
  sleep 1
done
[[ -n "$loki_event" ]] || die "Loki did not return marker $marker"
printf '%s\n' "$loki_event" >"$TEMP_DIR/telemetry-event.json"
validate_evidence \
  contracts/telemetry-event.schema.json \
  telemetry-event.json
event_id="$(jq --raw-output '.event_id' "$TEMP_DIR/telemetry-event.json")"
integrity_hash="$(jq --raw-output '.integrity_hash' "$TEMP_DIR/telemetry-event.json")"
log "Loki stored contract-valid telemetry event $event_id ($integrity_hash)"

curl --fail --silent --show-error \
  "$SOURCE_FIXTURE_URL/emit?marker=sources-$marker" \
  --output "$TEMP_DIR/source-emission.json"
jq --exit-status '
  (.markers | keys | sort) == ["application", "firewall", "host", "ids", "ingress", "kubernetes"] and
  (.netflow_src_port | type == "number")
' "$TEMP_DIR/source-emission.json" >/dev/null

source_events_ready=false
for _attempt in {1..60}; do
  end_ns="$(date +%s)999999999"
  curl --fail --silent --show-error --get \
    --data-urlencode 'query={enterprise="ENT-A",application=~"APP0[12]"}' \
    --data-urlencode "start=$start_ns" \
    --data-urlencode "end=$end_ns" \
    --data-urlencode 'direction=backward' \
    --data-urlencode 'limit=100' \
    "$LOKI_URL/loki/api/v1/query_range" \
    --output "$TEMP_DIR/source-loki-response.json"
  if jq --exit-status \
    --slurpfile emitted "$TEMP_DIR/source-emission.json" '
      [.data.result[].values[]?[1] | fromjson?] as $events |
      ($emitted[0].markers) as $markers |
      ($emitted[0].netflow_src_port) as $netflow_port |
      def participant_actor:
        .ip == "10.60.1.10" and
        .participant_id == "JS26-P-0001" and
        .team_id == "JS26-R-001" and
        .team_label == "red-app";
      any($events[];
        .request_id == $markers.ingress and
        .source == "ingress" and .raw_event == "ingress_request" and
        .event_type == "http_request" and .verdict == "allowed" and
        (.actor | participant_actor)) and
      any($events[];
        .request_id == $markers.firewall and
        .source == "network" and .raw_event == "firewall_refused" and
        .event_type == "scope_violation" and .outcome == "denied" and
        .verdict == "refused" and .application == "APP02" and
        .target.ip == "10.108.0.12" and
        (.actor | participant_actor)) and
      any($events[];
        .request_id == $markers.ids and
        .source == "ids" and .raw_event == "suricata_alert" and
        .event_type == "ids_alert" and .verdict == "allowed" and
        (.actor | participant_actor)) and
      any($events[];
        .request_id == $markers.host and
        .source == "host" and .raw_event == "host_alert" and
        .actor.team_label == "unknown" and
        .metadata.attribution_status == "unknown") and
      any($events[];
        .request_id == $markers.application and
        .source == "application" and .raw_event == "request_completed" and
        .event_type == "http_request" and .verdict == "allowed" and
        (.actor | participant_actor)) and
      any($events[];
        .request_id == $markers.kubernetes and
        .source == "kubernetes" and .raw_event == "kubernetes_event" and
        .actor.team_label == "unknown" and
        .metadata.attribution_status == "unknown") and
      any($events[];
        .source == "network" and .raw_event == "netflow_record" and
        .network.src_port == $netflow_port and .verdict == "allowed" and
        (.actor | participant_actor)) and
      all(
        $events[] |
        select(
          (.request_id | IN(
            $markers.ingress,
            $markers.firewall,
            $markers.ids,
            $markers.host,
            $markers.application,
            $markers.kubernetes
          )) or
          (.source == "network" and .raw_event == "netflow_record" and
           .network.src_port == $netflow_port)
        );
        .enterprise == "ENT-A" and
        if .request_id == $markers.firewall then
          .application == "APP02" and
          .namespace == "jengasec-ent-a-app02" and
          .target.ip == "10.108.0.12"
        else
          .application == "APP01" and
          .namespace == "jengasec-ent-a-app01" and
          .target.ip == "10.108.0.11"
        end
      )
    ' "$TEMP_DIR/source-loki-response.json" >/dev/null; then
    source_events_ready=true
    break
  fi
  sleep 1
done
[[ "$source_events_ready" == true ]] \
  || die "Loki did not return every synthetic production-source event"
jq --exit-status '
  all(
    .data.result[];
    (.stream | keys | sort) ==
      ["application", "detected_level", "enterprise", "event_type", "namespace", "service_name", "severity", "source"]
  )
' "$TEMP_DIR/source-loki-response.json" >/dev/null \
  || die "Loki stream labels contain an unapproved field"

jq --compact-output \
  --slurpfile emitted "$TEMP_DIR/source-emission.json" '
    [.data.result[].values[]?[1] | fromjson?] as $events |
    ($emitted[0].markers) as $markers |
    ($emitted[0].netflow_src_port) as $netflow_port |
    $events[] |
    select(
      (.request_id | IN(
        $markers.ingress,
        $markers.firewall,
        $markers.ids,
        $markers.host,
        $markers.application,
        $markers.kubernetes
      )) or
      (.source == "network" and .raw_event == "netflow_record" and
       .network.src_port == $netflow_port)
    )
  ' "$TEMP_DIR/source-loki-response.json" \
  >"$TEMP_DIR/source-telemetry-events.jsonl"

source_event_count="$(wc -l <"$TEMP_DIR/source-telemetry-events.jsonl")"
[[ "$source_event_count" -eq 7 ]] \
  || die "expected seven synthetic production-source events, found $source_event_count"
while IFS= read -r source_event; do
  printf '%s\n' "$source_event" >"$TEMP_DIR/source-telemetry-event.json"
  validate_evidence \
    contracts/telemetry-event.schema.json \
    source-telemetry-event.json
done <"$TEMP_DIR/source-telemetry-events.jsonl"
log "Loki stored seven contract-valid application, gateway, network, host, and cluster events"

quarantine_count() {
  "${COMPOSE[@]}" exec -T vector sh -c \
    'if [ -f /var/lib/vector/quarantine/events.jsonl ]; then wc -l < /var/lib/vector/quarantine/events.jsonl; else echo 0; fi' \
    | tr -d '[:space:]'
}

quarantine_before="$(quarantine_count)"
curl --fail --silent --show-error \
  "$TEST_EMITTER_URL/emit-invalid?marker=invalid-$marker" \
  --output /dev/null
curl --fail --silent --show-error \
  "$TEST_EMITTER_URL/emit-sensitive?marker=sensitive-$marker" \
  --output /dev/null

quarantine_after="$quarantine_before"
for _attempt in {1..30}; do
  quarantine_after="$(quarantine_count)"
  if (( quarantine_after >= quarantine_before + 2 )); then
    break
  fi
  sleep 1
done
(( quarantine_after >= quarantine_before + 2 )) \
  || die "Vector did not quarantine both rejected events"
"${COMPOSE[@]}" exec -T vector \
  sh -c 'cat /var/lib/vector/quarantine/events.jsonl' \
  >"$TEMP_DIR/quarantine.jsonl"
if grep -q 'TEST-ONLY-NOT-A-CREDENTIAL' "$TEMP_DIR/quarantine.jsonl"; then
  die "quarantine retained a sensitive value"
fi
jq --slurp --exit-status '
  any(.[]; .reason == "sensitive_field") and
  any(.[]; .reason == "contract_or_catalogue_rejected") and
  all(.[]; (.payload_hash | test("^sha256:[a-f0-9]{64}$")))
' "$TEMP_DIR/quarantine.jsonl" >/dev/null
log "Vector quarantined invalid and sensitive events without retaining payloads"

metric_value=""
for _attempt in {1..60}; do
  curl --fail --silent --show-error --get \
    --data-urlencode \
    'query=jengasec_test_http_requests_total{job="test-emitter",route="emit"}' \
    "$PROMETHEUS_URL/api/v1/query" \
    --output "$TEMP_DIR/prometheus-response.json"
  metric_value="$(
    jq --raw-output '
      [
        .data.result[]?.value[1]
        | tonumber
        | select(. > 0)
      ][0] // empty
    ' "$TEMP_DIR/prometheus-response.json"
  )"
  if [[ -n "$metric_value" ]]; then
    break
  fi
  sleep 1
done
[[ -n "$metric_value" ]] || die "Prometheus did not scrape the emitted-request metric"
log "Prometheus stored test emitter requests=$metric_value"

kubernetes_health=""
for _attempt in {1..60}; do
  curl --fail --silent --show-error --get \
    --data-urlencode \
    'query=jengasec_test_kubernetes_health{job="source-fixture",enterprise="ENT-A",application="APP01"}' \
    "$PROMETHEUS_URL/api/v1/query" \
    --output "$TEMP_DIR/kubernetes-health-response.json"
  kubernetes_health="$(
    jq --raw-output '
      [
        .data.result[]?.value[1]
        | tonumber
        | select(. == 1)
      ][0] // empty
    ' "$TEMP_DIR/kubernetes-health-response.json"
  )"
  if [[ -n "$kubernetes_health" ]]; then
    break
  fi
  sleep 1
done
[[ "$kubernetes_health" == "1" ]] \
  || die "Prometheus did not scrape the synthetic Kubernetes health metric"
log "Prometheus stored the remote-written Kubernetes health metric"

attribution_metric=""
for _attempt in {1..60}; do
  curl --fail --silent --show-error --get \
    --data-urlencode \
    'query=sum(jengasec_attribution_events_total{job="vector",status="known"})' \
    "$PROMETHEUS_URL/api/v1/query" \
    --output "$TEMP_DIR/attribution-metric-response.json"
  attribution_metric="$(
    jq --raw-output '
      [.data.result[]?.value[1] | tonumber | select(. > 0)][0] // empty
    ' "$TEMP_DIR/attribution-metric-response.json"
  )"
  if [[ -n "$attribution_metric" ]]; then
    break
  fi
  sleep 1
done
[[ -n "$attribution_metric" ]] \
  || die "Prometheus did not scrape the attribution health metric"
log "Prometheus stored the attribution health metric"

curl --fail --silent --show-error \
  "$GRAFANA_URL/api/datasources/uid/prometheus/health" \
  | jq --exit-status '.status == "OK"' >/dev/null
curl --fail --silent --show-error \
  "$GRAFANA_URL/api/datasources/uid/loki/health" \
  | jq --exit-status '.status == "OK"' >/dev/null
curl --fail --silent --show-error \
  "$GRAFANA_URL/api/dashboards/uid/jengasec-observability" \
  | jq --exit-status '.dashboard.uid == "jengasec-observability"' >/dev/null
log "Grafana provisioned the data sources and dashboard"
log "end-to-end observability smoke check passed"
