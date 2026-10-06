#!/usr/bin/env bash
# Prove a real event reaches Loki and a real metric reaches Prometheus.
# Owner: Observability. Run after start-observability.sh: ./scripts/smoke-observability.sh
# Changes: emits one synthetic event and stores only local observability test data.
set -euo pipefail

# shellcheck source=scripts/_lib.sh
. "$(dirname "$0")/_lib.sh"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/observability/compose.yaml"
COMPOSE=(docker compose --file "$COMPOSE_FILE")
HOST="${JENGASEC_OBSERVABILITY_HOST:-127.0.0.1}"
REFERENCE_URL="http://${HOST}:${JENGASEC_REFERENCE_PORT:-8080}"
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

  "${COMPOSE[@]}" run --rm --no-deps \
    --volume "$TEMP_DIR:/evidence:ro" \
    --entrypoint check-jsonschema \
    contract-tests \
    --schemafile "$schema" "/evidence/$evidence_file"
}

wait_for_http "reference workload" "$REFERENCE_URL/healthz"
wait_for_http "Loki" "$LOKI_URL/ready"
wait_for_http "Prometheus" "$PROMETHEUS_URL/-/ready"
wait_for_http "Grafana" "$GRAFANA_URL/api/health"

"${COMPOSE[@]}" build --quiet contract-tests

marker="smoke-$(date -u +%Y%m%dT%H%M%S)-$$"
start_ns="$(date +%s)000000000"
curl --fail --silent --show-error \
  "$REFERENCE_URL/emit?marker=$marker" \
  --output "$TEMP_DIR/logging-event.json"
validate_evidence \
  contracts/logging-contract.schema.json \
  logging-event.json
log "reference workload emitted contract-valid marker $marker"

loki_event=""
for _attempt in {1..60}; do
  end_ns="$(date +%s)999999999"
  curl --fail --silent --show-error --get \
    --data-urlencode 'query={cell="app-01",event_type="reference_smoke"}' \
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
        | select(.metadata.original.detail.marker == $marker)
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
log "Loki stored contract-valid telemetry event $event_id"

metric_value=""
for _attempt in {1..60}; do
  curl --fail --silent --show-error --get \
    --data-urlencode \
    'query=jengasec_reference_http_requests_total{job="reference-app",route="emit"}' \
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
log "Prometheus stored reference emit requests=$metric_value"

curl --fail --silent --show-error \
  "$GRAFANA_URL/api/datasources/uid/prometheus/health" \
  | jq --exit-status '.status == "OK"' >/dev/null
curl --fail --silent --show-error \
  "$GRAFANA_URL/api/datasources/uid/loki/health" \
  | jq --exit-status '.status == "OK"' >/dev/null
curl --fail --silent --show-error \
  "$GRAFANA_URL/api/dashboards/uid/jengasec-codespaces" \
  | jq --exit-status '.dashboard.uid == "jengasec-codespaces"' >/dev/null
log "Grafana provisioned connected data sources and the Codespaces dashboard"
log "end-to-end observability smoke check passed"
