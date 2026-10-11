#!/usr/bin/env bash
# Build and start the JengaSec observability stack.
# Owner: Observability. Run: ./scripts/start-observability.sh
# Changes: creates or updates Docker containers, networks, and volumes.
set -euo pipefail

# shellcheck source=scripts/_lib.sh
. "$(dirname "$0")/_lib.sh"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/observability/compose.yaml"
DISPLAY_HOST="${JENGASEC_OBSERVABILITY_HOST:-127.0.0.1}"
RUNTIME_DIR="$REPO_ROOT/observability/.runtime"
ACCESS_FIXTURE="$REPO_ROOT/observability/tests/fixtures/access/access-principals.csv"

need docker
need python3
docker info >/dev/null 2>&1 || die "Docker is not running"

retention_hours="${JENGASEC_RETENTION_HOURS:-168}"
[[ "$retention_hours" =~ ^[1-9][0-9]*$ ]] \
  || die "JENGASEC_RETENTION_HOURS must be a positive integer"
if [[ -n "${JENGASEC_EVENT_WINDOW_HOURS:-}" || -n "${JENGASEC_APPEAL_WINDOW_HOURS:-}" ]]; then
  [[ "${JENGASEC_EVENT_WINDOW_HOURS:-}" =~ ^[1-9][0-9]*$ ]] \
    || die "JENGASEC_EVENT_WINDOW_HOURS must be a positive integer"
  [[ "${JENGASEC_APPEAL_WINDOW_HOURS:-}" =~ ^[1-9][0-9]*$ ]] \
    || die "JENGASEC_APPEAL_WINDOW_HOURS must be a positive integer"
  required_hours=$((JENGASEC_EVENT_WINDOW_HOURS + JENGASEC_APPEAL_WINDOW_HOURS))
  (( retention_hours >= required_hours )) \
    || die "retention must cover the event window plus the appeal window"
fi
export JENGASEC_RETENTION_HOURS="$retention_hours"

python3 "$REPO_ROOT/scripts/prepare-observability-runtime.py" \
  --runtime-dir "$RUNTIME_DIR" \
  --access-principals "$ACCESS_FIXTURE"

run docker compose --file "$COMPOSE_FILE" up \
  --build \
  --detach \
  --remove-orphans \
  --wait

log "Grafana:   http://${DISPLAY_HOST}:${JENGASEC_GRAFANA_PORT:-3000}"
log "Prometheus: http://${DISPLAY_HOST}:${JENGASEC_PROMETHEUS_PORT:-9090}"
log "Loki:      http://${DISPLAY_HOST}:${JENGASEC_LOKI_PORT:-3100}"
log "Emitter:   http://${DISPLAY_HOST}:${JENGASEC_TEST_EMITTER_PORT:-8080}"
log "Sources:   http://${DISPLAY_HOST}:${JENGASEC_SOURCE_FIXTURE_PORT:-8081}"
log "OTLP:      ${DISPLAY_HOST}:${JENGASEC_OTLP_PORT:-4317}/tcp"
log "Syslog:    ${DISPLAY_HOST}:${JENGASEC_SYSLOG_PORT:-1514}/tcp+udp"
log "NetFlow:   ${DISPLAY_HOST}:${JENGASEC_NETFLOW_PORT:-2055}/udp"
log "Retention: ${JENGASEC_RETENTION_HOURS}h"
