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

need docker
docker info >/dev/null 2>&1 || die "Docker is not running"

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
