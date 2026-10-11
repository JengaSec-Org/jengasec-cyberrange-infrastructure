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
