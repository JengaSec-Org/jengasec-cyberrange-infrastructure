#!/usr/bin/env bash
# Build and start the local JengaSec observability stack.
# Owner: Observability. Run: ./scripts/start-observability.sh
# Changes: creates or updates local Docker containers, networks, and volumes only.
set -euo pipefail

# shellcheck source=scripts/_lib.sh
. "$(dirname "$0")/_lib.sh"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/observability/compose.yaml"

need docker
docker info >/dev/null 2>&1 || die "Docker is not running"

run docker compose --file "$COMPOSE_FILE" up \
  --build \
  --detach \
  --remove-orphans \
  --wait

log "Grafana:   http://127.0.0.1:${JENGASEC_GRAFANA_PORT:-3000}"
log "Prometheus: http://127.0.0.1:${JENGASEC_PROMETHEUS_PORT:-9090}"
log "Loki:      http://127.0.0.1:${JENGASEC_LOKI_PORT:-3100}"
log "Workload:  http://127.0.0.1:${JENGASEC_REFERENCE_PORT:-8080}"
