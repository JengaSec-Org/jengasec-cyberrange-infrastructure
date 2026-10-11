#!/usr/bin/env bash
# Stop the JengaSec observability stack while preserving its data volumes.
# Owner: Observability. Run: ./scripts/stop-observability.sh
# Changes: removes stack containers and network; named data volumes remain.
set -euo pipefail

# shellcheck source=scripts/_lib.sh
. "$(dirname "$0")/_lib.sh"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/observability/compose.yaml"

need docker
docker info >/dev/null 2>&1 || die "Docker is not running"

run docker compose --file "$COMPOSE_FILE" down --remove-orphans
log "observability stack stopped; named data volumes were preserved"
