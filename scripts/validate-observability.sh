#!/usr/bin/env bash
# Validate observability configs, schemas, fixtures, and container builds.
# Owner: Observability. Run: ./scripts/validate-observability.sh
# Changes: builds local images and creates temporary local Docker resources only.
set -euo pipefail

# shellcheck source=scripts/_lib.sh
. "$(dirname "$0")/_lib.sh"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/observability/compose.yaml"
COMPOSE=(docker compose --file "$COMPOSE_FILE")

need docker
need jq
docker info >/dev/null 2>&1 || die "Docker is not running"

log "validating Docker Compose model"
"${COMPOSE[@]}" config --quiet

log "validating JSON fixtures and dashboard syntax"
find "$REPO_ROOT/contracts/fixtures" -type f -name '*.json' -print0 \
  | xargs -0 -r -n1 jq empty
jq empty \
  "$REPO_ROOT/observability/grafana/dashboards/jengasec-observability.json"

log "building reference emitter and contract test images"
"${COMPOSE[@]}" build test-emitter contract-tests catalogue-renderer

log "checking test emitter Python syntax"
"${COMPOSE[@]}" run --rm --no-deps \
  --entrypoint python \
  test-emitter \
  -c 'compile(open("/app/app.py", encoding="utf-8").read(), "/app/app.py", "exec")'

log "running JSON Schema fixture tests"
"${COMPOSE[@]}" run --rm --no-deps contract-tests

log "rendering Vector lookups from the event catalogue"
"${COMPOSE[@]}" run --rm --no-deps catalogue-renderer

log "validating Vector configuration and VRL program"
"${COMPOSE[@]}" run --rm --no-deps vector \
  validate --skip-healthchecks /etc/vector/generated/vector.yaml

log "validating Prometheus configuration"
"${COMPOSE[@]}" run --rm --no-deps \
  --entrypoint /bin/promtool \
  prometheus \
  check config /etc/prometheus/prometheus.yml

log "validating Loki configuration"
"${COMPOSE[@]}" run --rm --no-deps loki \
  -config.file=/etc/loki/local-config.yaml \
  -verify-config=true

log "observability validation passed"
