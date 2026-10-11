#!/usr/bin/env bash
# Validate observability configs, schemas, fixtures, and container builds.
# Owner: Observability. Run: ./scripts/validate-observability.sh
# Changes: builds images and creates temporary Docker resources.
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

log "building test fixtures and contract test images"
"${COMPOSE[@]}" build \
  test-emitter \
  source-fixture \
  otel-collector \
  contract-tests \
  catalogue-renderer

log "checking test emitter Python syntax"
"${COMPOSE[@]}" run --rm --no-deps \
  --entrypoint python \
  test-emitter \
  -c 'compile(open("/app/app.py", encoding="utf-8").read(), "/app/app.py", "exec")'

log "checking source fixture Python syntax"
"${COMPOSE[@]}" run --rm --no-deps \
  --entrypoint python \
  source-fixture \
  -c 'compile(open("/app/app.py", encoding="utf-8").read(), "/app/app.py", "exec")'

log "validating OpenTelemetry Collector configuration"
"${COMPOSE[@]}" run --rm --no-deps \
  otel-collector \
  validate --config=/etc/otelcol-contrib/config.yaml

log "validating k3s OpenTelemetry Collector configurations"
for collector_config in logs.yaml cluster.yaml; do
  "${COMPOSE[@]}" run --rm --no-deps --user 0 \
    --env K8S_NODE_NAME=rehearsal-node \
    --env OBS_OTLP_ENDPOINT=obs.example.invalid:4317 \
    --env OBS_OTLP_INSECURE=true \
    --env OBS_PROMETHEUS_REMOTE_WRITE_URL=http://obs.example.invalid:9090/api/v1/write \
    --volume "$REPO_ROOT/charts/observability-agent/files:/validation:ro" \
    otel-collector \
    validate --config="/validation/$collector_config"
done

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
