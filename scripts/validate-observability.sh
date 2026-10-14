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
RUNTIME_DIR="$REPO_ROOT/observability/.runtime"

need docker
need jq
need python3
need helm
docker info >/dev/null 2>&1 || die "Docker is not running"

validation_root="$(mktemp -d /tmp/jengasec-collector-validation.XXXXXX)"
collector_container=""
cleanup() {
  if [[ -n "$collector_container" ]]; then
    docker rm "$collector_container" >/dev/null 2>&1 || true
  fi
  rm -r -- "$validation_root"
}
trap cleanup EXIT

python3 "$REPO_ROOT/scripts/prepare-observability-runtime.py" \
  --runtime-dir "$RUNTIME_DIR" \
  --access-principals \
  "$REPO_ROOT/observability/tests/fixtures/access/access-principals.csv"

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
  website-feed-mock \
  otel-collector \
  contract-tests \
  catalogue-renderer \
  dashboard-renderer \
  grafana-access-provisioner

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

log "checking website feed mock Python syntax"
"${COMPOSE[@]}" run --rm --no-deps \
  --entrypoint python \
  website-feed-mock \
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
    --env OBS_KUBE_TOKEN_FILE=/dev/null \
    --env OBS_KUBE_CA_FILE=/validation-ca.crt \
    --volume /etc/ssl/certs/ca-certificates.crt:/validation-ca.crt:ro \
    --volume "$REPO_ROOT/charts/observability-agent/files:/validation:ro" \
    otel-collector \
    validate --config="/validation/$collector_config"
done

log "testing native Kubernetes collectors and persistent replay"
project_name="$("${COMPOSE[@]}" config --format json | python3 -c 'import json,sys; print(json.load(sys.stdin)["name"])')"
collector_container="$(docker create "${project_name}-otel-collector")"
docker cp "$collector_container:/otelcol-contrib" "$validation_root/otelcol-contrib"
chmod 0755 "$validation_root/otelcol-contrib"
"${COMPOSE[@]}" run --rm --no-deps \
  --entrypoint python \
  --env HELM_BIN=/validation-tools/helm \
  --env OTELCOL_BIN=/validation-tools/otelcol-contrib \
  --volume "$(command -v helm):/validation-tools/helm:ro" \
  --volume "$validation_root/otelcol-contrib:/validation-tools/otelcol-contrib:ro" \
  contract-tests \
  charts/observability-agent/tests/test-agent.py

log "running JSON Schema fixture tests"
"${COMPOSE[@]}" run --rm --no-deps contract-tests

log "testing native infrastructure event acceptance and rejection"
"${COMPOSE[@]}" run --rm --no-deps --entrypoint python contract-tests \
  observability/tests/render-infrastructure-vector-tests.py \
  >"$validation_root/infrastructure-vector.yaml"
"${COMPOSE[@]}" run --rm --no-deps \
  --env JENGASEC_INFRASTRUCTURE_RESOURCE_IDS=test-host \
  --volume "$validation_root/infrastructure-vector.yaml:/validation/infrastructure.yaml:ro" \
  vector test /validation/infrastructure.yaml

log "checking infrastructure metrics and optional integrations"
"${COMPOSE[@]}" run --rm --no-deps --entrypoint python contract-tests \
  charts/observability-agent/tests/test-wal-guard.py
for test_script in test-infrastructure-metrics.py test-optional-integrations.py test-release-archive.py test-infrastructure-dashboards.py test-provisioning-snapshot.py test-provisioning-service.py test-gateway-observation.py; do
  "${COMPOSE[@]}" run --rm --no-deps \
    --entrypoint python \
    contract-tests \
    "observability/tests/$test_script"
done

log "running attribution snapshot fixture tests"
"${COMPOSE[@]}" run --rm --no-deps \
  --entrypoint bash \
  contract-tests \
  observability/tests/test-attribution.sh

log "running Grafana dashboard and access fixture tests"
"${COMPOSE[@]}" run --rm --no-deps \
  --entrypoint bash \
  contract-tests \
  observability/tests/test-grafana-access.sh

log "running evidence export fixture tests"
"${COMPOSE[@]}" run --rm --no-deps \
  --entrypoint bash \
  contract-tests \
  observability/tests/test-evidence-export.sh

log "rendering Vector lookups from the event catalogue"
"${COMPOSE[@]}" run --rm --no-deps catalogue-renderer

log "rendering Vector lookups from the platform attribution fixtures"
"${COMPOSE[@]}" run --rm --no-deps attribution-renderer

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
  -config.expand-env=true \
  -verify-config=true

log "observability validation passed"
