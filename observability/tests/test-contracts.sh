#!/usr/bin/env bash
# Validate positive and negative fixtures against the two telemetry contracts.
# Owner: Observability. Run: docker compose -f observability/compose.yaml run --rm contract-tests
# Changes: reads contracts and fixtures only; it does not change local or remote state.
set -euo pipefail

# shellcheck source=scripts/_lib.sh
. "$(dirname "$0")/../../scripts/_lib.sh"

need check-jsonschema

assert_valid() {
  local schema="$1"
  local fixture="$2"

  check-jsonschema --schemafile "$schema" "$fixture"
  log "accepted valid fixture: $fixture"
}

assert_invalid() {
  local schema="$1"
  local fixture="$2"

  if check-jsonschema --schemafile "$schema" "$fixture" >/dev/null 2>&1; then
    die "invalid fixture unexpectedly passed: $fixture"
  fi
  log "rejected invalid fixture: $fixture"
}

assert_valid \
  contracts/logging-contract.schema.json \
  contracts/fixtures/logging/valid/reference-smoke.json
assert_invalid \
  contracts/logging-contract.schema.json \
  contracts/fixtures/logging/invalid/missing-outcome.json
assert_valid \
  contracts/telemetry-event.schema.json \
  contracts/fixtures/telemetry/valid/reference-smoke.json
assert_invalid \
  contracts/telemetry-event.schema.json \
  contracts/fixtures/telemetry/invalid/extra-top-level-field.json

log "contract fixture tests passed"
