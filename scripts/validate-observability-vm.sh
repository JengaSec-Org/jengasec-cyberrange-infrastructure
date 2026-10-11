#!/usr/bin/env bash
# Rehearse the OBS VM Ansible role in an isolated local directory.
# Owner: Observability. Run: ./scripts/validate-observability-vm.sh
# Changes: creates and removes an isolated /tmp rehearsal tree.
set -euo pipefail

# shellcheck source=scripts/_lib.sh
. "$(dirname "$0")/_lib.sh"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REHEARSAL_ROOT="$(mktemp -d /tmp/jengasec-obs-vm.XXXXXX)"

cleanup() {
  exit_status=$?
  if declare -p compose >/dev/null 2>&1; then
    if (( exit_status != 0 )); then
      vector_container="$("${compose[@]}" ps --quiet vector 2>/dev/null || true)"
      if [[ -n "$vector_container" ]]; then
        docker inspect --format '{{json .State.Health}}' "$vector_container" >&2 || true
      fi
      "${compose[@]}" logs --no-color --tail=100 >&2 || true
    fi
    "${compose[@]}" down --remove-orphans >/dev/null 2>&1 || true
  fi
  if [[ -n "${REHEARSAL_ROOT:-}" && -d "$REHEARSAL_ROOT" ]]; then
    rm -r -- "$REHEARSAL_ROOT"
  fi
}
trap cleanup EXIT

need ansible-playbook
need curl
need docker
need python3
docker info >/dev/null 2>&1 || die "Docker is not running"

export JENGASEC_OBS_REHEARSAL_ROOT="$REHEARSAL_ROOT"
python_path="$(command -v python3)"
export JENGASEC_OBS_PYTHON="$python_path"
playbook=(
  ansible-playbook
  --inventory "localhost,"
  "$REPO_ROOT/ansible/observability-rehearsal.yml"
)

"${playbook[@]}" --syntax-check
"${playbook[@]}" >"$REHEARSAL_ROOT/first-run.log"
"${playbook[@]}" >"$REHEARSAL_ROOT/second-run.log"
grep -Eq 'localhost.*changed=0 .*failed=0' "$REHEARSAL_ROOT/second-run.log" \
  || die "second OBS VM rehearsal was not idempotent"

current="$REHEARSAL_ROOT/opt/current"
[[ -L "$current" ]] || die "rehearsal did not activate a release"
[[ "$(stat --format '%a' "$REHEARSAL_ROOT/etc/observability.env")" == "600" ]] \
  || die "OBS environment file is not owner-only"
[[ "$(stat --format '%a' "$REHEARSAL_ROOT/etc/secrets/grafana_admin_password")" == "600" ]] \
  || die "Grafana secret is not owner-only"

grep -q 'uri: "http://website-feed-mock:8080/api/feed"' \
  "$REHEARSAL_ROOT/state/lookups/vector.yaml" \
  || die "rehearsal Vector config did not use the test feed"
if grep -Eq '__[A-Z0-9_]+__' "$REHEARSAL_ROOT/state/lookups/vector.yaml"; then
  die "rehearsal Vector config retained a template placeholder"
fi

docker compose \
  --project-name jengasec-observability-rehearsal \
  --env-file "$REHEARSAL_ROOT/etc/observability.env" \
  --file "$current/observability/compose.production.yaml" \
  config --quiet

compose=(
  docker compose
  --project-name jengasec-observability-rehearsal
  --profile rehearsal
  --env-file "$REHEARSAL_ROOT/etc/observability.env"
  --file "$current/observability/compose.production.yaml"
)
"${compose[@]}" up --build --detach --remove-orphans --wait
"${compose[@]}" up --build --detach --remove-orphans --wait
"$current/scripts/wait-observability-stack.sh" \
  --compose-file "$current/observability/compose.production.yaml" \
  --env-file "$REHEARSAL_ROOT/etc/observability.env" \
  --project-name jengasec-observability-rehearsal
curl --fail --silent --output /dev/null http://127.0.0.1:3000/api/health
[[ "$(curl --silent --output /dev/null --write-out '%{http_code}' \
  http://127.0.0.1:9090/)" == "404" ]] \
  || die "Prometheus write proxy exposed an unexpected path"
"${compose[@]}" down --remove-orphans
"${compose[@]}" down --remove-orphans
log "OBS VM deployment and production-stack rehearsal passed twice"
