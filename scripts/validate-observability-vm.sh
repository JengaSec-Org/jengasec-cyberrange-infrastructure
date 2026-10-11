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
  if [[ -n "${REHEARSAL_ROOT:-}" && -d "$REHEARSAL_ROOT" ]]; then
    rm -r -- "$REHEARSAL_ROOT"
  fi
}
trap cleanup EXIT

need ansible-playbook
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
log "OBS VM deployment rehearsal passed twice without live changes"
