#!/usr/bin/env bash
# Refresh Vector attribution lookups from the read-only platform views.
# Owner: Observability. Run: ./scripts/sync-observability-lookups.sh --service-file PATH --output-dir PATH
# Changes: atomically replaces OBS-owned lookup snapshots; safe to run again.
set -euo pipefail

# shellcheck source=scripts/_lib.sh
. "$(dirname "$0")/_lib.sh"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SERVICE_FILE=""
OUTPUT_DIR=""
TEMP_DIR=""

usage() {
  echo "usage: $0 --service-file PATH --output-dir PATH"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --service-file)
      SERVICE_FILE="${2:-}"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="${2:-}"
      shift 2
      ;;
    --help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      die "unknown argument: $1"
      ;;
  esac
done

[[ -f "$SERVICE_FILE" ]] || die "--service-file must name a readable PostgreSQL service file"
[[ -n "$OUTPUT_DIR" ]] || die "--output-dir is required"
need psql
need python3
mkdir -p -- "$OUTPUT_DIR"
TEMP_DIR="$(mktemp -d)"
cleanup() {
  if [[ -n "${TEMP_DIR:-}" && -d "$TEMP_DIR" ]]; then
    rm -r -- "$TEMP_DIR"
  fi
}
trap cleanup EXIT

export PGSERVICEFILE="$SERVICE_FILE"
export PGSERVICE=obs_attribution

service_mode="$(stat --format=%a "$SERVICE_FILE")"
[[ "${service_mode: -1}" == "0" ]] \
  || die "PostgreSQL service file must not be readable by other users"
tls_active="$(
  psql \
    --no-psqlrc \
    --tuples-only \
    --no-align \
    --set ON_ERROR_STOP=1 \
    --command 'SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()'
)"
[[ "$tls_active" == "t" ]] || die "platform database connection is not using TLS"

query_to_csv() {
  local output_file="$1"
  local query="$2"
  psql \
    --no-psqlrc \
    --csv \
    --pset footer=off \
    --set ON_ERROR_STOP=1 \
    --command "$query" \
    >"$output_file"
}

query_to_csv "$TEMP_DIR/ip-allocations.csv" '
  SELECT contract_version, updated_at, allocation_id, ip_address, kind,
         participant_id, team_id, team_label, namespace, status,
         valid_from, valid_until
  FROM obs_ip_allocations_v1
  ORDER BY ip_address, valid_from'
query_to_csv "$TEMP_DIR/applications.csv" '
  SELECT contract_version, updated_at, application_instance_id, enterprise,
         application, namespace, service_name, ip_address, status,
         optional, enabled, image_digest
  FROM obs_applications_v1
  ORDER BY enterprise, application'
query_to_csv "$TEMP_DIR/scope-assignments.csv" '
  SELECT contract_version, updated_at, team_id, source_cidr, enterprise,
         application, namespace, target_ip, active, valid_from, valid_until
  FROM obs_scope_assignments_v1
  ORDER BY team_id, enterprise, application'
query_to_csv "$TEMP_DIR/access-principals.csv" '
  SELECT contract_version, updated_at, participant_id, role, team_id,
         enterprise, application, namespace
  FROM obs_access_principals_v1
  ORDER BY participant_id, namespace, role'

python3 "$REPO_ROOT/scripts/render-observability-lookups.py" \
  --ip-allocations "$TEMP_DIR/ip-allocations.csv" \
  --applications "$TEMP_DIR/applications.csv" \
  --scope-assignments "$TEMP_DIR/scope-assignments.csv" \
  --access-principals "$TEMP_DIR/access-principals.csv" \
  --output-dir "$OUTPUT_DIR"
log "observability attribution lookup snapshot refreshed"
