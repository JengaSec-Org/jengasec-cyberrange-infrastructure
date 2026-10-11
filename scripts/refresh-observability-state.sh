#!/usr/bin/env bash
# Refresh production attribution, dashboards and Grafana access from platform views.
# Owner: Observability. Run from the OBS refresh timer or by an operator.
# Changes: atomically updates OBS lookups and dashboards; reloads Vector when needed.
set -euo pipefail

# shellcheck source=scripts/_lib.sh
. "$(dirname "$0")/_lib.sh"

SERVICE_FILE=""
LOOKUP_DIR=""
DASHBOARD_DIR=""
COMPOSE_FILE=""
ENV_FILE=""
GRAFANA_ADMIN_PASSWORD_FILE=""
GRAFANA_URL=""

usage() {
  echo "usage: $0 --service-file PATH --lookup-dir PATH --dashboard-dir PATH --compose-file PATH --env-file PATH --grafana-url URL --grafana-admin-password-file PATH"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --service-file)
      SERVICE_FILE="${2:-}"
      shift 2
      ;;
    --lookup-dir)
      LOOKUP_DIR="${2:-}"
      shift 2
      ;;
    --dashboard-dir)
      DASHBOARD_DIR="${2:-}"
      shift 2
      ;;
    --compose-file)
      COMPOSE_FILE="${2:-}"
      shift 2
      ;;
    --env-file)
      ENV_FILE="${2:-}"
      shift 2
      ;;
    --grafana-admin-password-file)
      GRAFANA_ADMIN_PASSWORD_FILE="${2:-}"
      shift 2
      ;;
    --grafana-url)
      GRAFANA_URL="${2:-}"
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

for path in \
  "$SERVICE_FILE" \
  "$COMPOSE_FILE" \
  "$ENV_FILE" \
  "$GRAFANA_ADMIN_PASSWORD_FILE"; do
  [[ -f "$path" ]] || die "required file is missing: $path"
done
[[ -n "$LOOKUP_DIR" && -n "$DASHBOARD_DIR" ]] \
  || die "lookup and dashboard directories are required"
[[ "$GRAFANA_URL" =~ ^https?://[^[:space:]@]+$ ]] \
  || die "--grafana-url must be an HTTP(S) URL without credentials"
need docker
need python3

lookup_hash() {
  local file
  for file in \
    applications.csv \
    ip-allocations.csv \
    scope-assignments.csv \
    access-principals.csv; do
    if [[ -f "$LOOKUP_DIR/$file" ]]; then
      sha256sum "$LOOKUP_DIR/$file"
    else
      echo "missing  $file"
    fi
  done | sha256sum | cut -d' ' -f1
}

before="$(lookup_hash)"
"$(dirname "$0")/sync-observability-lookups.sh" \
  --service-file "$SERVICE_FILE" \
  --output-dir "$LOOKUP_DIR"
python3 "$(dirname "$0")/render-grafana-dashboards.py" \
  --applications "$LOOKUP_DIR/applications.csv" \
  --output-dir "$DASHBOARD_DIR"
after="$(lookup_hash)"

compose=(
  docker compose
  --project-name jengasec-observability
  --env-file "$ENV_FILE"
  --file "$COMPOSE_FILE"
)
if [[ "$before" != "$after" ]] \
  && [[ -n "$("${compose[@]}" ps --status running --quiet vector)" ]]; then
  "${compose[@]}" run --rm --no-deps vector \
    validate --skip-healthchecks /etc/vector/generated/vector.yaml
  "${compose[@]}" up --detach --no-deps --force-recreate vector
  log "Vector reloaded with the refreshed attribution snapshot"
fi

if [[ -n "$("${compose[@]}" ps --status running --quiet grafana)" ]]; then
  python3 "$(dirname "$0")/provision-grafana-access.py" \
    --grafana-url "$GRAFANA_URL" \
    --admin-password-file "$GRAFANA_ADMIN_PASSWORD_FILE" \
    --access-principals "$LOOKUP_DIR/access-principals.csv" \
    --applications "$LOOKUP_DIR/applications.csv" \
    --dashboards-dir "$DASHBOARD_DIR" \
    --staff-dashboard \
    "$(dirname "$0")/../observability/grafana/dashboards/jengasec-observability.json"
fi
log "production observability state refreshed"
