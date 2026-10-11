#!/usr/bin/env bash
# Wait for every production observability container to be ready.
# Owner: Observability. Run from the OBS systemd unit after Docker Compose starts.
# Changes: none; safe to run again.
set -euo pipefail

# shellcheck source=scripts/_lib.sh
. "$(dirname "$0")/_lib.sh"

COMPOSE_FILE=""
ENV_FILE=""
TIMEOUT_SECONDS=180

usage() {
  echo "usage: $0 --compose-file PATH --env-file PATH [--timeout-seconds N]"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --compose-file)
      COMPOSE_FILE="${2:-}"
      shift 2
      ;;
    --env-file)
      ENV_FILE="${2:-}"
      shift 2
      ;;
    --timeout-seconds)
      TIMEOUT_SECONDS="${2:-}"
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

[[ -f "$COMPOSE_FILE" ]] || die "--compose-file must name a readable file"
[[ -f "$ENV_FILE" ]] || die "--env-file must name a readable file"
[[ "$TIMEOUT_SECONDS" =~ ^[1-9][0-9]*$ ]] \
  || die "--timeout-seconds must be a positive integer"
need docker

compose=(
  docker compose
  --project-name jengasec-observability
  --env-file "$ENV_FILE"
  --file "$COMPOSE_FILE"
)
services=(
  goflow2
  loki
  vector
  prometheus
  prometheus-write-proxy
  prometheus-scope-proxy
  grafana
)
deadline=$((SECONDS + TIMEOUT_SECONDS))

while (( SECONDS < deadline )); do
  pending=0
  for service in "${services[@]}"; do
    container_id="$("${compose[@]}" ps --quiet "$service")"
    if [[ -z "$container_id" ]]; then
      pending=1
      continue
    fi
    state="$(
      docker inspect \
        --format '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}' \
        "$container_id"
    )"
    case "$state" in
      running | "running healthy") ;;
      exited* | dead*) die "$service stopped before becoming ready" ;;
      *) pending=1 ;;
    esac
  done
  if (( pending == 0 )); then
    log "production observability containers are ready"
    exit 0
  fi
  sleep 2
done

die "production observability containers did not become ready in time"
