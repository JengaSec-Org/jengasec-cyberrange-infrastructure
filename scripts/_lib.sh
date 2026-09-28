#!/usr/bin/env bash
# Shared helpers. Source this at the top of every bash script:  . "$(dirname "$0")/_lib.sh"
set -euo pipefail

DRY_RUN="${DRY_RUN:-false}"
for arg in "$@"; do [ "$arg" = "--dry-run" ] && DRY_RUN=true; done

log()  { printf '%s  %s\n' "$(date -u +%H:%M:%S)" "$*"; }
warn() { printf '%s  WARN %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
die()  { printf '%s  ERROR %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; exit 1; }

# run <command…> — respects --dry-run
run() {
  if [ "$DRY_RUN" = true ]; then log "would run: $*"; else log "running: $*"; "$@"; fi
}

need() { command -v "$1" >/dev/null 2>&1 || die "missing command: $1"; }
