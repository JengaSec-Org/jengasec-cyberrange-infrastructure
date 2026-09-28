#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# what:   Put one cell back to its freeze snapshot (attack-day recovery)
# owner:  APP
# usage:  ./reset-cell.sh [--dry-run] app-07
# reads:  snapshots/<cell>/ (release revision + database dump)
# changes: rolls back the Helm release and restores the database
# safe to run again: yes
# runbook: runbooks/reset-cell.md
# ---------------------------------------------------------------------------
. "$(dirname "$0")/_lib.sh"
need helm; need kubectl

cell="${1:-}"; [ -n "$cell" ] || die "usage: reset-cell.sh <cell>"
snap_dir="$(dirname "$0")/../snapshots/$cell"
[ -d "$snap_dir" ] || die "no snapshot for $cell"

rev=$(cat "$snap_dir/revision")
log "rolling $cell back to revision $rev"
run helm rollback "$cell" "$rev" --namespace "$cell" --wait

log "restoring database"
run kubectl exec -n "$cell" statefulset/db -- bash -lc "psql -U appuser -d appdb -c 'DROP SCHEMA public CASCADE; CREATE SCHEMA public;'"
if [ "$DRY_RUN" != true ]; then
  kubectl exec -i -n "$cell" statefulset/db -- psql -U appuser -d appdb < "$snap_dir/db.sql"
fi
log "$cell reset"
