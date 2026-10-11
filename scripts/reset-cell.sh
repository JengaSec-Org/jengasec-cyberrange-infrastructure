#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# what:   Put one cell back to its freeze snapshot (attack-day recovery)
# owner:  APP
# usage:  ./reset-cell.sh [--dry-run] jengasec-ent-a-app07
# reads:  snapshots/<namespace>/ (release revision + database dump)
# changes: rolls back the Helm release and restores the database
# safe to run again: yes
# runbook: runbooks/reset-cell.md
# ---------------------------------------------------------------------------
. "$(dirname "$0")/_lib.sh"
need helm; need kubectl

namespace=""
for arg in "$@"; do
  [ "$arg" = "--dry-run" ] || namespace="$arg"
done
[ -n "$namespace" ] || die "usage: reset-cell.sh [--dry-run] <namespace>"
snap_dir="$(dirname "$0")/../snapshots/$namespace"
[ -d "$snap_dir" ] || die "no snapshot for $namespace"

rev=$(cat "$snap_dir/revision")
log "rolling $namespace back to revision $rev"
run helm rollback "$namespace" "$rev" --namespace "$namespace" --wait

log "restoring database"
run kubectl exec -n "$namespace" statefulset/db -- bash -lc "psql -U appuser -d appdb -c 'DROP SCHEMA public CASCADE; CREATE SCHEMA public;'"
if [ "$DRY_RUN" != true ]; then
  kubectl exec -i -n "$namespace" statefulset/db -- psql -U appuser -d appdb < "$snap_dir/db.sql"
fi
log "$namespace reset"
