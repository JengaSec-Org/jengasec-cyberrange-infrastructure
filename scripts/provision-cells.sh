#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# what:   Create or update every team environment from cells.yaml
# owner:  APP
# usage:  ./provision-cells.sh [--dry-run] [cell…]
# reads:  scripts/cells.yaml, charts/cell
# changes: namespaces, quotas, policies, databases, ingress in the cluster
# safe to run again: yes (helm upgrade --install)
# runbook: runbooks/provision-cells.md
# ---------------------------------------------------------------------------
. "$(dirname "$0")/_lib.sh"
need helm; need yq

CELLS_FILE="${CELLS_FILE:-$(dirname "$0")/cells.yaml}"
CHART="$(dirname "$0")/../charts/cell"

cells=$(yq -r '.cells[].name' "$CELLS_FILE")
[ $# -gt 0 ] && cells=$(printf '%s\n' "$@" | grep -v -- '--dry-run' || true)

for cell in $cells; do
  enterprise=$(yq -r ".cells[] | select(.name==\"$cell\") | .enterprise" "$CELLS_FILE")
  log "cell $cell ($enterprise)"
  run helm upgrade --install "$cell" "$CHART" \
      --namespace "$cell" --create-namespace \
      --set cell="$cell" --set enterprise="$enterprise" \
      --values "$(dirname "$0")/../charts/cell/values.yaml"
done
log "all cells done"
