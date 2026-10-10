#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# what:   Create or update every team environment from cells.yaml
# owner:  APP
# usage:  ./provision-cells.sh [--dry-run] [namespace…]
# reads:  scripts/cells.yaml, charts/cell
# changes: namespaces, quotas, policies, databases, ingress in the cluster
# safe to run again: yes (helm upgrade --install)
# runbook: runbooks/provision-cells.md
# ---------------------------------------------------------------------------
. "$(dirname "$0")/_lib.sh"
need helm; need yq

CELLS_FILE="${CELLS_FILE:-$(dirname "$0")/cells.yaml}"
CHART="$(dirname "$0")/../charts/cell"

requested=()
for arg in "$@"; do
  [ "$arg" = "--dry-run" ] || requested+=("$arg")
done

if [ "${#requested[@]}" -gt 0 ]; then
  namespaces=$(printf '%s\n' "${requested[@]}")
else
  namespaces=$(yq -r '.cells[] | select(.enabled == true) | .namespace' "$CELLS_FILE")
fi

for namespace in $namespaces; do
  row=".cells[] | select(.namespace==\"$namespace\")"
  enterprise=$(yq -r "$row | .enterprise" "$CELLS_FILE")
  application=$(yq -r "$row | .application" "$CELLS_FILE")
  reserved_ip=$(yq -r "$row | .reserved_ip" "$CELLS_FILE")
  [ "$enterprise" != "null" ] || die "unknown namespace: $namespace"

  log "application $enterprise/$application ($namespace, $reserved_ip)"
  run helm upgrade --install "$namespace" "$CHART" \
      --namespace "$namespace" --create-namespace \
      --set-string namespace="$namespace" \
      --set-string enterprise="$enterprise" \
      --set-string application="$application" \
      --set-string reservedIP="$reserved_ip" \
      --values "$(dirname "$0")/../charts/cell/values.yaml"
done
log "all enabled application instances done"
