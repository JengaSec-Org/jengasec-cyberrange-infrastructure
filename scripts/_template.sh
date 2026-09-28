#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# what:   <one line: what this script does>
# owner:  <role code, e.g. APP>
# usage:  ./_template.sh [--dry-run] <args>
# reads:  <files, contracts, env vars>
# changes:<what it creates or modifies — be honest>
# safe to run again: yes
# runbook: runbooks/<name>.md
# ---------------------------------------------------------------------------
. "$(dirname "$0")/_lib.sh"

need kubectl

main() {
  log "starting"
  # run kubectl get nodes
  log "done"
}

main "$@"
