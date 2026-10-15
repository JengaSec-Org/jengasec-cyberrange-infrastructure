#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# what:   Pack exactly what the AI API VM needs into one tarball (works with uncommitted changes)
# owner:  AIC
# usage:  ./ai-api/deploy/make-bundle.sh [out-dir]       default: out/
# reads:  ai-api/, contracts/, scenarios/, scripts/cells.yaml, scripts/ai-teams.yaml, the VM runbooks, docs/platform-vm.md
# changes:writes <out-dir>/jengasec-ai-api.tar.gz only (out/ is gitignored)
# safe to run again: yes (overwrites the tarball)
# runbook: runbooks/ai-api-vm.md
# ---------------------------------------------------------------------------
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${1:-$ROOT/out}"
PATHS=(ai-api contracts scenarios scripts/cells.yaml scripts/ai-teams.yaml runbooks/ai-api-vm.md runbooks/platform-vm-install.md docs/platform-vm.md)
mkdir -p "$OUT"
cd "$ROOT"

# A Windows checkout can turn LF into CRLF. JSON, YAML and Markdown do not care, but a CRLF shell or Python
# script fails on the VM ("bad interpreter"): refuse to package one. -U stops Git Bash's grep hiding CRs.
CR="$(printf '\r')"
crlf="$(grep -rlIU --include='*.sh' --include='*.py' --exclude-dir=__pycache__ --exclude-dir=.venv \
  --exclude-dir=venv -e "$CR" "${PATHS[@]}" 2>/dev/null || true)"
if [ -n "$crlf" ]; then
  echo "refusing: these scripts have CRLF line endings (fix each with: sed -i 's/\\r\$//' FILE):" >&2
  echo "$crlf" >&2
  exit 1
fi

tar -czf "$OUT/jengasec-ai-api.tar.gz" \
  --exclude='__pycache__' --exclude='*.pyc' --exclude='*.db' --exclude='.venv' --exclude='venv' \
  --exclude='ai-api/tokens.yaml' --exclude='.pytest_cache' --exclude='answer-key.yaml' \
  "${PATHS[@]}"
echo "wrote $OUT/jengasec-ai-api.tar.gz ($(du -h "$OUT/jengasec-ai-api.tar.gz" | cut -f1))"
