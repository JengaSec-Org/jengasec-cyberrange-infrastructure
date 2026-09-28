# scripts

Every area writes its own scripts here. Copy `_template.sh`, keep the header, and add a runbook entry.

| Script | Owner | Does |
|---|---|---|
| `provision-cells.sh` | Application Platform | Creates or updates all 14 team environments from `cells.yaml` |
| `create-accounts.py` | Application Platform | Creates Gitea users, organisations and repositories from the allocation export |
| `make-wg-configs.py` | Network & Access | One WireGuard key and config per person, plus the gateway peer file |
| `make-allowlists.py` | Security & Identity | Turns `contracts/scope-assignments.csv` into per-cell allow lists |
| `snapshot-cell.sh` / `reset-cell.sh` | Application Platform | Freeze snapshot, and rollback on attack day |
| `freeze.sh` / `unfreeze.sh` | Application Platform | Pause and resume every team pipeline |
