# scripts

Every area writes its own scripts here. Copy `_template.sh`, keep the header, and add a runbook entry.

| Script | Owner | Does |
|---|---|---|
| `provision-cells.sh` | Application Platform | Creates or updates enabled ENT-A/ENT-B application instances from `cells.yaml` |
| `create-accounts.py` | Application Platform | Creates Gitea users, organisations and repositories from the allocation export |
| `make-wg-configs.py` | Network & Access | One WireGuard key and config per person, plus the gateway peer file |
| `make-allowlists.py` | Security & Identity | Turns `contracts/scope-assignments.csv` into per-cell allow lists |
| `snapshot-cell.sh` / `reset-cell.sh` | Application Platform | Freeze snapshot, and rollback on attack day |
| `freeze.sh` / `unfreeze.sh` | Application Platform | Pause and resume every team pipeline |
| `start-observability.sh` | Observability | Build and start the observability stack |
| `validate-observability.sh` | Observability | Validate configs, builds, schemas and fixtures |
| `smoke-observability.sh` | Observability | Prove every development input reaches Loki or Prometheus |
| `stop-observability.sh` | Observability | Stop the stack without deleting its data |
| `render-observability-lookups.py` | Observability | Validate platform exports and render bounded Vector lookups |
| `sync-observability-lookups.sh` | Observability | Refresh attribution lookups through the read-only TLS database interface |
| `render-grafana-dashboards.py` | Observability | Render one scoped dashboard per application |
| `prepare-observability-runtime.py` | Observability | Create untracked development-only Grafana credentials |
| `provision-grafana-access.py` | Observability | Converge read-only Grafana organisations and application access |
| `export-observability-evidence.py` | Observability | Export one finding's sanitized, integrity-checked evidence pack |
