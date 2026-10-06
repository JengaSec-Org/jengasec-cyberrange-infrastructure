# Runbook: Codespaces observability foundation

Owner: Observability

Scope: local GitHub Codespaces and Debian 12 development VMs only. These
commands do not deploy to Server 3 or to k3s.

## Preconditions

- Use a 4-core, 8 GB Codespace (the repository dev container requests this).
- Keep forwarded ports private. Grafana enables anonymous Viewer access only
  for this isolated development stack.
- Run commands from the repository root.

## Start and validate

1. Create a Codespace for the branch and wait for the dev container to finish.
2. Validate all configs, images, schemas and fixtures:

   ```bash
   make obs-validate
   ```

3. Start the stack:

   ```bash
   make obs-up
   ```

4. Prove the full data path:

   ```bash
   make obs-smoke
   ```

The smoke check emits a unique synthetic event, validates the raw log against
the logging contract, finds the normalised event in Loki, validates that event
against the telemetry contract, queries the `/emit` request metric from
Prometheus, and confirms Grafana provisioned both data sources and the
dashboard.

Open port 3000 from the Codespaces Ports tab. The home dashboard is
`JengaSec Codespaces Observability`. Prometheus is on port 9090, Loki on 3100,
the reference workload on 8080, and Vector metrics on 9598. Loki is not
auto-forwarded because it is only queried by the smoke script and Grafana.

## Inspect and recover

Show current service state and recent logs:

```bash
docker compose -f observability/compose.yaml ps
docker compose -f observability/compose.yaml logs --tail=100 vector loki
```

If a configuration changed, rerun `make obs-validate`, then `make obs-up`.
Both commands are safe to run repeatedly. The smoke check can also be repeated;
each run uses a unique marker.

If Docker reports an occupied port, override only the host port for that run,
for example:

```bash
JENGASEC_GRAFANA_PORT=3300 make obs-up
JENGASEC_GRAFANA_PORT=3300 make obs-smoke
```

## Shutdown

```bash
make obs-down
```

Shutdown removes the local containers and network but preserves the named
Loki, Prometheus and Grafana volumes. No reset or Server 3 action is part of
this milestone.

## Remaining integration dependency

Do not configure an AI sink yet. `contracts/ai-api/openapi.yaml` has no ingest
operation. The AI and Observability owners must agree on either a Loki-reading
integration or a new authenticated ingestion contract before k3s deployment.
Until that decision is accepted, Loki is the only event destination.
