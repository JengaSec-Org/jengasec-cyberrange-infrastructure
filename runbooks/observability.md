# Runbook: observability stack

Owner: Observability

Run commands from the repository root. Docker Compose must be available. Keep
service ports private. Grafana anonymous access is disabled.

## Codespaces

Use a Linux Codespace with at least 4 CPUs and 8 GB of memory. Confirm Docker
and Docker Compose are available, then use the same start and stop commands
below. Keep forwarded service ports private.

## Start

```bash
make obs-validate
make obs-up
make obs-smoke
```

The stack binds to loopback by default. Grafana uses port 3000, Prometheus 9090,
the scoped metrics proxy 9091, Loki 3100, the application fixture 8080, the
source fixture 8081, the website feed mock 8082, Vector
metrics 9598, OTLP 4317, syslog 1514 TCP/UDP and NetFlow 2055 UDP. The syslog
host port maps to the contracted container port 514. Override a binding with
its `JENGASEC_*_BIND` or `JENGASEC_*_PORT` variable.

Startup creates random development-only Grafana credentials under the ignored
`observability/.runtime/` directory. Development retention is 168 hours. For a
production rehearsal, set `JENGASEC_RETENTION_HOURS`,
`JENGASEC_EVENT_WINDOW_HOURS` and `JENGASEC_APPEAL_WINDOW_HOURS`; startup
rejects retention shorter than the event plus appeal windows.

## Inspect and recover

```bash
docker compose -f observability/compose.yaml ps
docker compose -f observability/compose.yaml logs --tail=100 vector loki
```

After a configuration change, run `make obs-validate`, then `make obs-up`.
Both commands are safe to repeat.

`make obs-smoke` sends application, ingress, firewall, IDS, NetFlow, host and
Kubernetes events. It checks the stored records against the telemetry schema.
It also proves application and Kubernetes metrics reached Prometheus through
scrape and remote-write paths.
It proves APP01 tenant isolation, read-only Blue access, staff/judge access and
the contract and attribution-health alerts.

The source fixture uses participant `JS26-P-0001` from team `JS26-R-001`.
APP01 traffic resolves as allowed. The same sender's APP02 request resolves as
refused. Participant and team IDs remain in event bodies, not Loki labels.

If a port is in use, set another host port for startup and checks:

```bash
JENGASEC_GRAFANA_PORT=3300 make obs-up
JENGASEC_GRAFANA_PORT=3300 make obs-smoke
```

## Stop

```bash
make obs-down
```

This removes the containers and network. It keeps the named data volumes and
untracked development credentials.

## Rehearse the k3s agents

Render the chart before any cluster change:

```bash
helm lint charts/observability-agent \
  --set-string obs.otlpEndpoint=collector.example.invalid:4317 \
  --set-string obs.prometheusRemoteWriteUrl=http://collector.example.invalid:9090/api/v1/write \
  --set obs.tls.insecure=true
```

For a reviewed environment, set the real inventory endpoints and keep TLS
verification enabled. Install with `helm upgrade --install`, then check both
workloads:

```bash
kubectl -n jengasec-observability rollout status daemonset/observability-log-agent
kubectl -n jengasec-observability rollout status deployment/observability-cluster-collector
```

Do not apply the chart to Server 3 without separate live-operation approval.
Before a live gateway connection, confirm the firewall and IDS formats and map
them to the event catalogue. The development JSON syslog fixture is not a
gateway-owned contract.

Rollback uses the previous Helm revision:

```bash
helm history observability-agent -n jengasec-observability
helm rollback observability-agent REVISION -n jengasec-observability --wait
```

## Refresh attribution

Store a PostgreSQL service named `obs_attribution` outside the repository. It
must use the read-only platform role and TLS. Keep the service file unreadable
to other users. Refresh the lookup directory with:

```bash
./scripts/sync-observability-lookups.sh \
  --service-file /run/secrets/obs-postgresql-service \
  --output-dir /var/lib/jengasec-observability/lookups
```

Configure the deployment timer to run this once per minute and reload Vector
only after a successful refresh. A failure keeps the last valid snapshot.
Alert when `attribution-snapshot.json` has not been refreshed for two minutes.

The refresh also writes `access-principals.csv`. Preview access changes with
`scripts/provision-grafana-access.py --dry-run` before applying them. Live
identities must already exist in Grafana; only the development fixture creates
synthetic users. Managed users are Viewers, stale memberships are removed, and
staff/judge accounts receive the all-application view.

Prometheus exposes the OBS alert rules at `/api/v1/rules`. Alert notification
routing remains a deployment setting; this repository stores no receiver
credentials.

## Export finding evidence

Obtain one JSON row from `obs_findings_v1` through the read-only platform
interface. Keep the snapshot outside the repository and validate the planned
export before writing it:

```bash
./scripts/export-observability-evidence.py \
  --finding /run/jengasec-observability/finding.json \
  --loki-url http://127.0.0.1:3100 \
  --output-root /var/lib/jengasec-observability/evidence \
  --dry-run
```

Remove `--dry-run` to create the pack. The exporter fails if any cited event or
correlation ID is missing, preserves empty platform-audit and competition
files, and leaves an identical existing pack unchanged. Supply those two
families as prefiltered NDJSON only when needed, together with their owning
contract versions.

Verify a completed pack before release to a named judge or staff identity:

```bash
cd /var/lib/jengasec-observability/evidence/FINDING_ID
sha256sum --check SHA256SUMS
```

Keep the source finding snapshot and pack through the appeal window. Do not
copy packs into the repository or expose the evidence directory through
Grafana.

## Outbound integrations

The development stack posts sanitized events to its mock `/api/feed` receiver.
Set `JENGASEC_WEBSITE_FEED_URL` only after the website owner provides the live
HTTPS receiver and authentication method. `make obs-smoke` proves a live event
arrived without sensitive or attribution fields.

Vector also writes normalized events to the `vector-ai-handoff` volume. A live
deployment mounts that volume at `/var/lib/vector/ai-handoff/` with OBS-only
write access. Do not add a network destination or credentials until the AI
owner publishes that interface.
