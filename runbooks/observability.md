# Runbook: observability stack

Owner: Observability

Run commands from the repository root. Docker Compose must be available. Keep
service ports private. Grafana anonymous access is only for isolated
validation.

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
Loki 3100, the application fixture 8080, the source fixture 8081, Vector
metrics 9598, OTLP 4317, syslog 1514 TCP/UDP and NetFlow 2055 UDP. The syslog
host port maps to the contracted container port 514. Override a binding with
its `JENGASEC_*_BIND` or `JENGASEC_*_PORT` variable.

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

If a port is in use, set another host port for startup and checks:

```bash
JENGASEC_GRAFANA_PORT=3300 make obs-up
JENGASEC_GRAFANA_PORT=3300 make obs-smoke
```

## Stop

```bash
make obs-down
```

This removes the containers and network. It keeps the named data volumes.

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
