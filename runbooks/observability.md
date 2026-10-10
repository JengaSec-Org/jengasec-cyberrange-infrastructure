# Runbook: observability stack

Owner: Observability

Run commands from the repository root. Docker Compose must be available. Keep
service ports private. Grafana anonymous access is only for isolated
validation.

## Start

```bash
make obs-validate
make obs-up
make obs-smoke
```

The stack binds to loopback by default. Grafana uses port 3000, Prometheus 9090,
Loki 3100, the test emitter 8080, and Vector metrics 9598. Override a binding
with its `JENGASEC_*_BIND` or `JENGASEC_*_PORT` variable.

## Inspect and recover

```bash
docker compose -f observability/compose.yaml ps
docker compose -f observability/compose.yaml logs --tail=100 vector loki
```

After a configuration change, run `make obs-validate`, then `make obs-up`.
Both commands are safe to repeat.

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
