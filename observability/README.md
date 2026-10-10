# Observability development stack

Docker Compose runs the first complete JengaSec telemetry path in Codespaces
or a Debian 12 rehearsal environment.

```text
reference emitter stdout -> Vector -> normalized telemetry -> Loki
reference emitter /metrics ------------------------------> Prometheus
Loki + Prometheus ----------------------------------------> Grafana
invalid/sensitive events -> sanitized Vector quarantine
```

The emitter is a contract fixture, not an application-team service. The stack
does not connect to Server 3.

## Collection and mapping

Vector reads only containers carrying the
`jengasec.observability.collect=true` label. Before Vector starts, a one-shot
renderer reads `contracts/telemetry-event-catalogue.yaml`, builds the
application/event lookup, and inserts the catalogue's sensitive-key pattern
into the runtime configuration. Unknown events and unlisted detail fields are
rejected instead of being copied into Loki.

| Telemetry field | Source |
|---|---|
| `event_id` | SHA-256 of the accepted producer event |
| `integrity_hash` | SHA-256 of the normalized record before the hash is added |
| enterprise/application/namespace | validated producer identifiers |
| `raw_event` | producer event catalogue key |
| `event_type`, default severity, ATT&CK mapping | shared event catalogue |
| actor, target and HTTP fields | bounded logging-contract fields |
| `metadata` | catalogue-listed detail plus producer level |

Loki labels only the bounded deployment and event dimensions. Request IDs,
event IDs, actor identifiers and future participant/team attribution stay in
the JSON body.

## Rejection and quarantine

The sensitive-key stage runs before normalization. Rejected events are written
to the Vector quarantine volume as timestamp, source, reason and payload hash
only. Raw payloads and sensitive values are not retained. The smoke check
proves both a malformed event and a sensitive-field event are quarantined.

The Docker socket provides broad discovery access even when mounted read-only.
A k3s deployment must replace `docker_logs` with `kubernetes_logs` and narrow
RBAC to the competition namespaces; the mapping and rejection stages remain.

There is deliberately no AI sink. The accepted AI contract defines no
producer ingestion endpoint or authentication. Add one only through an
approved integration contract.

See `runbooks/observability-codespaces.md` for startup, validation and
shutdown.
