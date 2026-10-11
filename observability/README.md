# Observability

Docker Compose runs the JengaSec telemetry path with a test emitter, Vector,
Loki, Prometheus, and Grafana.

```text
test emitter stdout -> Vector -> normalised telemetry -> Loki
test emitter /metrics -----------------------------> Prometheus
Loki + Prometheus ---------------------------------> Grafana
rejected events -> sanitised Vector quarantine
```

The emitter is a test fixture. It is not an application service.

## Collection

Vector reads containers with the `jengasec.observability.collect=true` label.
A renderer builds the Vector event lookup and sensitive-key policy from
`contracts/telemetry-event-catalogue.yaml`. Vector rejects unknown events and
detail fields that are not in the catalogue.

| Telemetry field | Source |
|---|---|
| `event_id` | SHA-256 of the accepted producer event |
| `integrity_hash` | SHA-256 of the normalised record |
| Enterprise, application, namespace | Validated producer fields |
| `raw_event` | Producer catalogue key |
| Event type, severity, ATT&CK mapping | Event catalogue |
| Actor, target, HTTP fields | Logging contract |
| `metadata` | Allowed detail fields and producer level |

Loki indexes bounded deployment and event fields. IDs and participant
attribution remain in the JSON body.

The quarantine stores the time, source, rejection reason, and payload hash. It
does not store raw payloads or sensitive values.

The Docker socket grants broad discovery access even when mounted read-only.
Cluster deployments must use `kubernetes_logs` and namespace-scoped RBAC.

Add a downstream sink only through an approved integration contract.

See `runbooks/observability.md` for operation and recovery.
