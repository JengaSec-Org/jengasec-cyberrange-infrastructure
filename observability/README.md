# Observability

Docker Compose runs the development telemetry path with Vector, GoFlow2,
OpenTelemetry Collector, Loki, Prometheus and Grafana.

```text
application stdout -------------------------------> Vector -> Loki
gateway syslog -----------------------------------> Vector -> Loki
NetFlow/IPFIX -> GoFlow2 --------------------------> Vector -> Loki
application stdout + Kubernetes events -> OTLP ---> Vector -> Loki
application + Kubernetes metrics -> remote write ----------> Prometheus
Loki + Prometheus ------------------------------------------> Grafana
rejected events -> sanitised Vector quarantine
```

The emitters are executable fixtures, not application services. The network
fixture sends real syslog and NetFlow v5. GoFlow2 is the protocol decoder. The
cluster fixture uses OTLP/gRPC and Prometheus remote write, matching the k3s
interfaces.

## Collection

A renderer builds the Vector event lookup, application lookup and
sensitive-key policy from the shared catalogue and `scripts/cells.yaml`.
Vector rejects unknown events, uncatalogued detail fields and sensitive keys.
The development stack also renders a synthetic snapshot of the attribution
and access views in `contracts/observability-data-interface.md`.

| Telemetry field | Source |
|---|---|
| `event_id` | SHA-256 of the accepted producer event |
| `integrity_hash` | SHA-256 of the normalised record |
| Enterprise, application, namespace and target IP | Canonical application lookup |
| `raw_event` | Producer catalogue key |
| Event type, severity and ATT&CK mapping | Event catalogue |
| Actor, target, HTTP, network and IDS fields | Accepted source record |
| `metadata` | Bounded normalized fields only |

Loki indexes bounded deployment and event fields. IDs and attribution remain
in the JSON body. The quarantine stores the time, source, rejection reason and
payload hash. It never stores rejected payloads or sensitive values.

Accepted events go to a staff Loki tenant and an application tenant. Grafana
uses one organisation per application. Loki tenancy and the Prometheus label
proxy enforce each namespace boundary; attribution never becomes a label.

`scripts/sync-observability-lookups.sh` is the live snapshot consumer. It uses
a TLS PostgreSQL service, reads only the versioned OBS views, validates their
identifiers and relationships, and replaces lookup files atomically. Invalid
or unavailable source data leaves the last valid snapshot unchanged.

Prometheus alerts on contract rejection, unknown attribution and unavailable
pipeline targets. Loki and Prometheus share configurable retention.

## k3s inputs

`charts/observability-agent` supplies the production-side collectors. A
DaemonSet reads application container stdout. One cluster collector watches
Kubernetes events and health, scrapes annotated application metrics and sends
them to the OBS interfaces in `contracts/address-plan.md`.

The OTLP endpoint uses certificate verification unless an isolated rehearsal
explicitly sets `obs.tls.insecure=true`. The live certificate must be trusted
by the collector image.

The development syslog fixture defines only the tested OBS adapter shape. The
gateway owner must confirm the live firewall and IDS formats before deployment.
No AI ingestion endpoint is defined here; the AI-owned interface remains an
external dependency.

See `runbooks/observability.md` for operation and recovery.
