# Observability

The live stack combines host, PostgreSQL, WireGuard, Kubernetes and gateway
telemetry in Grafana. Vector normalizes events into Loki; Prometheus stores
metrics. Deployment uses the existing OBS VM and private inventory.
Docker Compose also provides an isolated development fixture path.

```text
application stdout -------------------------------> Vector -> Loki
gateway syslog -----------------------------------> Vector -> Loki
NetFlow/IPFIX -> GoFlow2 --------------------------> Vector -> Loki
application stdout + Kubernetes events -> OTLP ---> Vector -> Loki
application + Kubernetes metrics -> remote write ----------> Prometheus
Loki + Prometheus ------------------------------------------> Grafana
rejected events -> sanitised Vector quarantine
sanitised public updates -> website POST /api/feed
contract-valid events -> local AI handoff spool
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

Accepted application events go to a staff Loki tenant and an application tenant. Grafana
uses one organisation per application. Loki tenancy and the Prometheus label
proxy enforce each namespace boundary; attribution never becomes a label.

`scripts/sync-observability-lookups.sh` is the live snapshot consumer. It uses
a TLS PostgreSQL service, reads only the versioned OBS views, validates their
identifiers and relationships, and replaces lookup files atomically. Invalid
or unavailable source data leaves the last valid snapshot unchanged.

Global infrastructure events use a separate versioned contract and go only
to the staff tenant. Resource identity and deployment environment remain
explicit; global events are never assigned to an invented application.

The native provisioning adapter reads participants, teams, VPN allocations,
targets, assignments and event windows without database writes. Native IDs
stay separate from the canonical application access interface. A valid empty
snapshot remains empty; failed or expired snapshots cannot authorize access
or provide current attribution. See `provisioning/README.md`.

Live Grafana alerts cover sustained failures, freshness, recent errors and
capacity. Optional ntfy delivery sends only fixed text and alert counts, with
recovery messages. Receiver settings stay outside Git. Development retains
its Prometheus contract alerts. Loki and Prometheus retain seven days by
default.

`scripts/export-observability-evidence.py` reads one versioned finding row and
selects its cited and correlated events from the staff Loki tenant. It keeps
telemetry, platform audit and competition records in separate files, verifies
that every cited identifier resolved, and writes an owner-only pack with
SHA-256 checksums.

## k3s inputs

`charts/observability-agent` supplies one collector per cluster for Kubernetes
events, health, workload metrics and annotated application metrics. A separate
host service reads container logs with arbitrary container names. It rejects
unstructured or invalid records before persistent buffering. The cluster
namespace retains its baseline pod security policy; the chart requires no
host mounts or permission to read Secrets.

Live collectors use verified mutual TLS for OTLP and remote write. Cluster
state and sanitized log queues persist across restarts. The requested PVC
size is not a filesystem quota with the local-path provisioner; monitor host
disk capacity and queue use.

The development syslog fixture defines only the tested OBS adapter shape. The
gateway owner must confirm the live firewall and IDS formats before deployment.
No AI ingestion endpoint is defined here; the AI-owned interface remains an
external dependency.

## Outbound integrations

The website publisher sends only schema version, event ID, timestamp,
enterprise, application, event type, severity, outcome and verdict. It omits
attribution, addresses, paths, raw bodies and metadata. Development posts to a
mock; deployment must set `JENGASEC_WEBSITE_FEED_URL` after the website owner
confirms its receiver and authentication.

The AI boundary is a mode-locked NDJSON spool of normalized telemetry at
`/var/lib/vector/ai-handoff/`. It deliberately defines no AI endpoint,
transport or authentication. Those remain AI-owned integration dependencies.

Quarantine and AI handoff files use minute segments. The auxiliary spool
maintenance timer removes completed segments older than seven days or above
their configured byte caps. It preserves the two most recent minutes and
files that changed during inspection. Capacity can shorten these auxiliary
copies; Loki retains the primary seven-day records. Removal counts, retained
bytes, cap excess and maintenance freshness are node textfile metrics. Active
segments can exceed a cap until they close and the next sweep completes.

See `runbooks/observability.md` for operation and recovery.

## OBS VM

`observability/compose.production.yaml` runs the shared services without
development emitters. The infrastructure receiver accepts authenticated
remote write, OTLP logs and sanitized infrastructure events on the approved
private interface. Query APIs remain internal; Grafana binds to loopback for
the access gateway. Node exporters also require client certificates.
Docker log inputs are restricted to the selected Compose project.

Ansible stages immutable source archives and validates native configurations
before activation. Website publishing and canonical platform attribution are
optional. The rehearsal profile is for explicit validation and its records
remain separate from live data.

Seven linked staff views cover Overview, Team Activity, Infrastructure &
Services, Kubernetes, Network & Security, Event Investigation & Evidence, and
Telemetry Health. Open `/d/jengasec-overview` first. Missing collection, quiet
traffic, failed services and validation data have distinct states.
