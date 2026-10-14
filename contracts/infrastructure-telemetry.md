# Contract: global infrastructure telemetry

Owner: Observability, with the host, gateway and Kubernetes owners.

`infrastructure-source.schema.json` defines source records.
`infrastructure-event.schema.json` defines stored records. Both use
`schema_version: infrastructure/1.0`. This contract adds a separate global
infrastructure path. It does not change application telemetry version 2.0.
Source owners review their mappings before a live rollout.

Every record uses `record_family: infrastructure_telemetry`. Platform audit and
competition records keep their own contracts and stores. Infrastructure
records do not carry an invented enterprise, application or namespace.
An observed Kubernetes namespace belongs in `resource.namespace`.

Sources supply an approved `resource_id`, event time `ts`, an opaque
`source_event_id`, severity, outcome, resource details and event-specific
attributes. Times use UTC and end in `Z`. The source ID is the SHA-256 of a
stable journal cursor, Kubernetes event UID and resource version, or decoded
sensor record identity. It is not a Loki label.

The normalizer checks the source schema and the resource inventory. It adds
`received_ts`, collection provenance and a stable `event_id`:
`infra_` followed by SHA-256 of `resource_id`, a newline and `source_event_id`.
`integrity_hash` is `sha256:` followed by SHA-256 of the stored object before
that field is added. The encoding is UTF-8 JSON with keys sorted recursively,
no extra whitespace and no ASCII escaping. A delivery retry can produce the
same event ID with a later receipt time or newer optional attribution. Exports
verify each record before deduplicating retries and retain the earliest
verified receipt, including its original attribution.

The staff Loki tenant stores these records. The allowed labels are
`record_family`, `environment`, `source`, `resource_id`, `event_type` and
`severity`. Resource IDs come from a deployment allowlist. Resource names,
service names, addresses, ports and event IDs stay in the JSON body.
Application organizations never receive this stream.

The optional normalized `attribution` object is an observation-only lookup
from the private native provisioning cache. It always states
`identity_source=jengasec_provisioning`, `mapping_state=native_only` and
`authorization=none`. A `known` result carries `source` or `destination`
participant, optional team and role fields, plus the original snapshot hash,
capture time and expiry. IDs remain native decimal strings in the body.
The normalizer does not accept attribution from event producers.

The current native snapshot must be fresh and the event must fall within its
capture window. A failed pull clears the lookup before it fetches. Unknown,
stale, expired and out-of-window records carry no identity; validation and
rehearsal records remain un-attributed. A current lookup cannot reconstruct
earlier assignments and never supplies access or scoring authority.

| Event | Meaning |
|---|---|
| `host.service_state` | An allowlisted service started, stopped, reloaded or failed |
| `host.auth_success`, `host.auth_failure` | A local authentication result without an account name or command |
| `host.boot` | A recent kernel boot observed by the collector |
| `kubernetes.event` | A Kubernetes reason, type, count and resource reference; no event message |
| `network.flow` | An observed flow with counts; no firewall verdict is inferred |
| `firewall.decision` | A verdict from an actual rate-limited gateway rule log |
| `ids.alert` | A passive sensor rule match with its signature ID and action |
| `collector.health`, `collector.loss` | Queue state, delivery health or an explicit collection gap |

`environment` is `live`, `validation` or `rehearsal`. The local IDS canary
signature uses `validation`; it is not an attack finding. Zero VPN peers or
flows is a valid empty state. A current collector heartbeat proves collection
is running; silence alone does not.

Host and gateway agents sanitize before writing their durable queue. They
exclude account names, email addresses, raw messages, commands, request
bodies, keys and packet payloads. Invalid central input goes to the existing
hash-only quarantine. The HTTPS receiver requires verified client TLS.
Kubernetes sends the same source body through the approved TLS OTLP receiver.

The host queue retains at most 50,000 records and 64 MiB of encoded payload,
plus database and WAL overhead. Queue overflow removes the oldest record and
increments a persistent loss counter. Journal cursors commit atomically with
events. A failed delivery preserves the queue; an acknowledgement removes the
batch. Central infrastructure delivery uses a persistent 512 MiB queue and
backpressure. Loki retains the existing seven-day window.

The event agent publishes queue, loss, rejection, collection and delivery
metrics through the existing node exporter's textfile collector. Missing or
stale collection and failed delivery are separate from a quiet sensor.
