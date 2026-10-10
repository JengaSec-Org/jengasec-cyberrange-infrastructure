# Contract: platform data consumed by Observability

Owners: Competition Platform for the source data; Observability for the
read-only consumer.

The platform database is authoritative. OBS connects with a TLS-protected
PostgreSQL role that has `SELECT` on the versioned views below and no table
write privilege. The role and connection string are secrets and never appear
in Git.

Every view includes `contract_version = 1` and `updated_at`. Timestamps are UTC.
Rows contain opaque identifiers only; participant names, team names, email
addresses, phone numbers and identity data are excluded.

## Attribution views

`obs_ip_allocations_v1` represents the `ip_allocations` table:

| Column | Meaning |
|---|---|
| `allocation_id` | Stable opaque allocation identifier |
| `ip_address` | One participant, application or spare address |
| `kind` | `participant`, `application` or `spare` |
| `participant_id` | `JS26-P-NNNN`, nullable for non-participant rows |
| `team_id` | Stable team identifier, nullable for application/spare rows |
| `team_label` | `red-app`, `blue-app`, `red-ai`, `blue-ai`, `staff` or `judge` |
| `namespace` | Associated application namespace when applicable |
| `status` | `reserved`, `active` or `revoked` |
| `valid_from`, `valid_until` | Attribution validity window; end may be null |

`obs_applications_v1` represents the `applications` table:

| Column | Meaning |
|---|---|
| `application_instance_id` | `<enterprise>/<application>`, for example `ENT-A/APP01` |
| `enterprise` | `ENT-A` or `ENT-B` |
| `application` | `APP01` through `APP09` |
| `namespace` | Canonical Kubernetes namespace |
| `service_name` | Name from the shared application catalogue |
| `ip_address` | Reserved VLAN 108 address |
| `status` | `building`, `frozen`, `live` or `down` |
| `optional`, `enabled` | Optional-app declaration and current activation |
| `image_digest` | Frozen image digest, nullable until freeze |

`obs_scope_assignments_v1` represents `scope_assignments` and supplies
`team_id`, `source_cidr`, target enterprise/application/namespace/IP,
`active`, `valid_from` and `valid_until`.

OBS refreshes these three views at least once per minute and writes its local
lookup files atomically. It alerts after two missed refresh intervals. The
last valid snapshot remains active during a transient database failure.

## Access and evidence views

`obs_access_principals_v1` supplies only `participant_id`, `role`, `team_id`,
and the enterprise/application/namespace each identity may read. It is used to
provision individual dashboard identities; shared accounts are forbidden.

`obs_findings_v1` supplies a finding ID, target enterprise/application,
start/end timestamps and explicitly cited telemetry event IDs. It excludes
finding prose, attachments and participant identity data. Evidence generation
uses this view but never writes back through the OBS database role.

## Consumer behavior

- An active participant allocation resolves source IP to participant, team and
  label in the event body, never in Loki labels.
- An application row resolves destination IP to enterprise, application and
  namespace.
- A matching active scope row yields `allowed`; a known participant/application
  pair without a matching scope row yields `refused` when the gateway reports a
  policy refusal.
- Missing or stale attribution is explicit (`unknown`) and raises a pipeline
  health signal. OBS never guesses an identity.
