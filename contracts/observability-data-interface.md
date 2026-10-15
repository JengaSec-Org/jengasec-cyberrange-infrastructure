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

`obs_findings_v1` supplies exactly these columns:

| Column | Meaning |
|---|---|
| `finding_id` | Stable opaque finding identifier |
| `enterprise`, `application`, `namespace` | Canonical target identifiers |
| `start_ts`, `end_ts` | Inclusive UTC evidence window |
| `telemetry_event_ids` | Distinct array of explicitly cited stable event IDs |
| `correlation_ids` | Distinct array of opaque request or trace IDs |

The JSON export adds the common `contract_version` and `updated_at` fields and
must validate against `observability-finding.schema.json`. It excludes finding
prose, attachments and participant identity data. Evidence generation uses
this view but never writes back through the OBS database role.

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

## Versioned scoring interface

The website also exposes an authenticated HTTPS interface for scoring. The
database views above remain observation interfaces. Their last-known lookup
behavior does not authorize scores or AI actions after authority expires.

| Route | Authority and result |
|---|---|
| `GET /api/scoring/identity/` | `X-Feed-Token` or the separate read-only `X-Scoring-Identity-Token`; timed canonical teams, workloads, addresses, scopes, producer registrations and approved exclusions |
| `GET /api/scoring/receipts/` | `X-Feed-Token`; immutable producer receipts and platform-issued cases, using independent receipt and case cursors |
| `POST /api/scoring/receipts/` | A separate bearer credential for the named producer; observations only |
| `POST /api/scoring/evidence/` | `X-Feed-Token`; private, verified evidence bound to one calculation input snapshot |
| `POST /api/scoring/readiness/` | `X-Feed-Token`; operational state, with no authority to create marks |
| `POST /api/feed/` | `X-Feed-Token`; strict `scoring-feed/2.0` cumulative criterion revisions |

The website owns the complete request contracts in `docs/CONTRACT-feed.md` and
`docs/observability-interface.md`. The exact trailing slash matters. Clients
must not forward credentials through redirects. An HTTP 202 response contains
individual outcomes: only an exact accepted or duplicate revision is delivered.
Retry a pending row with its original revision. Keep a rejected row for operator
repair; do not silently discard it or invent a different team.

The read-only identity credential authorizes only identity GET requests. AI
hosts use it through a root-owned publisher that refreshes current authority
every 30 seconds. The publisher removes the local snapshot when refresh fails.
Snapshots expire within 120 seconds. Historical snapshots support score
reproduction but never authorize an action.

The `main-scoring/1.0` calculator ships from the website's
`jengasec_scoring_policy` package. OBS imports that package and sends measured
facts, collection quality and the resulting mark. The receiver independently
calculates the mark. Entry, Documentation and authorized bonus workflows remain
website-owned. Application Red uses its reviewed finding workflow and cannot
receive automatic telemetry awards.

Cases freeze their scenario, expected assertions, opportunity, defender,
target owner, actor, assignment and required producer IDs. The defender and
workload owner can differ for an explicitly assigned AI defender. External
producers cannot set labels or change scope. A competitor's own detection is
different from a central IDS observation. Every required runner, verifier and
gateway must have complete target-specific source coverage for the issued
case. Process health and a healthy unrelated producer cannot prove silence.
Independent verifier coverage must include the defender's receipt transport.

The collector uses UTC half-open cumulative windows, a 120-second delivery
grace and a 60-second calculation interval. Functional probes run every 15
seconds with bounded requests; readiness alone cannot satisfy the functional
assertion. Missing probes remain in expected coverage. The policy requires
at least 99 percent completed coverage and at most two seconds of clock
uncertainty. Missing source coverage holds a criterion. A measured failure
or a verified missed attack can produce zero. Scenario rehearsals do not earn
official marks.

Receipt sequence cursors discover late observations without rescanning time
windows. The collector consumes both cursor streams before calculating. The
platform's derived paired-build and reviewed-finding state may change; issued
labels and identity do not. Late finding corrections can remove protection
credit. Before finalization, a correction replaces one logical criterion
component and preserves earlier revisions. After finalization, the website's
appeal and judge correction workflow applies.

The collector archives original typed proof, scenario receipts, identity,
policy inputs and query definitions before it queues a score. Application
`evt_` and infrastructure `infra_` records keep their native identities. AI
proof uses a typed archive wrapper around the unchanged native receipt.
References must resolve to retained proof; a reference string alone is not
evidence. Raw application and infrastructure records continue to use their
existing exporters and access boundaries. Participants cannot retrieve staff
proof through a score link.

The delivery queue is limited to 64 MiB and 50,000 pending rows. It warns at
75 percent and holds new work at capacity, without eviction. The source cache
and website archive require explicit byte budgets. Referenced archives remain
available through the configured appeal window and every open appeal hold.
These archives do not change the seven-day raw telemetry retention policy.
