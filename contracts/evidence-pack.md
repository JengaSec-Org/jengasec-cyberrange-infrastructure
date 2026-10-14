# Contract: observability evidence pack

Owners: Observability for export; Scoring for finding interpretation.

An export is generated for one `obs_findings_v1` JSON row from its target,
time window, cited event IDs and correlation IDs. The input validates against
`observability-finding.schema.json`; the manifest validates against
`evidence-pack.schema.json`. It contains only data required to validate that
finding.

```text
<finding-id>/
├── manifest.json
├── telemetry.ndjson
├── platform-audit.ndjson
├── competition-events.ndjson
└── SHA256SUMS
```

The three event files preserve the boundaries in `event-boundaries.md`. Empty
families remain present and are declared empty in the manifest. A non-empty
platform-audit or competition file names its owning contract version in the
manifest. Every telemetry row validates against the normalized telemetry
schema and includes its stable event ID, timestamps, attribution and integrity
hash.

The manifest records the finding ID, target, UTC query window, contract
versions, export timestamp, row counts and SHA-256 of each event file.
`SHA256SUMS` covers the manifest and event files. Rows are sorted by timestamp
then event ID. Repeating an export with unchanged source data retains the
original export timestamp and leaves the pack unchanged.

The export removes secrets, request and response bodies, raw payloads, names,
emails, phone numbers and unnecessary personal data. It is written with
owner-only permissions, retained through the appeal window, and accessible
only to named judge and staff identities. The exporter rejects telemetry with
forbidden keys or email-like values and removes those fields from external
record families before writing them.

## Global infrastructure exports

`scripts/export-infrastructure-evidence.py` selects staff infrastructure records
by resource IDs, a UTC time window, environment and optional exact event IDs.
It verifies each record against `infrastructure-event.schema.json`, checks its
content hash and stable ID, and rejects conflicting source content. Repeated
delivery of the same source record is deduplicated after hash verification.

The manifest uses `infrastructure-evidence/1.0` and validates against
`infrastructure-evidence.schema.json`. Infrastructure records are written to
`infrastructure-telemetry.ndjson`; the platform audit and competition files
remain separate and empty. This export does not create a finding. An empty
resource window is valid; a requested missing event ID fails the export.

The exporter queries the staff tenant only. It keeps files owner-readable,
uses atomic directory publication and preserves an identical existing pack.
`SHA256SUMS` covers each evidence file and the manifest. The maximum query
window is seven days and the maximum response is 100,000 records. Narrow the
resource scope or time window if the limit is reached.
