# Contract: observability evidence pack

Owners: Observability for export; Scoring for finding interpretation.

An export is generated for one finding from its target, time window, cited
event IDs and correlation IDs. It contains only data required to validate that
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
families remain present and are declared empty in the manifest. Every telemetry
row validates against the normalized telemetry schema and includes its stable
event ID, timestamps, attribution and integrity hash.

The manifest records the finding ID, target, UTC query window, contract
versions, export timestamp, row counts and SHA-256 of each event file.
`SHA256SUMS` covers the manifest and event files. Rows are sorted by timestamp
then event ID so repeating an export over unchanged data is deterministic.

The export removes secrets, request and response bodies, raw payloads, names,
emails, phone numbers and unnecessary personal data. It is written with
owner-only permissions, retained through the appeal window, and accessible
only to named judge and staff identities.
