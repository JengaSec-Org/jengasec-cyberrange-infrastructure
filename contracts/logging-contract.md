# Contract: application telemetry

Owner: AI Track with Observability. Application Briefs owns the per-application
event list; Scoring confirms which events it relies on.

Each application writes one JSON object per line to standard output. The JSON
must validate against `logging-contract.schema.json`, and its `event` must be a
common or application-specific entry in `telemetry-event-catalogue.yaml`.

## Identity fields

| Field | Value |
|---|---|
| `schema_version` | `2.0` |
| `enterprise` | `ENT-A` or `ENT-B` |
| `application` | `APP01` through `APP09` |
| `namespace` | `jengasec-<enterprise>-<application>`, lower-case |

The platform injects these values into the workload. Applications must not
derive or override them from a request.

## Request events

Use `request_completed` for one summary event per handled request. Supply the
HTTP method, path without query string, status, source IP, opaque request ID,
and an opaque application `user_id` when known. Use a brief event as a second
event only when it records a meaningful security or business action.

```json
{
  "schema_version": "2.0",
  "ts": "2026-10-10T09:15:02.113Z",
  "level": "info",
  "enterprise": "ENT-A",
  "application": "APP01",
  "namespace": "jengasec-ent-a-app01",
  "event": "request_completed",
  "outcome": "denied",
  "request_id": "req-7f2a",
  "source_ip": "10.60.2.14",
  "method": "POST",
  "path": "/api/v1/transfers",
  "status": 403,
  "action": "create_transfer",
  "user_id": "acct-1842",
  "detail": {
    "route": "transfers.create"
  }
}
```

## Data that is never accepted

Do not log credentials, authentication headers, cookies, tokens, private keys,
full card or identity-document numbers, request or response bodies, names,
email addresses, or phone numbers. The catalogue's `never_log_keys` list is
enforced case-insensitively at every object depth. A rejected event is recorded
only as a reason, rejected key names, source metadata and payload hash; its
values are not retained.

`detail` is flat and may contain only keys listed for the selected catalogue
entry. Paths, opaque identifiers and other high-cardinality values stay in the
event body and are never Loki labels.

## Compatibility

This is a breaking replacement for the unimplemented Zawadi/Afya draft. Once
application build checkpoint C2 begins, new versions may only add optional
fields or mappings unless all contract owners approve a breaking change.
