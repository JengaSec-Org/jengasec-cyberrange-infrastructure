# Native provisioning observations

Owners: Platform owns the source tables and their meaning. Observability owns
this read-only consumer and snapshot format. Review this interface with both
owners before another component consumes it. It does not replace
`contracts/observability-data-interface.md` or its competition identity views.

The adapter reads `participants`, `teams`, `vpn_allocations`, `targets`,
`target_assignments` and `event_config` in one PostgreSQL `REPEATABLE READ READ
ONLY` transaction. It does not query a website signup registry. It omits names,
email, external identity, peer keys, team codes, event names and audit details.
An empty database is a successful empty snapshot.

## Run

Run on the database host with the existing local PostgreSQL identity:

```sh
sudo python3 scripts/refresh-provisioning-observability.py \
  --local-peer --database jengasec \
  --output-dir /var/lib/jengasec-observability/provisioning
```

Local mode uses the existing `postgres` OS identity, a Unix socket and the
built-in `pg_read_all_data` role inside the read-only transaction. It creates
no database object, account or grant. SQL selects only the allowlisted columns.
Run it at least once per minute. Python 3 and `psql` are required.

A remote consumer may use `--service-file PATH` instead of `--local-peer`.
The private libpq file must contain the `obs_provisioning` service, use
`sslmode=verify-full`, and reference a source-owner-provided read-only role.
The adapter also checks that its actual connection uses TLS. Credentials and
environment addresses stay outside the repository.

## Snapshot and freshness

The output directory must have mode `0700`. Files have mode `0600`:

| File | Meaning |
|---|---|
| `provisioning-snapshot.json` | Validated observations described by `snapshot.schema.json` |
| `provisioning-status.json` | Publication state, content hash, last success and expiry described by `status.schema.json` |
| `refresh.lock` | Prevents overlapping writers |

Native bigint IDs are decimal strings. `identity_source=jengasec_provisioning`,
`mapping_state=native_only` and `authorization=none` are mandatory. No `JS26`
identifier, canonical application scope, access-principal row or firewall
verdict is generated. Team side and category remain the values reported by
their source. Unsupported roles or source states remain `unknown`.

Snapshots contain six record arrays and their counts. Allocations preserve
reported status and include `effective_state`; revoked, expired, reserved,
ineligible or unresolved allocations cannot resolve as active. Assignment
windows preserve nullable bounds. Missing bounds remain unknown, and ended
windows are expired. Disabled targets stay disabled. Target endpoints are
collected only as IP literals; other endpoint forms remain unknown. No DNS or
canonical application mapping is guessed.

The default lifetime is 120 seconds from the database capture time.
`--max-age-seconds` accepts 30 to 300 seconds. Consumers must verify the status
hash against the snapshot and require `state=fresh`, `usable=true` and an
unexpired capture window. The adapter's `read_current()` and `resolve_address()`
functions implement this check. `resolve_address()` returns current native
identity only, with its validity window and `authorization=none`. Do not apply
a current snapshot to an event before its capture time. This interface does
not reconstruct past assignments or connect event windows to individual
allocations when the source has no such relation.

A failed source refresh preserves the last valid snapshot bytes but sets
status to unusable immediately. A successful empty refresh replaces earlier
rows. Publication replaces files atomically and uses the status hash as its
commit marker. An absent or mismatched marker is unusable. A stopped timer
cannot keep old rows usable past expiry. Previous rows are evidence of a past
observation, never an access decision or an active fallback.

Inspect current freshness and counts without querying the database:

```sh
python3 scripts/refresh-provisioning-observability.py \
  --output-dir /var/lib/jengasec-observability/provisioning --inspect
```

The adapter limits each table to 10,000 rows, all tables to 20,000 rows,
snapshot input and output to 8 MiB, and target port lists to 64 entries. It
rejects malformed rows and inconsistent references. A source query has a
15-second statement timeout; the client enforces a 30-second deadline.
Errors expose only bounded reason codes, never database errors or source data.

Run `python3 observability/tests/test-provisioning-snapshot.py` for format,
empty-state, revocation, expiry, failure, recovery and read-boundary checks.
