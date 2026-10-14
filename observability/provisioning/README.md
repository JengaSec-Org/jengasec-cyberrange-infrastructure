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

## Periodic source and private cache

`ansible/observability-provisioning.yml` installs one explicitly selected host.
It requires Python 3, systemd and the existing node exporter textfile directory.
The source also requires the existing local PostgreSQL client and identity.
The role installs no package, account, database object or grant. It verifies
that authentication configuration hashes remain unchanged.

Set these values in the private inventory or an untracked variables file:

| Variable | Source | Central cache |
|---|---|---|
| `obs_provisioning_mode` | `source` | `cache` |
| `obs_provisioning_endpoint_enabled` | Enable for central transfer | Keep disabled |
| `obs_provisioning_listen_address` | Explicit private interface address | Unused |
| `obs_provisioning_allowed_client_address` | Central collector address | Unused |
| `obs_provisioning_allowed_client_certificate_sha256` | SHA-256 of the existing client certificate DER bytes | Unused |
| `obs_provisioning_source_address` | Unused | Source address covered by the server certificate |
| `obs_provisioning_tls_ca_path` | Existing client CA file | Existing server CA file |
| `obs_provisioning_tls_cert_path` and `obs_provisioning_tls_key_path` | Existing source server certificate and key | Existing central client certificate and key |

Run the playbook with `--limit` selecting exactly one host and `-e @PATH` for
its private variables. Install the source first. The default refresh interval
is 60 seconds and the default lifetime is 120 seconds. The source stores its
private files in `/var/lib/jengasec-observability/provisioning`; the central
copy uses the separate `/var/lib/jengasec-observability/provisioning-cache`.

The optional endpoint accepts only the configured client address and exact
CA-verified client certificate. It binds to the selected private interface.
The only data route is `GET /v1/provisioning/snapshot`. It returns a JSON object
with `status` and `snapshot`, using the contracts above. Unavailable, failed,
expired or concurrently replaced source data returns HTTP 503. The endpoint
reads cached files and has no database or mutation route. Requests are bounded and are not
logged with their addresses, paths or contents.

The central client verifies the server certificate and hostname, rejects
redirects and oversized responses, then checks every source field, derived
state, count, content hash and capture window. It preserves the original
source bytes and expiry. A successful poll cannot extend a source snapshot's
lifetime. Failed pulls retain the prior bytes and immediately invalidate the
cache status. Native rows remain private observations; neither this cache nor
its status can populate competition CSV files or Grafana membership.

The source timer is `jengasec-provisioning-source.timer`. The cache timer is
`jengasec-provisioning-cache.timer`. The optional endpoint runs as
`jengasec-provisioning-endpoint.service`. Each timer calls the bounded helper
and publishes a separate node textfile. Metrics use only `mode=source|cache`
and, for row counts, one of the six fixed table names:

| Metric suffix after `jengasec_provisioning_` | Meaning |
|---|---|
| `refresh_success` | Last capture or pull completed successfully |
| `snapshot_usable` | Last run validated a fresh publication |
| `last_attempt_timestamp_seconds` | Last helper run, for detecting a stopped timer |
| `last_success_timestamp_seconds` | Original source publication time |
| `snapshot_capture_timestamp_seconds` | Source capture time, or zero when unusable |
| `snapshot_expires_timestamp_seconds` | Original expiry, retained on failure |
| `refresh_duration_seconds` | Time spent in the last refresh |
| `snapshot_rows{table}` | Current usable row count, or zero when unusable |

Check `refresh_success=1` and `snapshot_usable=1` before reading row counts.
Also require `time()` to be before the expiry timestamp and the last attempt
to be recent. These timestamp checks detect a stopped timer even if its last
textfile still reports success. A fresh source with zero rows is valid and
differs from missing or stale observations. Inventory supplies host and
environment labels; snapshots contribute no identity labels.

Run `python3 observability/tests/test-provisioning-service.py` for exchange,
content validation, failed pulls, recovery and aggregate health checks.

To stop collection, disable the source and cache timers and stop the optional
endpoint. Existing snapshot bytes become unusable at their original expiry.
For rollback, stop these OBS units, restore matching saved scripts, query,
configuration and systemd units, reload systemd, and run one refresh before
re-enabling the timer. The playbook preserves previous installed files with
Ansible backups. Do not restore an old cache as fresh or alter source data to
make validation pass. Removing this adapter does not require any database,
account, TLS credential or SSH changes.
