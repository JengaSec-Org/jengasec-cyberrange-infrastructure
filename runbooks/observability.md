# Runbook: observability stack

Owner: Observability

Run commands from the repository root. Docker Compose must be available;
`make obs-validate` also requires Helm. Keep service ports private. Grafana
anonymous access is disabled.

## Start

```bash
make obs-validate
make obs-up
make obs-smoke
```

The stack binds to loopback by default. Grafana uses port 3000, Prometheus 9090,
the scoped metrics proxy 9091, Loki 3100, the application fixture 8080, the
source fixture 8081, the website feed mock 8082, Vector
metrics 9598, OTLP 4317, syslog 1514 TCP/UDP and NetFlow 2055 UDP. The syslog
host port maps to the contracted container port 514. Override a binding with
its `JENGASEC_*_BIND` or `JENGASEC_*_PORT` variable.

Startup creates random development-only Grafana credentials under the ignored
`observability/.runtime/` directory. Development retention is 168 hours. For a
production rehearsal, set `JENGASEC_RETENTION_HOURS`,
`JENGASEC_EVENT_WINDOW_HOURS` and `JENGASEC_APPEAL_WINDOW_HOURS`; startup
rejects retention shorter than the event plus appeal windows.

## Inspect and recover

Start at `/d/jengasec-overview` for host reachability, services and alerts.
The linked views preserve the time window and shared filters:

| View | Purpose |
|---|---|
| Overview | Fleet health and current alerts |
| Team Activity | Actor, team, target, event and outcome |
| Infrastructure & Services | Host capacity, services, PostgreSQL and VPN health |
| Kubernetes | Node conditions, workload availability, restarts and collector health |
| Network & Security | Observed flows, reported firewall decisions and IDS detections |
| Event Investigation & Evidence | Exact event and correlation lookup |
| Telemetry Health | Freshness, queues, delivery, rejection and loss |

Team Activity keeps `/d/jengasec-observability`. Select the time
window, target and role, then use the event timeline to inspect the actor,
event and reported outcome. Team and participant fields accept exact opaque
IDs. The request/trace and event-ID fields also use exact matches; leave them
blank to include all records. Expand a log line to follow its evidence or
correlation links. A team-table link narrows the view to that team and target.

Request counts use application request summaries. Ingress and network
records remain available in the timeline. Security events and IDS alerts
are observations for investigation. Workload events keep their source
attribution. Response approvals, execution and AI decisions require their
owners' feeds. Use Telemetry Health to check collection and delivery before
interpreting a quiet event panel. Live is the default environment; rehearsal
and validation data require an explicit filter selection.

```bash
docker compose -f observability/compose.yaml ps
docker compose -f observability/compose.yaml logs --tail=100 vector loki
```

After a configuration change, run `make obs-validate`, then `make obs-up`.
Both commands are safe to repeat.

`make obs-smoke` sends application, ingress, firewall, IDS, NetFlow, host and
Kubernetes events. It checks the stored records against the telemetry schema.
It also proves application and Kubernetes metrics reached Prometheus through
scrape and remote-write paths.
It proves APP01 tenant isolation, read-only Blue access, staff/judge access and
the contract and attribution-health alerts.

The source fixture uses participant `JS26-P-0001` from team `JS26-R-001`.
APP01 traffic resolves as allowed. The same sender's APP02 request resolves as
refused. Participant and team IDs remain in event bodies, not Loki labels.

If a port is in use, set another host port for startup and checks:

```bash
JENGASEC_GRAFANA_PORT=3300 make obs-up
JENGASEC_GRAFANA_PORT=3300 make obs-smoke
```

## Stop

```bash
make obs-down
```

This removes the containers and network. It keeps the named data volumes and
untracked development credentials.

## Rehearse the k3s agents

Render the chart before any cluster change:

```bash
helm lint charts/observability-agent \
  --set-string obs.otlpEndpoint=collector.example.invalid:4317 \
  --set-string obs.prometheusRemoteWriteUrl=http://collector.example.invalid:9090/api/v1/write \
  --set obs.tls.insecure=true
```

For a reviewed environment, use `ansible/observability-clusters.yml` with
`observability_clusters` hosts. Set cluster name, resource ID, private
endpoints and TLS file paths through the `obs_cluster_*` variables. Stage and
validate first; `obs_cluster_apply=true` applies the reviewed release.
Enable event collection and host log readers with
`obs_cluster_events_enabled=true` and `obs_cluster_host_logs_enabled=true`.
Check the deployment and host service:

```bash
kubectl -n jengasec-observability rollout status deployment/observability-cluster-collector
systemctl status jengasec-container-logs.service
```

The host reader accepts contract-compliant JSON before writing its persistent
queue. It does not need a Kubernetes API credential. The cluster deployment
has read-only resource permissions and no Secret access. Retain its PVC and
host state directory during upgrades. With local-path storage, a PVC request
does not enforce a disk quota; use host capacity and queue alerts.

Rollback uses the previous Helm revision:

```bash
helm history observability-agent -n jengasec-observability
helm rollback observability-agent REVISION -n jengasec-observability --wait
```

## Refresh attribution

Store a PostgreSQL service named `obs_attribution` outside the repository. It
must use the read-only platform role and TLS. Keep the service file unreadable
to other users. Refresh the lookup directory with:

```bash
./scripts/sync-observability-lookups.sh \
  --service-file /run/secrets/obs-postgresql-service \
  --output-dir /var/lib/jengasec-observability/lookups
```

Configure the deployment timer to run this once per minute and reload Vector
only after a successful refresh. A failure keeps the last valid snapshot.
Alert when `attribution-snapshot.json` has not been refreshed for two minutes.

The refresh also writes `access-principals.csv`. Preview access changes with
`scripts/provision-grafana-access.py --dry-run` before applying them. Live
identities must already exist in Grafana; only the development fixture creates
synthetic users. Managed users are Viewers, stale memberships are removed, and
staff/judge accounts receive the all-application view.

The OBS role manages Grafana access by default. Set
`obs_manage_grafana_access: false` to refresh canonical lookups and generated
dashboard files without running membership convergence. For a manual refresh,
pass `--manage-grafana-access false` to `refresh-observability-state.sh`; this
mode does not require Grafana credentials. It preserves existing Grafana users,
memberships, data sources and imported dashboards. Publish dashboard changes
separately through the approved importer. A retained release must support the
switch before it can be activated with access management disabled.

This canonical interface is separate from the native read-only provisioning
adapter in `observability/provisioning/README.md`. The native adapter cannot
create Grafana memberships or treat provisioning rows as website signups.

## Staff dashboards and alerts

Converge the seven views and managed Grafana alerts in the existing staff
organization. Supply the existing admin password and a unique ntfy topic
through private files:

```bash
python3 scripts/provision-infrastructure-grafana.py \
  --grafana-url https://GRAFANA_HOST \
  --admin-password-file PRIVATE_PASSWORD_FILE \
  --ntfy-topic-file PRIVATE_TOPIC_FILE
```

Use `--dry-run` for inspection. Use `--grafana-only` instead of the topic
argument when external delivery is unconfigured. The importer preserves
users, memberships, datasource credentials and unrelated notification routes.
Grafana displays these rules under Alerting. The Prometheus rules API contains
only the separate development rules.

Check firing and recovery delivery with a labelled validation signal. Public
notifications contain fixed text and counts; identities, addresses, log
bodies and private dashboard URLs remain in the staff view.

## Export finding evidence

Obtain one JSON row from `obs_findings_v1` through the read-only platform
interface. Keep the snapshot outside the repository and validate the planned
export before writing it:

```bash
./scripts/export-observability-evidence.py \
  --finding /run/jengasec-observability/finding.json \
  --loki-url http://127.0.0.1:3100 \
  --output-root /var/lib/jengasec-observability/evidence \
  --dry-run
```

Remove `--dry-run` to create the pack. The exporter fails if any cited event or
correlation ID is missing, preserves empty platform-audit and competition
files, and leaves an identical existing pack unchanged. Supply those two
families as prefiltered NDJSON only when needed, together with their owning
contract versions.

Verify a completed pack before release to a named judge or staff identity:

```bash
cd /var/lib/jengasec-observability/evidence/FINDING_ID
sha256sum --check SHA256SUMS
```

Keep the source finding snapshot and pack through the appeal window. Do not
copy packs into the repository or expose the evidence directory through
Grafana.

## OBS VM delivery

Use `ansible/observability.yml` with a private inventory containing one
`observability` host. This entrypoint excludes the common role and leaves
accounts and SSH settings alone. Docker Engine and Compose 2.24 or newer
are required. Run the isolated deployment rehearsal before a VM change:

```bash
python3 -m venv /tmp/jengasec-ansible-venv
/tmp/jengasec-ansible-venv/bin/pip install -r ansible/requirements.txt
PATH="/tmp/jengasec-ansible-venv/bin:$PATH" make obs-vm-validate
```

On a shared Docker host, select an unused loopback address with
`JENGASEC_OBS_REHEARSAL_BIND`. Keep each validation Compose project separate
from the live project. Docker source filters must select the matching project
before starting fixture publishers.

For a fresh Debian 12 amd64 host, `obs_prepare_host=true` also installs Docker
and prepares a dedicated data volume. First test the storage helper on a
disposable expanded GPT image:

```bash
sudo bash observability/tests/test-storage.sh
```

Copy `scripts/prepare-observability-storage.py` to the selected host. Run it
as root with `--device` set to the inspected disk. Without `--apply`, it only
prints a JSON plan. Save that plan in private controller storage and review
the disk size, existing partitions, new extent and mount point.

Set `obs_data_device`, `obs_storage_plan_file` (the controller path),
`obs_data_mount=/srv/jengasec-observability` and
`obs_state_root=/srv/jengasec-observability/state`. Run the OBS playbook with
`--tags obs-host` to prepare the host before staging a release. The helper
refuses a changed layout, existing filesystem signatures or an occupied
mount point. It preserves the original partitions, backs up GPT, adds only
the unused trailing extent, formats that new partition and mounts it by UUID.

The recovery record is under `/var/backups/jengasec-observability/storage`.
Repeat applies verify that record and keep the filesystem. An interrupted
partition operation needs inspection before retry. Never restore GPT while
the data volume is mounted. Docker and containerd keep their data under the
new mount, and their systemd units require it before starting.

Set a unique `obs_release_id` and the approved private interface and address
in inventory. The role verifies the existing address and never creates a VLAN.
An optional website publisher also needs its approved `/api/feed` URL.

Keep `obs_grafana_admin_password` in private secret storage or Ansible Vault.
Platform attribution also needs the read-only TLS PostgreSQL service file as
`obs_postgresql_service_content`. Keep secret values out of Git.
Set `obs_attribution_mode=disabled` when the authoritative platform views are
unconfigured. This removes rehearsal lookup identities and disables refresh;
it does not change existing Grafana memberships. An empty website URL disables
that publisher. Neither optional integration blocks infrastructure collection.

Stage and validate a release without starting services:

```bash
ansible-playbook -i PRIVATE_INVENTORY ansible/observability.yml --syntax-check
ansible-playbook -i PRIVATE_INVENTORY ansible/observability.yml \
  --extra-vars obs_release_id=RELEASE_ID
```

For a private VM rehearsal, set `obs_rehearsal_mode=true`,
`obs_function_bind=127.0.0.1`, `obs_grafana_bind=127.0.0.1` and `obs_start=true`.
The rehearsal profile enables the existing source fixture, collector and
website mock. Set `obs_rehearsal_event_interval_seconds=60` to emit a clearly
marked synthetic activity batch each minute; the default is disabled. These
records exercise the dashboards without performing application actions.

Provision approved users with `scripts/provision-grafana-access.py` and
private initial credentials.
The provisioner keeps passwords for existing users. Keep the same Grafana
admin secret across releases.

Live startup requires an approved operation. After confirming current
health, network ownership, secrets and rollback, run
the same play with `obs_start=true`, `obs_live_operation_approved=true`,
and `obs_validate_network=true`. An enabled website publisher also requires
`obs_website_feed_interface_approved=true`.

For authenticated infrastructure collection, the production ports are:

| Bind | Port | Allowed source and purpose |
|---|---:|---|
| Approved private interface | TCP 9090 | Mutual TLS remote write, OTLP and infrastructure events |
| Each monitored host | TCP 9100 | Mutual TLS node metrics |
| Loopback | TCP 3000 | Approved HTTPS access gateway to Grafana |

Legacy syslog, NetFlow and direct OTLP inputs remain on loopback unless their
separate source contract is configured. Loki, Prometheus query APIs, the
Vector API and scoped metrics proxy stay inside the Docker network.

With `obs_infrastructure_enabled=true`, port 9090 uses verified mutual
TLS on `obs_metrics_bind`. It accepts remote write, OTLP log export and
`POST /api/v1/infrastructure-events`; query APIs remain internal. Set
`obs_metrics_interface` to its approved interface. Keep unused legacy input
bindings on loopback. Supply the CA, metrics client certificate and key, and
ingress certificate and key through the `obs_metrics_tls_*_file` and
`obs_ingest_tls_*_file` controller paths. The server certificate must cover the
configured receiver address. Private keys stay outside the release archive.

For native provisioning attribution, configure the cache's
`obs_provisioning_attribution_endpoint` and set
`obs_infrastructure_attribution_certificate_sha1` to the exact cache client
certificate's DER SHA-1 fingerprint. This runtime fingerprint selects the
authenticated client; certificate trust and hostname verification remain
required. `POST /api/v1/infrastructure-attribution` rejects other clients.
Keep Vector's internal lookup receiver off host ports. An empty fingerprint
disables publication. The cache invalidates the lookup before fetching and
publishes only fresh native allocations, with no authorization or canonical
identity mapping. See `observability/provisioning/README.md`.

Configure `obs_metrics_targets` with each resource's `resource_id`, `address`
and `role`. The collector installs bounded labels from this inventory. Vector
keeps the validated source environment and resource labels so validation
events cannot become live host observations.
The receiver accepts out-of-order samples within one hour so retained
collector queues can replay after a restart. Monitor send failures and WAL
lag; an outage beyond that window needs inspection before trusting recovery.

Use `ansible/observability-nodes.yml` for hosts in `observability_nodes`. Each
host needs `obs_node_address`, private TLS file paths and a bounded
`obs_node_services` list. Enable `obs_node_postgresql` only on a database host,
or `obs_node_wireguard_interface` on a VPN host. The PostgreSQL collector uses
local read-only `pg_monitor` queries and excludes its own connection. The VPN
collector exports aggregate counts and traffic without peer keys. Zero peers
is a valid empty state. The node exporter requires a client certificate.

On a host that already uses active UFW, set `obs_node_manage_ufw: true`,
`obs_node_ufw_source_address` to the collector's private IPv4 address, and
`obs_node_ufw_interface` to the interface holding `obs_node_address`. This
adds one incoming TCP rule for that source, destination, interface and
`obs_node_port`. It does not enable UFW or change existing rules or policies.
The option defaults to false. To remove the allowance, use `ufw delete allow
in on INTERFACE proto tcp from COLLECTOR_IP to NODE_IP port NODE_PORT comment
'JengaSec observability'` with the same inventory values. Disabling the option
leaves the existing rule in place.

Use `ansible/observability-event-agents.yml` for sanitized host events. Supply
resource identity, service list, HTTPS receiver and client TLS paths in private
inventory. The collector keeps its queue and cursor under
`/var/lib/jengasec-event-agent`. Inspect `jengasec-event-agent.timer`, collector
freshness and delivery counters. Authentication messages and command text are
not stored. A delivery outage preserves queued events; queue overflow and
collection failures remain visible in metrics.

The active release is `/opt/jengasec-observability/current`. Releases are
immutable below `/opt/jengasec-observability/releases`. Configuration and
secrets are below `/etc/jengasec-observability`. Loki, Prometheus, Grafana,
Vector quarantine, the AI handoff and evidence packs are below `obs_state_root`
(`/var/lib/jengasec-observability` by default, or the dedicated volume's
`state` directory). The role does not delete an old release or data directory.

`jengasec-observability-spools.timer` checks completed quarantine and existing
AI handoff segments each minute. It applies the configured retention period
and byte caps (256 MiB and 1 GiB by default), preserving active and recently
written segments. Set `obs_spool_metrics_dir` to the node exporter's existing
textfile directory to expose cleanup freshness, retained bytes, cap excess
and removal counters. Active segments may temporarily exceed the cap; this
is reported explicitly. The timer handles only these auxiliary spools and
does not remove Loki, Prometheus or collector queue data.

For an upgrade, retain the current private deployment variables, environment
file and lookup configuration with the current release ID. Stage a new
release ID, run validation, then use the approved startup variables. Source
files transfer in one archive whose bytes match the release fingerprint.
To roll back, restore the retained configuration and matching deployment
variables, rehearse with `--check`, then set that ID with
`obs_activate_existing_release=true` and the required approval variables.
Do not pass newer integration settings to an older release renderer.
The role switches the `current` link and restarts the stack. Never reuse a
release ID for different source.

Take a cold backup during an approved maintenance window. Record the current
spool timer state, then stop `jengasec-observability-spools.timer` and any active
`jengasec-observability-spools.service` before stopping
`jengasec-observability.service`. Older releases may have no spool units.
Copy the full state directory with numeric owners to encrypted storage and
record a SHA-256 inventory. Keep all three units stopped while restoring
state so cleanup cannot change the files being copied.

Back up Vault and the PostgreSQL service secret through the secrets owner.
To recover, restore the state directory and numeric ownership, stage the
matching release, then start the stack. Restore the spool timer's prior state
only when that release supports maintenance. The deployment role disables
it for older releases. Verify native Loki and Prometheus queries and a
labelled validation event. Run the development smoke check in an isolated
rehearsal. Retain backups and evidence through the appeal window.

The website receiver and authentication remain website-owned. The shared AI
gateway uses the versioned AI API contract. A rehearsal mock or a local spool
does not establish that either integration is deployed.

## Outbound integrations

The development stack posts sanitized events to its mock `/api/feed` receiver.
Keep `JENGASEC_WEBSITE_FEED_URL` pointed at that event-consumer interface. The
website scoring endpoint accepts calculated criterion revisions, so it must
receive the separate scoring collector's `scoring-feed/2.0` envelope.

Vector also writes normalized events to the `vector-ai-handoff` volume. A live
deployment mounts that volume at `/var/lib/vector/ai-handoff/` with OBS-only
write access. The AI gateway reads this bounded spool and applies fresh
platform scope to each caller.

## Scoring collector rollout and recovery

Use the website owner's approved release and a designated competition. Apply
its migrations and run `manage.py scoring_policy preflight --competition ID`
before enrollment. Resolve baseline differences before freezing a future
window with `scoring_policy enroll`. The website requires an explicit archive
byte budget. Register verified frozen workloads, assignments, producers and
scenario versions with `manage.py scoring_sources`. Confirm the deployed
website release, acting identity and secret paths before starting collection.

The deployment agent must run with `--verify-artifacts` during the competition.
Its authenticated artifact heartbeat verifies deployed content independently
of application health. A tag, an old freeze or a ready process is insufficient.
AI workload owners must supply equivalent authenticated deployment receipts.
An outage should reduce measured availability; missing content identity must
hold scoring. Do not fill an identity gap retroactively.

Prepare a private JSON configuration that validates against
`contracts/scoring-collector.schema.json`. Set the exact HTTPS website origin,
competition ID, UTC window, feed credential file, source-cache budget and
private state directory. `producers` maps local aliases to platform-issued
producer UUIDs and credential files. Each `probes` entry names its registered
target, producer alias, health path, separate functional path and typed JSON
assertions. A successful process-health response cannot satisfy a failed
functional assertion. Set `metrics_file` to the existing node exporter's
textfile directory. All credential files must be owner-only.

For native proof and collector measurement writes, set `loki_url` to the
existing OBS mTLS receiver using a name or address covered by its server
certificate. Set `loki_tls` with `ca_file`, `cert_file` and `key_file`, installed
through `obs_scoring_credentials`. All three must be regular files owned by
root or the service account. The private key must be owner-only; the CA and
certificate must not be writable by a group or other users. Symlinks,
incomplete settings, invalid material and mismatched keys fail validation.
Server trust and hostname checks remain enabled.

Issue a dedicated client certificate from the existing telemetry CA with
`CN=jengasec-scoring-collector`. Set
`obs_infrastructure_scoring_certificate_sha1` to its fingerprint as 40 hex
characters without separators. The default empty value disables the native
routes. Nginx requires both the reserved CN and the active fingerprint for
`GET /loki/api/v1/query_range` and `POST /loki/api/v1/push`. It forces the
`staff` tenant and removes any Authorization header before forwarding. This
credential permits evidence reads and measurement appends, and needs no
Grafana or administrator credential. The reserved collector role is denied
on every other ingestion route even when its pin is disabled or replaced;
retired certificates cannot regain generic ingest access. Other existing
ingest clients retain their routes and cannot use the native Loki routes.
List the infrastructure resources that the collector may cite.

For AI receipts, configure `ai_gateway.url`, its operator credential file and
an exact producer map from team, source ID and role to the platform producer
UUID. Use the AIC service's HTTPS origin. `ai_gateway.api_prefix` defaults to
`/api/v1/scoring`; select `/api/v1` only for an explicit private backend
connection. The bridge retains complete native and embedded effect proof before
queueing normalized receipts and acknowledging the gateway cursor. A missing
mapping for an issued case holds that cursor. Unscheduled action audit records
stay non-scoring records.

Deploy with `ansible/scoring-observability.yml` and a private inventory selecting
one existing OBS host. Supply `obs_scoring_policy_source` as the checked-out
website source, `obs_scoring_config_source` as the private JSON file, and only
the explicit `obs_scoring_credentials` files. The role uses the existing Python
runtime with JSON Schema and YAML support. It creates no accounts and changes
no SSH settings. `obs_scoring_start` defaults to false. Review the selected
host, storage budget, credentials, state paths and recovery controls before
enabling the service.

The service keeps functional measurements on a separate schedule from slow
publication. Its private `status.json` and `probes.json` distinguish delivery
from probe progress. Existing node metrics expose pending rows, pending bytes,
rejected rows and backpressure. At capacity or after a storage failure, restore
capacity or repair the source before retrying. Preserve the delivery database,
source cache and original IDs across restarts. Do not reset cursors to make a
warning disappear. A missing source receipt or archive must remain a hold.

Use `ansible/scoring-ai.yml` for the separately selected gateway, actuator or
effect-probe role. The gateway requires an existing unprivileged account and
group with the reviewed file access; the role does not create identities or
change memberships. Its defaults are `/opt/jengasec-scoring-ai`,
`/etc/jengasec-scoring-ai` and `/var/lib/jengasec-scoring-ai`, with unit
`jengasec-scoring-ai.service`. These are separate from the AIC service's
`jengasec-ai` directories. The gateway listens only on `127.0.0.1`; it creates
no public nginx location. Configure a fixed authenticated command to the
actuator and a separate fixed command to the effect verifier.

Install the private gateway on the same host as the AIC service, with reviewed
read access to its configured OBS telemetry spool and current identity. The
facade does not copy the AIC event database into that spool.
The existing AIC service is the only public facade. Set its `SCORING_MODE=1`,
`SANDBOX_SEED=0`, and `SCORING_GATEWAY_PORT` to the gateway's `listen_port`
(default 9681). `SCORING_GATEWAY_TIMEOUT_SECONDS` defaults to 35, with a
maximum of 60 seconds. Public `/api/v1/scoring/*` requests reach private
`/api/v1/*` paths. The facade preserves the original bearer and request bytes.
Register each producer's token hash, canonical identity and role in the
gateway's protected configuration. Existing v1 reads retain their contract.
Legacy decision, action and revert writes return 409 in scoring mode; callers
must supply the scoring protocol's provenance. Backend failures never record
a shadow replacement.

The operator must clear the AIC service's legacy website feed credentials and
disable `jengasec-ai-marks.timer`. The installer disables the timer in scoring
mode; it does not rewrite existing credentials. The publisher also refuses
publication. Use a reviewed database without sandbox
events; explicit sandbox seeding prevents scoring-mode startup. The existing
AIC `ADMIN_TOKEN` must also be registered as a gateway operator for
`/admin/kill-switch` to work. The original staff token reaches the gateway;
the facade supplies no privileged replacement token. GET reads real actuator
state and POST must confirm actual revocation. Failed or pending recovery is
an error, not a change to an independent flag.

`snapshot-evidence` archives selected telemetry evidence. It is not a VM or
application snapshot. Revert removes an actuator-owned block lease and checks
functional recovery; workload restoration remains unsupported.

Deploy `ansible/scoring-ai-identity.yml` on each selected gateway and actuator
host before enabling actions. Set the website's
`DJANGO_SCORING_IDENTITY_TOKEN` and supply its matching private file as
`scoring_ai_identity_token_source`. The `scoring_ai_identity_config` object
requires `schema_version: scoring-ai-identity/1.0`, the HTTPS `origin`, the
competition ID, `token_file` under the role's configuration directory, and
`snapshot_file` under its state directory. An optional `ca_file` selects a
root-owned CA bundle. The credential grants identity reads only.

For a gateway, set the role's `scoring_ai_identity_reader_user` and
`scoring_ai_identity_reader_group` to its existing service identity, and set
the same `reader_group` in the JSON configuration. The publisher owns the
snapshot and grants that group read access only. For a root actuator, omit
the reader group. Set each runtime's `identity_file` to that host's published
snapshot. Keep the credential outside all runtime-readable directories.
Enable `scoring_ai_identity_start` during the approved rollout. Confirm a
fresh snapshot can be read as the selected service account before starting
the gateway. The timer refreshes every 30 seconds and invalidates the snapshot
on a failed refresh; actions require current authority with at most 120
seconds of validity.

The actuator uses a dedicated drop-only
nftables table and timed exact-target tuples. It requires fresh current scope,
management-network exclusions, one active restriction per team and target,
five new restrictions per minute, thirty per hour and leases of at most 60
seconds. Expired authority, unsupported actions and unverified effects cannot
be recorded as successful execution.

The effect verifier must run from the approved source and independent control
addresses. It checks actual service responses before, during and after the
restriction. Runtime design, safety and decision assertions must come from the
registered independent observer. Teams still supply their competition AI
services; the shared gateway does not manufacture a competing agent or a
successful runtime assertion.

Before finalization, verify each role's source, timed identity, native proof,
calculated facts, feed outcome, stored revision and authorized website view.
Exercise a correction, duplicate retry, partial rejection, outage/restart,
override, delayed board, evidence-access rejection and appeal hold. Verify
actual effect, automatic expiry, explicit reversal and the kill switch on the
approved network target. Have another reviewer reproduce the marks from the
archived inputs. Local tests are not evidence of this live acceptance.

Use fix-forward recovery for code and configuration failures:

1. Contain the affected operation. Stop incorrect publication through the
   website's controls or stop `jengasec-scoring.service`. Keep OBS collection
   and unaffected reads running where possible. For an unsafe AI restriction,
   enable the actual actuator kill switch and verify functional restoration
   before stopping the gateway. Kernel expiry, explicit reversal and the kill
   switch remain required containment controls. Do not flush shared firewall
   tables. Keep current-identity refresh running unless that component needs
   repair.
2. Record the affected release, configuration paths, service identities and
   state paths privately. Preserve the collector's `delivery.sqlite3` and
   `sources.sqlite3`, source and receipt cursors, rejected rows and retained
   proof. Preserve each gateway and actuator `state_file`, evidence directory,
   action keys, producer sequences and kill-switch state. Preserve website
   score revisions, overrides, archive objects and appeal holds through the
   website owner's recovery procedure. Source control cannot restore this
   runtime state.
3. Before a migration or storage repair, take a consistent private backup.
   Stop all writers before copying a state directory, or use SQLite's backup
   API for each database and coordinate the related stores and evidence.
   A live copy of the main SQLite file alone can omit committed WAL data.
   Retain required journal files and numeric ownership when copying stopped
   state. Verify database integrity and that referenced evidence remains
   readable. A backup from before an acknowledged export can be incomplete;
   keep affected publication held until retained source proof and receiver
   history establish what can be recovered.
4. Apply a reviewed forward correction with compatible code, configuration
   and migrations. Validate migrations on a copy first. Preserve existing
   rows, stable component keys and the enrolled policy; do not reset databases,
   counters, cursors, producer IDs or epochs to bypass a failure. Use a new
   policy version only through the website's approved policy process. Stop
   affected writers before replacing their installed source. The Ansible
   roles update code and configuration in place; setting their `*_start`
   options to false does not stop an already running service. These roles do
   not reverse migrations or remove runtime state after a failed check.
5. Run checks for the changed behavior and redeploy the corrected release
   against the preserved state. Confirm credential and receiver compatibility,
   source progress, queue delivery, archived inputs and stored revisions.
   Fetch a fresh execution-authority snapshot before resuming actions. Keep
   historical authority as evidence; never extend an old snapshot's expiry.
   Reconcile actuator state and verify functional recovery before clearing
   the kill switch. A restart must not replay a missing firewall restriction.

A corrected calculation keeps `main:<criterion>` and receives the next
delivery revision. The collector includes calculated marks in its input
fingerprint, so changed results can produce a correction without deleting
source cursors. Older input-only fingerprints are reevaluated once. Existing
queued payloads and immutable evidence are not rewritten. A permanently
rejected older row stays visible in queue metrics while an eligible higher
revision can be delivered. Retry the same rejected payload only after fixing
its rejection cause; changed facts or marks require a new revision. Verify
the website's accepted revision and authorized view before resuming normal
publication. Missing evidence or identity remains a hold.

Use release rollback only for an incident where a forward correction cannot
contain the harm adequately. Record that reason and check data compatibility
before selecting an earlier binary. Reverting code does not reverse committed
scores, restore database contents or remove a runtime action. A separate
release-rollback drill is not a prerequisite for routine forward repair.

For isolated integration validation, install the website's test dependencies,
set `JENGASEC_PLATFORM_SOURCE` to its compatible checkout, and run
`make scoring-integration-check` with that Python environment. The check uses
a disposable test database and local functional HTTP service. Run
`make scoring-check` for collector and AI transport, proof and failure checks.
