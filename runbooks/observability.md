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

Take a cold backup during an approved maintenance window. Stop
`jengasec-observability.service`, copy the full state directory with numeric
owners to encrypted storage, record a SHA-256 inventory, then start the unit
and run the smoke check. Back up Vault and the PostgreSQL service secret
through the secrets owner, not with the data copy. To recover, keep the unit
stopped, restore the state directory and numeric ownership, stage the matching
release, start it, verify native Loki and Prometheus queries, then run the full
smoke check. Retain backups and evidence through the appeal window.

The website receiver and authentication remain website-owned. The AI network
endpoint, transport and authentication remain AI-owned. Until those owners
publish their interfaces, do not treat a rehearsal mock or the local AI spool
as a live integration.

## Outbound integrations

The development stack posts sanitized events to its mock `/api/feed` receiver.
Set `JENGASEC_WEBSITE_FEED_URL` only after the website owner provides the live
HTTPS receiver and authentication method. `make obs-smoke` proves a live event
arrived without sensitive or attribution fields.

Vector also writes normalized events to the `vector-ai-handoff` volume. A live
deployment mounts that volume at `/var/lib/vector/ai-handoff/` with OBS-only
write access. Do not add a network destination or credentials until the AI
owner publishes that interface.
