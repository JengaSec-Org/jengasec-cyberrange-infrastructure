# Kubernetes observability collector

The chart observes Kubernetes health and resource use in the OBS namespace.
It reads cluster objects and kubelet metrics through the Kubernetes API. It
does not read Secrets or change workloads. Application metrics require the
existing scrape annotation and a namespace in the application contract.

Supply `obs.cluster`, `obs.resourceId`, `obs.environment`, and the HTTPS
remote-write URL from inventory. Install the client certificate, key, and CA
as the `obs.tls.secretName` Secret. Live mode rejects unverified TLS.

Metrics start with `obs.eventsEnabled: false`. Enable it with the approved
OTLP endpoint after infrastructure-event ingestion is ready. Events contain
resource identity, reason, type, count, and a source event hash. Event messages
are discarded. Cluster metrics use trusted identity and allowlisted labels;
object UIDs and arbitrary application labels are removed. API events for
`observability-validation-*` resources in the OBS namespace use the validation
environment. These names are reserved for the OBS acceptance fixture.

The collector uses a retained PVC for the remote-write WAL and event queue.
One replica and a Recreate upgrade prevent concurrent WAL writers. Kubernetes
health and collection health are distinct: check remote-write freshness and
export failures in addition to pod readiness. A full PVC or queue is a loss
risk and requires operator attention. Retention in the central store remains
seven days.

Stage the OBS-only Ansible playbook with `obs_cluster_apply: false`. Review the
rendered resources, current cluster health, and certificate paths before
setting it to true. The role uses an atomic Helm upgrade and preserves the PVC.
For rollback, run `helm rollback jengasec-observability <revision> --namespace
jengasec-observability --wait` on the collector's cluster. On the first install,
remove only this Helm release; retain its PVC and TLS Secret for recovery.

Pod Security remains enabled. The chart does not mount host container logs.
Set `obs_cluster_host_logs_enabled: true` in the same OBS-only playbook to run
the optional host reader. It reads CRI files under `/var/log/pods`, uses no
Kubernetes API credentials, and writes only its private queue directory. Its
TLS keys are systemd credentials. It cannot read the host's Kubernetes or SSH
configuration.

The host reader accepts application JSON from any container name in a
contracted application namespace. The file path must match the event namespace.
Other namespaces may emit the infrastructure contract. Plain text, unknown
fields, nested objects outside the contract, wrong scopes, and other record
families are dropped before buffering. The central receiver still validates
each event against its complete contract. Filter and exporter counters expose
rejections and delivery failures. This reader does not turn unstructured
component output into Kubernetes API events.

The host queue holds at most 128 batches of 64 records; each source record is
limited to 64 KiB. Its checkpoints and queue survive service restarts. The
collector's localhost health endpoint does not prove delivery: verify central
log queries and exporter counters after changes. To stop the host reader,
disable only `jengasec-container-logs.service`; keep its state for replay.

Run `tests/test-agent.py` with `HELM_BIN` and `OTELCOL_BIN` pointing to Helm and
OpenTelemetry Collector Contrib 0.137.0. It verifies rendering boundaries and
executes the native event and metric sanitization processors.
