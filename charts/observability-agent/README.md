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
object UIDs and arbitrary application labels are removed.

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

Run `tests/test-agent.py` with `HELM_BIN` and `OTELCOL_BIN` pointing to Helm and
OpenTelemetry Collector Contrib 0.137.0. It verifies rendering boundaries and
executes the native event and metric sanitization processors.
