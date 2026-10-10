# ADR 0002: Codespaces observability foundation

**Status:** proposed

**Context.** The observability configuration needs an end-to-end development
path before anything is designed for or applied to Server 3. The logging and
telemetry contracts also require a concrete normalization boundary, while the
AI API contract does not yet define how producers deliver events.

**Decision.** Run the first milestone as a pinned Docker Compose stack in
Codespaces. A reference emitter writes contract-valid JSON and exposes
Prometheus metrics. Vector renders its event mapping and sensitive-key policy
from the shared catalogue, quarantines rejected input without retaining raw
payloads, converts accepted logs to the strict telemetry shape, and sends them
to Loki. Prometheus scrapes the emitter and Vector; Grafana provisions both
data sources and a dashboard. Do not configure an AI sink until its ingestion
contract is agreed.

**Consequences.** Contributors can validate the complete event and metric paths
without Server 3 access. The later k3s work can replace Docker discovery with
the Kubernetes log source while preserving the transform and contracts. The
development-only Docker socket mount and anonymous Grafana access must not be
copied into the k3s deployment. AI consumption remains an explicit integration
dependency.
