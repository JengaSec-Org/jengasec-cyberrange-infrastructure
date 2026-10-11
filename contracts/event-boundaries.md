# Contract: event boundaries

Owner: Observability, with Platform and Scoring.

Three record families remain separate even when an evidence pack refers to
more than one of them.

| Family | Contains | Authority | Storage |
|---|---|---|---|
| Telemetry | Application, ingress, network, IDS, Kubernetes and host observations | `telemetry-event.schema.json` | Loki and the OBS telemetry store |
| Platform audit | Staff and automated changes to platform state | Competition Platform audit contract | Platform audit store; staff access only |
| Competition | Findings, decisions, scores, appeals and published results | Scoring and AI contracts | Competition Platform database |

Telemetry never awards points by itself. Scoring may cite stable telemetry
event IDs, but it owns the interpretation and score. A platform action is not
renamed into a telemetry event merely to make it visible in Grafana.

Evidence exports preserve this separation as different files and describe the
source and contract version of each file in their manifest.
