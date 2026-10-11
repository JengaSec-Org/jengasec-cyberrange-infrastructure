# Pinned versions

Everyone runs these. Change by pull request so the whole team moves together.

| Thing | Version | Where |
|---|---|---|
| Guest OS | Debian 12 (bookworm) | Dev VMs and all platform VMs |
| Hypervisor | Proxmox VE 9.1 | Server 3 (as found) |
| Kubernetes | k3s (pin the exact channel/version here once installed) | k3s VMs |
| Helm | 3.22.0 | Dev VMs, deploy pipeline |
| Ansible | core 2.19.3 | Dev VMs and OBS VM rehearsal |
| Python | 3.11 (Debian 12 default) | Scripts |
| PostgreSQL | 16.15-bookworm | Platform, cells and future OBS event store |
| Test Python image | 3.11.14-slim-bookworm | Test emitter and contract checks |
| Vector | 0.58.0-debian | Telemetry collector |
| GoFlow2 | 2.2.7 | NetFlow/IPFIX decoder |
| OpenTelemetry Collector Contrib | 0.137.0 | Cluster log and event transport |
| Prometheus | 3.15.0 | Metrics store |
| Prometheus label proxy | 0.12.0 | Per-application metrics boundary |
| NGINX | 1.28.0-alpine3.21 | Prometheus remote-write endpoint guard |
| Loki | 3.7.8 | Log store |
| Grafana | 13.2.3 | Dashboards |
| check-jsonschema | 0.38.2 | Contract test image |

Fill the blanks the first time each is installed — in the same pull request as the install.
