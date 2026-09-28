# Pinned versions

Everyone runs these. Change by pull request so the whole team moves together.

| Thing | Version | Where |
|---|---|---|
| Guest OS | Debian 12 (bookworm) | Dev VMs and all platform VMs |
| Hypervisor | Proxmox VE 9.1 | Server 3 (as found) |
| Kubernetes | k3s (pin the exact channel/version here once installed) | k3s VMs |
| Helm | 3.x (record exact) | Dev VMs, deploy pipeline |
| Ansible | core 2.x (record exact) | Dev VMs |
| Python | 3.11 (Debian 12 default) | Scripts |
| PostgreSQL | 16 (official image) | Platform and cells |
| Vector | record exact | Cluster |
| Prometheus / Loki / Grafana | record exact | obs VM |

Fill the blanks the first time each is installed — in the same pull request as the install.
