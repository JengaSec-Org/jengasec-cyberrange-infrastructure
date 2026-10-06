# Pinned versions

Everyone runs these. Change by pull request so the whole team moves together.

| Thing | Version | Where |
|---|---|---|
| Guest OS | Debian 12 (bookworm) | Dev VMs and all platform VMs |
| Codespaces base | devcontainers/base 1-bookworm (`sha256:ce2e9e61…`) | Development container |
| Codespaces Docker feature | docker-in-docker 4.1.2; Moby 29.7.2 | Development container |
| Hypervisor | Proxmox VE 9.1 | Server 3 (as found) |
| Kubernetes | k3s (pin the exact channel/version here once installed) | k3s VMs |
| Helm | 3.22.0 | Dev VMs, deploy pipeline |
| Ansible | core 2.x (record exact) | Dev VMs |
| Python | 3.11 (Debian 12 default) | Scripts |
| PostgreSQL | 16 (official image) | Platform and cells |
| Reference Python image | 3.11.14-slim-bookworm (`sha256:65a93d69…`) | Codespaces reference workload and contract tests |
| Vector | 0.58.0-debian (`sha256:1c1ea358…`) | Codespaces; future cluster collector |
| Prometheus | 3.15.0 (`sha256:efd719c9…`) | Codespaces; future obs VM |
| Loki | 3.7.8 (`sha256:1107dd52…`) | Codespaces; future obs VM |
| Grafana | 13.2.3 (`sha256:b28bae15…`) | Codespaces; future obs VM |
| check-jsonschema | 0.38.2 | Contract test image |

Fill the blanks the first time each is installed — in the same pull request as the install.

The complete immutable image digests live beside the image tags in
`observability/compose.yaml` and the two observability Dockerfiles. Keep the
version and digest together when upgrading an image.
