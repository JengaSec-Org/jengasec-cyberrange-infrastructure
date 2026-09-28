# Contract: addresses and names

Owner: Network & Access. Proposed values — confirm and keep this file correct; scripts read from it.

| Network | Range | Used for |
|---|---|---|
| School LAN | 192.168.40.0/24 | Proxmox management only |
| Platform (vmbr1, internal) | 10.10.10.0/24 | All VMs; internet through the host |
| Competition LAN (vmbr2 on nic1) | 10.50.0.0/22 | Attack-day Wi-Fi; reaches only the VPN endpoint |
| Red teams (WireGuard) | 10.60.1.0/24 … 10.60.40.0/24 | One range per Red team |
| Blue cells (WireGuard) | 10.61.1.0/24 … 10.61.20.0/24 | One range per Blue cell |
| Staff on site (WireGuard) | 10.63.0.0/24 | Marshals, judges, platform team |
| Kubernetes | 10.42.0.0/16 pods, 10.43.0.0/16 services | k3s defaults |

## Names

| Name | Points at |
|---|---|
| `<domain>` | Competition website (through the tunnel) |
| `git.<domain>` | Gitea (through the tunnel) |
| `ai.range.<domain>` | AI API |
| `app-NN.range.<domain>` | Team application on the competition network |
| `app-NN.preview.<domain>` | Team preview during the build stage only, password protected |
| `grafana.<domain>` | Dashboards, staff only through Cloudflare Access |

Traffic from a team's WireGuard range reaches the ingress without address translation, so logs show which team made every request.
