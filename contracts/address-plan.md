# Contract: addresses and names

Owner: Network & Access. VLAN availability and live interface addresses must be
confirmed with ICT before deployment.

## VLANs

| VLAN | ID | Default subnet | Purpose |
|---|---:|---|---|
| Management | 101 | `10.101.0.0/24` | Switches, APs, gateway administration; never participant-accessible |
| Staff | 102 | `10.102.0.0/24` | Platform operations and recovery |
| Judges | 103 | `10.103.0.0/24` | Read-only dashboards and scoring |
| Red AI users | 104 | `10.104.0.0/24` | WireGuard entry only |
| Red App users | 105 | `10.105.0.0/22` | WireGuard entry only |
| Blue AI users | 106 | `10.106.0.0/24` | WireGuard entry only |
| Blue App users | 107 | `10.107.0.0/23` | WireGuard entry only |
| Blue applications | 108 | `10.108.0.0/24` | Application addresses on k3s-blue |
| Functions | 109 | `10.109.0.0/24` | Machine-to-machine services; no people |

Server 3 remains on the separate `192.168.40.0/24` management network. The
VLAN IDs above must be checked against the existing campus allocation before
any interface is created.

## Function addresses

| Address | Service |
|---|---|
| `10.109.0.1` | Gateway/network services |
| `10.109.0.10` | Competition website |
| `10.109.0.20` | Shared database and registry services |
| `10.109.0.30` | Observability |
| `10.109.0.50` | k3s-blue |
| `10.109.0.60` | k3s-red, if enabled |

## Application addresses

| Application | ENT-A | ENT-B |
|---|---|---|
| APP01 | `10.108.0.11` | `10.108.0.21` |
| APP02 | `10.108.0.12` | `10.108.0.22` |
| APP03 | `10.108.0.13` | `10.108.0.23` |
| APP04 | `10.108.0.14` | `10.108.0.24` |
| APP05 | `10.108.0.15` | `10.108.0.25` |
| APP06 | `10.108.0.16` | `10.108.0.26` |
| APP07 | `10.108.0.17` | `10.108.0.27` |
| APP08 (optional) | `10.108.0.18` | `10.108.0.28` |
| APP09 (optional) | `10.108.0.19` | `10.108.0.29` |

Optional applications are enabled or disabled in both enterprises together.

## WireGuard allocation

| Identity | Team range |
|---|---|
| App Red team 1–54 | `10.60.<team>.0/24` |
| App Blue team 1–18 | `10.61.<team>.0/24` |
| AI Blue team 1–3 | `10.62.<team>.0/24` |
| Staff and judges | `10.63.0.0/24` |
| AI Red team 1–6 | `10.64.<team>.0/24` |

Addresses `.1` through `.9` in a team range are reserved. Participant
addresses start at `.10`, one `/32` per person. Gateway routing preserves the
WireGuard source address; no NAT is permitted between team ranges and
applications.

## Names

| Name | Points at |
|---|---|
| `<domain>` | Competition website |
| `git.<domain>` | Registry and source hosting |
| `ai.range.<domain>` | AI-owned API, when implemented |
| `<enterprise>-<application>.range.<domain>` | Application reserved address |
| `grafana.<domain>` | OBS access gateway |

Example: `ent-a-app01.range.<domain>` maps to `10.108.0.11`.

## OBS integration flows

| From | To | Port | Purpose |
|---|---|---:|---|
| Gateway | OBS | TCP/UDP 514 | Firewall and IDS syslog |
| Gateway | OBS | UDP 2055 | NetFlow/IPFIX |
| k3s-blue | OBS | TCP 4317 | OTLP application and Kubernetes events |
| k3s-blue | OBS | TCP 9090 | Prometheus remote write |
| OBS | Website | TCP 443 | Sanitized `POST /api/feed` |
| OBS | Shared database | TCP 5432 | Read-only attribution and finding views |
| Judges/Staff | OBS | TCP 443 | Authenticated dashboards and evidence export |

Loki, Grafana, Prometheus administration, Vector administration and the OBS
telemetry database are not exposed directly to participant or judge networks.
