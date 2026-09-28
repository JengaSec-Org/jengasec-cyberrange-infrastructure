# Contract: cell template

Owner: Application Platform, with Security. Every Application cell gets exactly this, created by `charts/cell`.

| Item | Value |
|---|---|
| Namespace | `app-NN` (01–07 Zawadi Bank, 08–14 Afya Health) |
| Guaranteed resources | 1 vCPU, 2 GB memory (including the cell's database) |
| Limit | 2 vCPU, 3 GB memory |
| Storage | 5 GB volume for the database |
| Network policy | Deny all, then: ingress controller → app, app → own database, app → log collection, app → DNS |
| Service account | `deployer`, may change only its own namespace |
| Database | PostgreSQL 16, credentials in a Kubernetes Secret `db-credentials` |
| Hostname | `app-NN.range.<domain>`, TLS from the range wildcard certificate |
| Ingress | Traefik route with a per-cell allow list and a rate limit |
| Logs and metrics | Collected automatically; a read-only Grafana folder per team |
| Preview (build stage only) | `app-NN.preview.<domain>` behind a per-team password |

A cell never gets: cluster-wide rights, access to another namespace, access to the platform namespace, access to the management network.
