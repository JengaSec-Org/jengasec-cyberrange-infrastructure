# Contract: application cell template

Owner: Application Platform, with Security. Each enabled application instance
is created by `charts/cell`.

| Item | Value |
|---|---|
| Enterprise | `ENT-A` or `ENT-B` |
| Application | `APP01` through `APP09` |
| Namespace | `jengasec-<enterprise>-<application>`, lower-case |
| Reserved IP | Contracted VLAN 108 address from `applications` |
| Guaranteed resources | 1 vCPU and 2 GB memory, including the database |
| Limit | 2 vCPU and 3 GB memory |
| Storage | 5 GB database volume |
| Database | PostgreSQL 16; credentials in Secret `db-credentials` |
| Workload identity | Namespace-scoped `deployer` service account |
| Ingress | Reserved IP and application hostname with scoped gateway rules |
| Observability | stdout logs, `/metrics`, health and Kubernetes events shipped automatically |

APP08 and APP09 are optional. They are enabled or disabled in ENT-A and ENT-B
together so the two enterprise instances remain identical.

The default policy denies all traffic, then permits only declared application
ingress, the application to its own database, same-enterprise application
dependencies, DNS, and egress to the collector. It never permits cross-
enterprise traffic, another application's database, the platform namespace,
or the management network.

The platform injects these immutable environment variables into every
application container:

- `JENGASEC_ENTERPRISE`
- `JENGASEC_APPLICATION`
- `JENGASEC_NAMESPACE`

Ingress permits the staff range `10.63.0.0/24`, the owning Blue team's
WireGuard range (`JS26-B-NNN` maps to `10.61.N.0/24`), and only active Red
assignments from the imported scope contract. `scripts/make-scope.py` validates
team IDs against the address plan and updates existing Helm releases with
`--reuse-values`, preserving their deployed image and other release settings.
Import current platform exports before applying scope changes; the script does
not create missing releases. Use `python3 scripts/make-scope.py --dry-run` to
render the Helm changes without modifying the cluster.

Teams have read-only access to their own observability view. They never receive
cluster-wide credentials or direct access to another namespace.

The competition website's range export is the source of assigned cell
namespaces and reserved service addresses. `scripts/import_platform_exports.py`
translates its `cells.yaml` and scope-assignment CSV into this repository's
`scripts/cells.yaml` and `contracts/scope-assignments.csv` formats. Application
namespaces must retain the canonical form shown above; the import fails rather
than silently renaming an assigned namespace or address.
