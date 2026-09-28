# jengasec-infra

Everything that builds, runs and tears down the JengaSec range lives here. One repository, one folder per area.

JengaSec runs on **one machine**: Server 3, a Proxmox host. Everything else is a virtual machine on it. Nobody experiments on Server 3 — you build and test on your own Debian 12 VM, open a pull request, and the change is applied to the server from this repository.

## Start here

1. Read `docs/standards.md` (how we work) and `CONTRIBUTING.md` (how to get a change in).
2. Build your dev VM: `tools/bootstrap-dev-vm.sh` (Debian 12, 2 vCPU, 4 GB, 40 GB).
3. Add yourself to `docs/people.md` in your first pull request.
4. Find your task IDs in the Ops Board and the "Who Does What" plan.

## Layout

| Folder | Holds | Owner |
|---|---|---|
| `contracts/` | The formats every area builds against. Change only by pull request. | Named per contract in `docs/contracts.md` |
| `ansible/` | Host and VM configuration: users, hardening, packages, k3s install | Platform |
| `charts/` | Helm charts, above all `charts/cell` — one team environment | Application Platform |
| `scripts/` | Everything automated: provisioning, accounts, configs, snapshots, resets | Whoever owns the task |
| `observability/` | Vector, Prometheus and Grafana configuration, exported dashboards | Observability |
| `runbooks/` | How to run and recover each thing, written for someone who is tired | Area that owns the thing |
| `docs/` | Standards, contracts index, access tiers, decisions, people, versions | Technical lead seat |
| `tools/` | Developer helpers, starting with the dev VM bootstrap | Anyone |

## Status of this scaffold

Nothing here has run against Server 3 yet. The Ansible roles, the cell chart and the scripts are starting points with the right shape, the right names and the right guard rails — the first job in each area is to run its own piece on a dev VM, fix what is wrong, and open the pull request that makes it real.

## The rule that matters most

There is no Automation Lead. **Every area automates its own work here.** If you have typed the same commands twice, the third time is a script in `scripts/`, with a runbook entry.
