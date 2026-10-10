# JengaSec engineering standards

These are short on purpose. Read them once; they decide most arguments before they start.

## 1. One server, three places to work

| Place | What it is | Who touches it |
|---|---|---|
| Your dev VM | Debian 12 on your own laptop, built by `tools/bootstrap-dev-vm.sh` | Everyone |
| This repository | The only description of the platform that counts | Everyone |
| Server 3 | The Proxmox host and its VMs | Only the access tiers in `docs/access-tiers.md` |

Try everything on your dev VM first. A change reaches Server 3 by being merged here and applied by someone with access, not by being typed into a terminal.

## 2. Automation is everyone's job

There is no Automation Lead. Each area writes its own scripts into `scripts/`.

**Script rules**

- Bash starts with `set -euo pipefail` and sources `scripts/_lib.sh`.
- Every script has a header: what it does, who owns it, how to run it, what it changes.
- Running it twice does nothing the second time (idempotent).
- Anything destructive supports `--dry-run` and prints what it would do.
- No hard-coded addresses, hostnames or passwords: read them from `contracts/`, Ansible variables, or arguments.
- Python: standard library plus `requests` and `PyYAML` only.
- Every script gets a runbook entry in `runbooks/`.

## 3. Naming

| Thing | Pattern | Example |
|---|---|---|
| VM | role, lowercase | `k3s-worker-2` |
| Enterprise ID | `ENT-A` or `ENT-B` | `ENT-A` |
| Application ID | `APP01` through `APP09` | `APP07` |
| Namespace | `jengasec-<enterprise>-<application>`, lower-case | `jengasec-ent-a-app07` |
| Asset ID | `<namespace>/<component>` | `jengasec-ent-a-app07/app` |
| Hostname | `<enterprise>-<application>.range.<domain>`, lower-case | `ent-a-app07.range.jengasec.example` |
| Branch | `<area>/<thing>` | `sec/allowlist-generator` |
| Script | verb-noun | `provision-cells.sh` |
| Secret | `<area>-<what>` | `app-registry-token` |

Display names may contain spaces, but machine interfaces use only these IDs.
Do not use the retired Zawadi/Afya or `app-NN` identifiers in new contracts.

## 4. Versions

Everyone uses the same versions, pinned in `docs/versions.md`. If you need a different one, change the file in a pull request so everyone moves together.

## 5. Contracts

A contract is a format two areas agree on. They live in `contracts/` and are listed in `docs/contracts.md`. Changing one is a pull request labelled `contract`, announced at stand-up. After checkpoint C2 (teams building), contracts only gain optional fields — nothing is renamed or removed.

## 6. Secrets

- Platform secrets: Ansible Vault (`ansible/group_vars/*/vault.yml`).
- Application secrets: Kubernetes Secrets created by the cell chart.
- Tokens for pipelines: repository secrets in Gitea or GitHub.
- Never in Git, never in chat, never in a screenshot. `pre-commit` runs a secret scan.

## 7. Definition of done

A task is done when: the deliverable exists, it is merged here, a runbook says how to run and recover it, and **someone other than the author has run it successfully**.

## 8. Ways of working

- Daily 15-minute stand-up: done, doing, blocked.
- Decisions go in `docs/adr/` as short records. If it is not written down, it is not decided.
- One incident channel. Problems there, not in private messages.
- Pair on anything that can break the platform: Proxmox, the cluster, the gateway, the site.
- Checkpoints C1 to C4 in the plan are where the team decides go or fallback.
