# The platform VM: website, AI and scoring on one machine

**Owner:** AIC (Kris) · **Status:** proposed 2026-10-14 · **Supersedes** the separate AI VM in `docs/ai-integration.md`

**Built from:**
- the server VM sheet (`VM.pdf`)
- the database quick reference
- NET's kit `jengasec-update-2026-10-14-wifi` (address plan, OPNsense handoff, WireGuard worker)
- NET's `JengaSec_VLAN_Ranges.pdf` (14 October 2026): VLANs 101–109, the fixed VLAN 109 addresses, the VPN ranges
- the website's Ansible, `jengasec-website-infrastructure` (`inventories/v1`: VM 101 is its own control node) and its `scripts/cutover/` (website database on postgres-vm)
- the observability contracts on `main`

**Rule for this page:** where it gives an address that is not live yet, it says so. Nothing here changes a live system.

## 1. What runs on VM 101 (`jengasec-vm`)

| Service | Listens on | Reached by |
|---|---|---|
| nginx → website (Django, gunicorn on the unix socket `/run/gunicorn/gunicorn.sock`), deployed by the website's Ansible (`make platform`) | **443** (TLS, the Ansible internal CA) | Participants, staff and judges over WireGuard and the venue Wi-Fi; Render is suspended after the cutover |
| AI API (`ai-api/`, uvicorn) | **8443** (TLS) | AI Blue and AI Red teams over WireGuard; Vector on the OBS VM (`/ingest`); staff |
| AI marks timer (`jengasec-ai-marks.timer`) | — | Calls the website **on the same machine** through nginx: `https://192.168.40.11/api/feed/` (the website's certificate names that address; traffic stays on the VM) |
| Ollama (proposal scoring model) | `127.0.0.1:11434` only | The website, locally |
| NET's control plane and Ansible controller (already here, from NET's kit) | as NET's kit sets it | NET; check its port does not clash with 443 or 8443 (the range portal API uses `127.0.0.1:8080`) |

Putting the AI API next to the website removes one network hop: the marks go to `127.0.0.1` and never cross a network. It also removes a VM, and a clash: NET has given `10.109.0.40` to wireguard-vm, which is the address the separate AI VM was going to use.

**Size it for the model.** VM 101 is 4 vCPU / 8 GB (the website's `host_vars/jengasec.yml`), shared by nginx, gunicorn, Redis, Bind9, Prometheus, Grafana, the AI API and Ollama. The AI API needs little: about 150 MB. Ollama is the heavy one: about 3–4 GB for a 4B model and about 5 GB for `llama3` (8B) while it scores. Either run proposal scoring outside the busy hours, or ask for 12 GB.

## 2. Two networks, two addresses

| Interface | Address | Exists now? | Used for |
|---|---|---|---|
| nic0, VM network `192.168.40.0/24` | **192.168.40.11** | Yes | Machine-to-machine traffic with the other VMs, and staff SSH. Participants **never** reach this network (NET's rule) |
| second NIC, Functions VLAN 109 (vmbr1 tag 109) | **10.109.0.10** | **No**: only once NET makes VLAN 109 live (OPNsense trunk, address plan §3) | Everything **participants** reach: the website on 443, the AI API on 8443 |

**The one rule:** VMs talk to VM 101 on `192.168.40.11`; people talk to it on `10.109.0.10`. Bind the services to all addresses (the default) and let the firewall in §5 decide who reaches what.

## 3. Every flow, both directions

### Into VM 101

| # | From | To | Port | What | Authentication |
|---|---|---|---:|---|---|
| I1 | OBS VM 104 `192.168.40.60` (Vector) | `192.168.40.11` | 8443 | `POST /api/v1/ingest`: all telemetry v2, NDJSON | `INGEST_TOKEN` + TLS (`docs/ai-integration.md` §1) |
| I2 | OBS VM 104 | `192.168.40.11` | 443 | `POST /api/feed`: availability/detection marks for App Blue, **once mismatch #1 in `docs/ai-integration.md` is settled** | `DJANGO_FEED_TOKEN` |
| I3 | Every participant, staff and judge (WireGuard `10.60.0.0/14`, `10.64.0.0/16`) via wireguard-vm | `10.109.0.10` | 443 | The website: findings, VPN config download, scoreboard, team pages | Website login |
| I4 | AI Blue `10.62.0.0/16`, AI Red `10.64.0.0/16`, staff `10.63.0.0/24` | `10.109.0.10` | 8443 | The AI API | One token per AI team; `ADMIN_TOKEN` for staff |
| I5 | Staff on `192.168.40.0/24` | `192.168.40.11` | 22 | Administration | SSH keys |

### Out of VM 101

| # | From VM 101 | To | Port | What |
|---|---|---|---:|---|
| O1 | website | postgres-vm 103 `192.168.40.45` | 5432 | The website's database `jengasec_web` (`scripts/cutover/setup-database-vm.sh`; only `192.168.40.11` and `10.109.0.10` may log in). The campus blocks outgoing 5432, so Neon is out; Render is suspended at the cutover |
| O2 | website (deploy agent, APP) | k8s-blue VM 106 `192.168.40.59` | 6443 | Scoped kubeconfig made by `website-access.sh grant` on VM 106 (it opens 6443 to `192.168.40.11` only) |
| O3 | NET control plane | postgres-vm 103 `192.168.40.45` | 5432 | NET's VPN pipeline database (provisioning jobs, allocations), on the same server as O1 |
| O4 | website | Brevo (mail), S3 storage (internet) | 443 | As on Render |
| O5 | AI marks | website on the same VM | 443 | via nginx on its own address; never leaves the VM |

### Between the other VMs (they matter to you, but someone else configures them)

| From | To | Port | What | Owner |
|---|---|---:|---|---|
| OBS 104 | website's database on postgres-vm `192.168.40.45` | 5432 | Read-only `obs_*_v1` attribution views (needs its own read-only login and a `pg_hba` line for `192.168.40.60`; `setup-database-vm.sh` allows only the website) | Website + OBS |
| wireguard-vm 102 `.47` | postgres-vm 103 `.45` | 5432 | Provisioning worker | NET |
| k8s-blue 106 | OBS 104 | 4317, 9090 | App logs and metrics | OBS / APP |
| gateway (OPNsense) | OBS 104 | 514, 2055 | Flow and IDS logs | NET / OBS |

**Where the attribution data lives.** OBS's contract reads the platform database's views. After the cutover that database is on postgres-vm, on the range, so an internet outage no longer stops attribution, the website or scoring. Only uploads and downloads (Backblaze, over 443) and email stop. Ask the database owner for OBS's read-only login.

## 4. Routing: replies must go back through the VPN

Participant traffic arrives **without NAT** (address plan §6, rule 1): a request from `10.60.2.13` arrives with that source address. VM 101's default gateway is the school router `192.168.40.1`, which knows nothing about `10.60.x`, so **replies would be lost** unless VM 101 has explicit routes back through wireguard-vm.

Once the VLAN 109 NIC exists (say it is `ens19`), add the routes to `/etc/network/interfaces` on VM 101:

```text
auto ens19
iface ens19 inet static
    address 10.109.0.10/24
    # Replies to participants go back through wireguard-vm, never via 192.168.40.1
    up   ip route add 10.60.0.0/14 via 10.109.0.40 dev ens19
    up   ip route add 10.64.0.0/16 via 10.109.0.40 dev ens19
    down ip route del 10.60.0.0/14 via 10.109.0.40 dev ens19
    down ip route del 10.64.0.0/16 via 10.109.0.40 dev ens19
    # Venue Wi-Fi reaches the servers directly (section 6, NET item 5); uncomment once that is live:
    # up   ip route add 10.105.0.0/24 via 10.109.0.1 dev ens19
    # down ip route del 10.105.0.0/24 via 10.109.0.1 dev ens19
```

If NET prefers to send everything through OPNsense instead, the next hop is `10.109.0.1`. Either way, check it with `ip route get 10.60.2.13`. The answer must name `ens19`, never `192.168.40.1`; `platform-check.sh` checks this for you.

Do **not** add a default route on `ens19`. VM 101 keeps `192.168.40.1` as its way to the internet (mail, Backblaze storage).

## 5. Firewall on VM 101

The gateway and wireguard-vm already filter, and this is the last layer. **The website's Ansible owns it, with ufw** (`roles/firewall`). Never load an nftables ruleset beside it: two firewalls on one host means the second silently undoes the first.

All the rules for this VM live in `inventories/v1/host_vars/jengasec.yml` in `jengasec-website-infrastructure`. That is the only place they work, because group rules are dropped on a host that is in seven groups.

| List | Opens | Flows |
|---|---|---|
| `firewall_rules_common` | 22 from `192.168.40.0/24` | I5 |
| `firewall_rules_lab` | 443 (and DNS, Grafana, Prometheus) from `192.168.40.0/24` | I2 (OBS's website feed) |
| `firewall_rules_venue` | 80 and 443 from the Wi-Fi `10.105.0.0/24`, VLAN 109 and every WireGuard range | I3 |
| `firewall_rules_ai_api` (added for this layout) | 8443 from `192.168.40.60`, `10.62.0.0/16`, `10.64.0.0/16` and `10.63.0.0/24` only | I1, I4 |

App Red / App Blue (`10.60.0.0/15`) and the Wi-Fi never reach 8443. Apply it with `make networking INVENTORY=inventories/v1`, then check with `sudo ufw status numbered`.

## 6. What the other owners must do

### NET: seven items, without them no participant can reach VM 101

1. **Apply `docs/net-platform-services.patch`** to `services/provision_worker.py` in NET's kit.

   As shipped, the worker drops every participant packet to `192.168.40.0/24` and to the website address *before* any allow rule. It has no way to grant "everyone may reach the website" or "AI teams may reach the AI API". It also refuses to give AI Blue a VPN profile, because AI Blue owns no target.

   The patch adds exact `/32`-and-port service allows rendered before the protected drop, and lets AI Blue be provisioned. Tested: the rendered ruleset passes `nft -c` on Debian 12. With identical inputs, the original kit opens nothing to the website and AI API, and the patched one opens exactly what is intended.

   Settings on wireguard-vm:
   ```text
   PLATFORM_SERVICES_JSON=[{"id":"website","endpoint":"10.109.0.10","protocol":"tcp","ports":[443],"sides":["red","blue"],"categories":["application","ai"],"staff":true},{"id":"ai-api","endpoint":"10.109.0.10","protocol":"tcp","ports":[8443],"sides":["red","blue"],"categories":["ai"],"staff":true}]
   ```
2. **Decide the AI Red rule** (NET's own open decision #1). The kit pairs AI Red with "AI targets" that do not exist (`CHANGE_ME`). The 9 October architecture, which Kris confirmed, says AI Red attacks the 18 applications, rate-limited at the gateway. With the patch, `AI_RED_TARGETS=applications` does exactly that. Leave it as `ai` only if the game rule changes.
3. **VLAN 109 for VM 101.** In Proxmox, add a NIC on vmbr1 with VLAN tag 109, address `10.109.0.10`. The OPNsense handoff's row "wireguard-vm → the website and the AI API" must allow `10.109.0.10` TCP 443 and 8443.

4. **Correct the VLAN sheet.** `JengaSec_VLAN_Ranges.pdf` (14 October) lists the AI API and scoring on Observability `10.109.0.30`. They run on `jengasec-vm` `10.109.0.10` with the website. Change that row (and `contracts/address-plan.md`) to "Observability (logs, Grafana)" and "Website, AI API, scoring (jengasec-vm)". Every other address on the sheet already matches this page.
5. **Venue Wi-Fi reaches the servers directly.** NET (14 October) has said the Wi-Fi is a `/24`, `10.105.0.0/24`. The sheet and `contracts/address-plan.md` both still say `/22` and need correcting. NET is also setting the Wi-Fi up so that it can reach the servers at Kindaruma without the VPN. That solves the bootstrap problem: participants can open the website and download their WireGuard profile before they have one. Three things to agree with NET while they set it up:
   - **Only the website, port 443.** Allow `10.105.0.0/24` to reach `10.109.0.10` TCP 443, plus ping if wanted. Do not open the AI API, the database, SSH or the applications on `10.108.0.0/24` to the Wi-Fi. The applications especially must stay VPN-only: scoring and OBS attribution identify a team by its WireGuard address, so a hit from `10.105.x.x` is `unknown` and cannot be scored.
   - **Return path.** Replies to `10.105.0.0/24` must go back the way the request came. If the Wi-Fi reaches VM 101 on `10.109.0.10`, uncomment the `10.105.0.0/24 via 10.109.0.1` route in §4. If it reaches VM 101 on `192.168.40.11` instead, the replies use the default gateway `192.168.40.1`, which must know that `10.105.0.0/24` lives behind OPNsense. Either way, check with `ip route get 10.105.0.20`.
   - **VM 101's firewall.** Already done: `firewall_rules_venue` opens 80/443, and only those, to `10.105.0.0/24` (§5).

6. **Load the event data, with turnout, not the full house.** `scripts/bootstrap_event.py` accepts only 18 / 54 / 3 / 6 teams and exactly 3 Red teams per app; the roster has 7 App Blue, 20 App Red, 6 AI Blue and 3 AI Red, so it refuses to load and no peer is ever made. Apply `docs/net-bootstrap-turnout.patch`:
   - It loads the teams the CSVs name.
   - It allows up to 3 Red teams per app and 2 per AI target.
   - Each App Red team must have exactly one app; each AI Red team has one or two AI targets.
   - `STRICT_TEAM_COUNTS=1` restores the old rule.

   The CSVs come from the website, never by hand: `jengasec-manage export_range --competition <id> --out <dir>` writes `net-targets.csv`, `net-assignments.csv`, `net-infrastructure-targets.csv` and `net-access-policies.csv`. Copy them into `config/csv-templates/` without the `net-` prefix, then run `jengasecctl.sh bootstrap`.

   Each AI Blue team's target is the AI API (`10.109.0.10:8443`), so AI Blue and its paired AI Red teams reach it through the kit's ordinary rules.

   Tested: the website's export of a turnout-sized event passes the patched bootstrap's dry run, which the original rejects. The database-writing path also ran against a stand-in database.
7. **Registration → VPN.** The website does not yet call the control plane's `POST /v1/participants` (`jengasec-control-plane.service`, `127.0.0.1:8080` on VM 101), so no registration ever becomes a peer. That code is still to be written, against the control plane's API.

### OBS

- Point the AI sink at the machine network: `--url https://192.168.40.11:8443/api/v1/ingest` (`docs/ai-integration.md` §1). Use VM 101's certificate as `ai-ca.crt`.
- Settle the website feed mismatch (`docs/ai-integration.md`, mismatch #1) before turning on flow I2.
- Ask the website owner for read-only access to the `obs_*_v1` views (the contract is `contracts/observability-data-interface.md`).

### APP (k8s-blue VM 106)

- On VM 106: `MODE=deploy WEBSITE_IP=192.168.40.11 ./website-access.sh grant`. Copy `website-access/website.kubeconfig` to VM 101 (mode 600, outside Git and outside Django settings). Then run `website-access.sh verify`; it must report all PASS.
- If `ufw` is **not** active on VM 106, the script warns that port 6443 is open to the whole `192.168.40.0/24`. Restrict it with the Proxmox firewall.

### Database (VM 103)

- The test account in the VM sheet (`netadmin` / `testdb`) is shared by every VM, and its password is written in a PDF. **Do not use it for anything real.** Give each consumer its own role and database, and tighten `pg_hba.conf` from `192.168.40.0/24` to the exact client addresses:
  ```text
  host  jengasec_vpn  jengasec_worker   192.168.40.47/32  scram-sha-256   # wireguard-vm
  host  jengasec_vpn  jengasec_control  192.168.40.11/32  scram-sha-256   # NET control plane on VM 101
  ```
- The AI API keeps its own SQLite file on VM 101 (`/var/lib/jengasec-ai`). It does not need VM 103. If you prefer PostgreSQL, add a `jengasec_ai` database and role, and set `DATABASE_URL`.

## 7. Install on VM 101

The exact steps, start to finish, are in [`runbooks/platform-vm-install.md`](../runbooks/platform-vm-install.md). In short:

1. The database VM has `jengasec_web` (`setup-database-vm.sh`).
2. The website goes on with its Ansible (`make bootstrap`, `networking`, `security`, `database`, `platform`), with `vault_jengasec_db_url` and `vault_django_feed_token` in the vault.
3. The AI API goes on from the bundle (`sudo ./ai-api/deploy/install.sh`), with `WEBSITE_FEED_URL=https://192.168.40.11/api/feed/` and the same feed token.
4. Check: `platform-check.sh` on the VM, then `platform-probe.ps1` / `platform-check.sh probe` from elsewhere.

## 8. Check it: `ai-api/deploy/platform-check.sh`

| Run | Where | Proves |
|---|---|---|
| `sudo platform-check.sh` | VM 101 | Local services are up; it can reach the website database, k8s-blue 6443 and postgres-vm; replies to participants route through wireguard-vm; ufw has the 8443 rules |
| `platform-check.sh probe 192.168.40.11` | OBS VM 104 | OBS can reach the AI API's ingest and the website |
| `platform-check.sh probe 10.109.0.10` (Windows: `platform-probe.ps1 10.109.0.10`) | A laptop with a participant WireGuard profile | The website (and, with an AI team's profile, the AI API) is reachable through the VPN, as the patched worker intends |

Run the three in that order. A failure tells you which row of §3 is broken, and §6 tells you whose change fixes it.
