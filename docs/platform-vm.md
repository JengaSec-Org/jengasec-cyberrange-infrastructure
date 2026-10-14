# The platform VM: website, AI and scoring on one machine

**Owner:** AIC (Kris) · **Status:** proposed 2026-10-14 · **Supersedes** the separate AI VM in `docs/ai-integration.md`

**Built from:**
- the server VM sheet (`VM.pdf`)
- the database quick reference
- NET's kit `jengasec-update-2026-10-14-wifi` (address plan, OPNsense handoff, WireGuard worker)
- NET's `JengaSec_VLAN_Ranges.pdf` (14 October 2026): VLANs 101–109, the fixed VLAN 109 addresses, the VPN ranges
- the website's `docs/VENUE-HOSTING.md`
- the observability contracts on `main`

**Rule for this page:** where it gives an address that is not live yet, it says so. Nothing here changes a live system.

## 1. What runs on VM 101 (`jengasec-vm`)

| Service | Listens on | Reached by |
|---|---|---|
| nginx → website (Django, gunicorn `127.0.0.1:8000`) | **443** (TLS, internal CA) | Participants, staff and judges over WireGuard; Render stays the public copy |
| AI API (`ai-api/`, uvicorn) | **8443** (TLS) | AI Blue and AI Red teams over WireGuard; Vector on the OBS VM (`/ingest`); staff |
| AI marks timer (`jengasec-ai-marks.timer`) | — | Calls the website **on the same machine**: `http://127.0.0.1:8000/api/feed/` |
| Ollama (proposal scoring model) | `127.0.0.1:11434` only | The website, locally |
| NET's control plane and Ansible controller (already here, from NET's kit) | as NET's kit sets it | NET; check its port does not clash with 443, 8443 or 8000 |

Putting the AI API next to the website removes one network hop: the marks go to `127.0.0.1` and never cross a network. It also removes a VM, and a clash: NET has given `10.109.0.40` to wireguard-vm, which is the address the separate AI VM was going to use.

**Size it for the model.** The architecture's web VM is 4 vCPU / 6 GB. Ollama with a 4B model needs about 3–4 GB on its own (website `docs/VENUE-HOSTING.md`). With the website, the AI API and 324 people, give VM 101 at least **6 vCPU / 12 GB** (16 GB if you move to a 7–8B model).

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
| O1 | website | **Neon** (internet) | 5432 | The website's database. It is shared with Render (`VENUE-HOSTING.md`), so **an internet outage stops the venue site too** |
| O2 | website (deploy agent, APP) | k8s-blue VM 106 `192.168.40.59` | 6443 | Scoped kubeconfig made by `website-access.sh grant` on VM 106 (it opens 6443 to `192.168.40.11` only) |
| O3 | NET control plane | postgres-vm 103 `192.168.40.45` | 5432 | NET's VPN pipeline database (provisioning jobs, allocations) |
| O4 | website | Brevo (mail), S3 storage (internet) | 443 | As on Render |
| O5 | AI marks | website on the same VM | 8000 | `127.0.0.1`, no network |

### Between the other VMs (they matter to you, but someone else configures them)

| From | To | Port | What | Owner |
|---|---|---:|---|---|
| OBS 104 | website's database (Neon today) | 5432 | Read-only `obs_*_v1` attribution views | Website + OBS |
| wireguard-vm 102 `.47` | postgres-vm 103 `.45` | 5432 | Provisioning worker | NET |
| k8s-blue 106 | OBS 104 | 4317, 9090 | App logs and metrics | OBS / APP |
| gateway (OPNsense) | OBS 104 | 514, 2055 | Flow and IDS logs | NET / OBS |

**Where the attribution data lives.** OBS's contract reads the platform database's views. On the venue plan that database is Neon, on the internet. During an outage OBS keeps its last good snapshot (its contract says so), but new WireGuard allocations stop resolving. That leaves new traffic `unknown`, AI Red sees nothing new, and scoring loses ground truth. Decide this with the website and OBS owners before the event: either a local read replica on postgres-vm 103, or accept it as a known risk.

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

Do **not** add a default route on `ens19`. VM 101 keeps `192.168.40.1` as its way to the internet (Neon, mail, storage).

## 5. Firewall on VM 101

The gateway and wireguard-vm already filter. This is the last layer, and it is what stops a mistake elsewhere from exposing the database-backed admin pages:

```text
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    iif lo accept
    ip saddr 192.168.40.0/24 tcp dport 22 accept                          # I5 staff SSH
    ip saddr 192.168.40.60 tcp dport { 443, 8443 } accept                 # I1, I2 OBS (Vector and website feed)
    ip saddr { 10.60.0.0/14, 10.64.0.0/16 } tcp dport 443 accept          # I3 everyone over WireGuard
    ip saddr { 10.62.0.0/16, 10.64.0.0/16, 10.63.0.0/24 } tcp dport 8443 accept   # I4 AI teams and staff
    # ip saddr 10.105.0.0/24 tcp dport 443 accept                         # venue Wi-Fi -> website only (NET item 5)
    icmp type echo-request accept
  }
}
```

Save it as `/etc/nftables.conf`, starting with the line `flush ruleset`, then run `systemctl enable --now nftables`. The ruleset uses the same syntax as the one checked with `nft -c` on Debian 12 in `runbooks/ai-api-vm.md`. Re-check after any edit with `sudo nft -c -f /etc/nftables.conf`.

## 6. What the other owners must do

### NET: five items, without them no participant can reach VM 101

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
   - **VM 101's firewall.** Uncomment the `10.105.0.0/24 tcp dport 443` line in §5.

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

```bash
# AI API (no --bind: it must answer on 192.168.40.11 for OBS and on 10.109.0.10 for teams)
sudo ./ai-api/deploy/install.sh
sudo sed -i 's|^WEBSITE_FEED_URL=.*|WEBSITE_FEED_URL=http://127.0.0.1:8000/api/feed/|' /etc/jengasec-ai/ai-api.env
#   + WEBSITE_FEED_TOKEN (= the website's DJANGO_FEED_TOKEN), WEBSITE_COMPETITION, ENGAGEMENT_DAYS
sudo systemctl restart jengasec-ai-api
# Website: follow the website repo's docs/VENUE-HOSTING.md (gunicorn on 127.0.0.1:8000, nginx on 443)
# then check everything:
sudo ./ai-api/deploy/platform-check.sh
```

For the website itself, read the HTTPS trap in `VENUE-HOSTING.md` before the event. Without TLS and with `DJANGO_DEBUG=False`, nobody can log in at the venue.

## 8. Check it: `ai-api/deploy/platform-check.sh`

| Run | Where | Proves |
|---|---|---|
| `sudo platform-check.sh` | VM 101 | Local services are up; it can reach Neon, k8s-blue 6443 and postgres-vm; replies to participants route through wireguard-vm; the firewall is loaded |
| `platform-check.sh probe 192.168.40.11` | OBS VM 104 | OBS can reach the AI API's ingest and the website |
| `platform-check.sh probe 10.109.0.10` | A laptop with a participant WireGuard profile | The website (and, with an AI team's profile, the AI API) is reachable through the VPN, as the patched worker intends |

Run the three in that order. A failure tells you which row of §3 is broken, and §6 tells you whose change fixes it.
