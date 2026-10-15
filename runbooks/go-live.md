# Go-live checklist: website, AI, VPN and apps

**Owner:** AIC (Kris) · **Status on 15 October 2026:** website and AI API run on VM 101. No participant can connect to the VPN yet: `participants` = 0, `targets` = 0, `provisioning_jobs` = 0 on postgres-vm.

**Progress, 15 October, midday:**

| Item | State |
|---|---|
| Website on VM 101 | Healthy (`/healthz/` 200). Feed token set (A1). |
| AI API on VM 101 | Running. Smoke test passes. Marks timer still exits 1: read `sudo journalctl -u jengasec-ai-marks -n 15` |
| VPN API (control plane) | Healthy, reaches its database |
| Diana's bootstrap | **Turnout patch applied on VM 101**: original kept as `scripts/bootstrap_event.py.orig-20261015`. Dry run passes on a 7/20/6/3 event. Her CSVs are still empty (C3). |
| wireguard-vm | WireGuard, worker and forwarding up. **No route to `10.108.x` / `10.109.x`**: VLAN trunk still to come (E1) |
| k8s-blue | 18 cell namespaces and MetalLB pool ready; no app deployed yet. MetalLB announces on `ens19`, which does not exist: NET to say whether `enp6s19` or `enp6s20` is VLAN 108 (F1) |
| Deploy agent | Installer staged on k8s-blue in `~/deploy-agent`; the website accepts its token |
| Website code (not yet pushed) | VPN registration page, NET CSV export, agent installer, `/pending/` no longer blocked by one unready team. All 449 website tests pass. |

**How a participant gets in, end to end.** Every phase below exists to make one link of this chain work:

```text
registers on the website ──► website approves the team
        │                              │
        │ (B) website calls the VPN API: POST /v1/participants, with their team code
        ▼                              ▼
  VPN API on VM 101 (jengasec-control-plane, 127.0.0.1:8080) writes a job into postgres-vm
        ▼
  worker on wireguard-vm adds the peer and the per-team firewall
  (only if the event data, phase C, says what that team may reach)
        ▼
  participant downloads the profile from the website, connects,
  and reaches only their app (10.108.0.x) or the AI API (10.109.0.10:8443)
```

Tick each box when its check passes. Never skip a check: each phase depends on the one before.

---

## A. VM 101 healthy (you, today)

- [ ] **A1. Website feed token.** Copy the six edited website-infrastructure files to the VM. Add `vault_django_feed_token` to the vault, with the same value as `WEBSITE_FEED_TOKEN` in `/etc/jengasec-ai/ai-api.env`. Then run `make platform ...`.
  - **Check:** `sudo ~/jengasec-ai/ai-api/deploy/smoke.sh` ends with "the website accepted them" and `0 failed`.
- [ ] **A2. Platform check.** Run `sudo ~/jengasec-ai/ai-api/deploy/platform-check.sh`.
  - **Check:** `0 failed`. The only expected warning is VLAN 109.
- [ ] **A3. Website backup.** Read `sudo journalctl -u jengasec-backup -n 30` and fix what it says.
  - **Check:** `systemctl status jengasec-backup` is not `failed`.

## B. Website talks to the VPN (AIC writes the code; you deploy it)

- [ ] **B1. Get the VPN API's code to AIC.** On VM 101, run `systemctl cat jengasec-control-plane`, then copy the file named in `ExecStart` to your PC with `scp`.
  - The website code is written against it: register participants, keys, approval, revocation, and the profile shown on the team page.
- [ ] **B2. Review the website change.** It is already written: `export_range` now writes NET's four CSVs; 21 range tests pass. Then commit and push `jengasec-competition-platform`. Ansible deploys from GitHub.
- [ ] **B3. Deploy.** Run `make platform ...` on VM 101.
  - **Check:** `sudo jengasec-manage export_range --competition <id> --out /tmp/range-export` writes `net-targets.csv`, `net-assignments.csv`, `net-infrastructure-targets.csv` and `net-access-policies.csv`.

## C. Event data loaded (you + Diana)

- [ ] **C1. Diana applies `docs/net-bootstrap-turnout.patch`** to `scripts/bootstrap_event.py`. Without it, the bootstrap refuses any event smaller than 18/54/3/6.
- [ ] **C2. Assign Red teams on the website.** Run `sudo jengasec-manage assign_targets --dry-run`, check the output, then run it with `--confirm --activate`. Only active assignments are exported.
- [ ] **C3. Export and hand over.**
  1. Run `export_range` (B3), then give the four `net-*.csv` files to Diana.
  2. She copies them into `config/csv-templates/` without the `net-` prefix.
  3. She runs `jengasecctl.sh bootstrap`: dry run first, then apply.
  - **Check, on postgres-vm:** `sudo -u postgres psql -d jengasec -c "select count(*) from targets;"` shows the number of Blue teams plus 1 (the platform).
- [ ] **C4. App ports.** The CSVs default to `80,443` for the apps. Confirm with the app team which ports the apps answer on at `10.108.0.x`, and set `NET_APP_PORTS` on the website if they differ.

## D. One test participant, end to end (you + Diana)

- [ ] **D1.** Register a test account on the website in an approved, assigned Red team.
  - **Check:** it appears in `participants` on postgres-vm, and a `provisioning_jobs` row reaches `succeeded`. If the row says `failed`, send Diana its `result_json`.
- [ ] **D2.** Download the profile from the website and connect from a laptop on the venue Wi-Fi.
  - **Check:** `sudo wg show` on wireguard-vm lists the peer with a recent handshake.
- [ ] **D3.** From that laptop:
  - its assigned app answers;
  - another team's app does not;
  - `platform-probe.ps1 10.109.0.10` shows 443 open (Wi-Fi) and 8443 closed (not an AI team).
- [ ] **D4.** Repeat with an AI Blue test account.
  - **Check:** `https://10.109.0.10:8443/healthz` answers over the VPN.

## E. Network pieces still open (Diana / NET)

- [ ] **E1.** VLAN 109 network card on VM 101 (`10.109.0.10`), with the return routes from `docs/platform-vm.md` §4. Without it, nothing over the VPN reaches VM 101: the AI API for AI teams, and the website for staff.
- [ ] **E2.** Venue Wi-Fi → `10.109.0.10:443` allowed at OPNsense, so people can reach the website before they have a VPN.
- [ ] **E3.** Update the VLAN sheet: Wi-Fi is a `/24`, and the AI API and scoring run on jengasec-vm.

`docs/net-platform-services.patch` (the earlier firewall patch) is **no longer required** for the AI teams. Their targets are now the AI API, so the kit provisions and allows them by its own rules. Keep it only if participants must reach the website over the VPN as well as the Wi-Fi.

## F. The applications (app team, on k8s-blue VM 106)

- [ ] **F1.** Each Blue team's app is deployed and answers at its reserved address (`10.108.0.11`–`.19` for ENT-A, `.21`–`.29` for ENT-B).
  - **Check, on VM 106:** `kubectl get svc -A -o wide | grep 10.108.0.` shows one address per deployed app.
- [ ] **F2.** The website can deploy to k8s-blue: `website-access.sh grant` was run on VM 106.
  - **Check:** `platform-check.sh` shows O2 ok and the kubeconfig check passing.
- [ ] **F3.** Observability collects from the apps and posts to the AI API.
  - **Check:** on OBS, run `platform-check.sh probe 192.168.40.11`. The AI API's event count grows when someone browses an app.

## Before the first engagement day

- [ ] Switch off the practice data: `SANDBOX_SEED=0`, then `install.sh --reset-db` (`runbooks/platform-vm-install.md`).
- [ ] Load the real AI teams and send each team its token (`runbooks/ai-api-vm.md`, "Real teams").
- [ ] Set `ENGAGEMENT_DAYS` in `/etc/jengasec-ai/ai-api.env`.
