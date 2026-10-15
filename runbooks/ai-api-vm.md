# Runbook: the AI API on a Debian 12 VM

**Owner:** AIC · **Where it runs at the event:** the platform VM 101 next to the website (`192.168.40.11` for VMs, `10.109.0.10` for teams once VLAN 109 is live; [`docs/platform-vm.md`](../docs/platform-vm.md)) · **How it connects:** [`docs/ai-integration.md`](../docs/ai-integration.md) · **Code:** `ai-api/`

Use this runbook to try the AI API on any Debian 12 VM now, and to install it on the obs VM later. The steps are the same in both cases.

## 1. Get the code onto the VM

On your machine, from the repository. This works with uncommitted changes:

```bash
./ai-api/deploy/make-bundle.sh                 # -> out/jengasec-ai-api.tar.gz
scp out/jengasec-ai-api.tar.gz <you>@<vm-ip>:~
```

Or, once the work is pushed, run `git clone` on the VM instead.

## 2. Install

On the VM:

```bash
mkdir -p ~/jengasec-ai && tar -xzf ~/jengasec-ai-api.tar.gz -C ~/jengasec-ai
cd ~/jengasec-ai
sudo ./ai-api/deploy/install.sh               # HTTPS on :8443; --no-tls for plain HTTP on :8000
```

The VM needs internet access for `apt` and `pip` the first time. The installer is safe to run again: it refreshes the code and keeps the secrets, tokens, certificate and database.

| What | Where |
|---|---|
| Service | `jengasec-ai-api.service`, running as user `jengasec-ai` |
| Settings and secrets (ingest and admin tokens) | `/etc/jengasec-ai/ai-api.env` |
| One token per AI team, plain text, readable by root only | `/etc/jengasec-ai/team-tokens.txt` |
| Token hashes, which are all the service keeps | `/etc/jengasec-ai/tokens.yaml` |
| Self-signed certificate (replace with the internal CA's, ADR 0003) | `/etc/jengasec-ai/tls/` |
| Database (SQLite; set `DATABASE_URL` for PostgreSQL) | `/var/lib/jengasec-ai/ai-api.db` |
| Code, contracts, scenario data and venv | `/opt/jengasec-ai/` |

## 3. Check it

```bash
sudo /opt/jengasec-ai/repo/ai-api/deploy/smoke.sh
```

This runs every done-when check in Architecture §15.3:
- AI Blue reads events across both enterprises.
- AI Red RI-01 sees only its own traffic.
- An ingested live event comes back labelled `red-app`.
- The SSE stream works.
- `block-ip` is recorded but not applied.
- AI Red cannot act.
- A decision is stored.
- The kill switch halts actions.
- The judges' export shows precision and recall.

## 4. See how it works: the guided tour

```bash
sudo /opt/jengasec-ai/repo/ai-api/deploy/tour.sh
```

The tour takes nine steps, pausing for Enter between each:
1. What AI Blue reads.
2. What AI Red reads (its own traffic only).
3. The assets.
4. The baseline alerts.
5. A live event posted to `/ingest` arriving on the stream.
6. Shadow actions, including a deliberately wrong one, and AI Red being refused.
7. A decision.
8. The example agent.
9. What the judges get.

You can also browse `https://<vm-ip>:8443/docs`, an interactive page for every endpoint. Click **Authorize** and paste a team token.

## 4b. Try it as an AI team, from another machine

Copy `/etc/jengasec-ai/tls/server.crt` from the VM and take one token from `team-tokens.txt`. Then:

```bash
python3 ai-api/examples/blue_agent.py --api https://<vm-ip>:8443/api/v1 --token <AI-01 token> --cacert server.crt --once
python3 ai-api/examples/red_feed.py   --api https://<vm-ip>:8443/api/v1 --token <RI-01 token> --cacert server.crt
```

The example Blue agent groups failed logins by team across all apps. It flags `JS26-R-005` (s01) and the low-and-slow `RI-01` (s04), which the platform's per-address baseline misses. `red_feed.py` shows RI-01 that it triggered no baseline alert.

The curl and Python quickstart is in `ai-api/README.md`.

## 5. Day-to-day

| Task | Command |
|---|---|
| Status and logs (one JSON line per request) | `systemctl status jengasec-ai-api` · `journalctl -u jengasec-ai-api -f` |
| Re-issue one team's token (the old one stops working) | `sudo /opt/jengasec-ai/venv/bin/python /opt/jengasec-ai/repo/ai-api/scripts/issue-tokens.py --teams /opt/jengasec-ai/repo/scripts/ai-teams.yaml --out /etc/jengasec-ai/tokens.yaml --team RI-03 --print-to /root/ri-03.txt && sudo systemctl restart jengasec-ai-api` |
| Kill switch (halts every AI action in one step; SEC-12 target is under 10 s) | `curl -sk -X POST -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' -d '{"on":true}' https://127.0.0.1:8443/api/v1/admin/kill-switch` |
| Overview of teams, tokens and activity | `curl -sk -H "Authorization: Bearer $ADMIN_TOKEN" https://127.0.0.1:8443/api/v1/admin/teams` |
| Judges' export, one file per team (AIC-20) | `curl -sk -H "Authorization: Bearer $ADMIN_TOKEN" https://127.0.0.1:8443/api/v1/admin/export/AI-01 > AI-01.json` |
| Fresh sandbox (clears decisions and actions too) | `sudo ./ai-api/deploy/install.sh --reset-db` |
| Live range: stop serving scripted data | set `SANDBOX_SEED=0` in `ai-api.env`, then `--reset-db` before day one |

`ADMIN_TOKEN` and `INGEST_TOKEN` are in `/etc/jengasec-ai/ai-api.env`. Load them with `sudo bash -c 'set -a; . /etc/jengasec-ai/ai-api.env; …'`, or copy them out.

## 6. The competition VM

The steps are the same as for a test VM, with these differences:

```bash
sudo ./ai-api/deploy/install.sh      # on the platform VM: listen on both addresses; the firewall decides who gets in
```

**Host firewall.** On the platform VM the website's Ansible owns the firewall (ufw, `docs/platform-vm.md` §5): do **not** load this ruleset there. The ruleset below is for a dedicated AI VM only:

```bash
sudo apt-get install -y nftables
sudo tee /etc/nftables.conf >/dev/null <<'NFT'
flush ruleset
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    iif lo accept
    tcp dport 22 ip saddr 10.102.0.0/24 accept
    tcp dport 8443 ip saddr { 10.109.0.30, 10.62.0.0/16, 10.64.0.0/16, 10.102.0.0/24, 10.63.0.0/24 } accept
    icmp type echo-request accept
  }
}
NFT
sudo systemctl enable --now nftables
```

**Go-live checklist** (the day before the first engagement day):

1. Import the real teams from the website export, then issue their tokens:
   ```bash
   python3 ai-api/scripts/import-ai-teams.py allocation.csv
   sudo ./ai-api/deploy/install.sh
   sudo rm /etc/jengasec-ai/tokens.yaml
   sudo ./ai-api/deploy/install.sh     # issues a new token for every team
   ```
   Hand each team only its own line of `/etc/jengasec-ai/team-tokens.txt`.
2. In `/etc/jengasec-ai/ai-api.env`, set:
   - `SANDBOX_SEED=0`
   - `WEBSITE_FEED_URL=https://192.168.40.11/api/feed/` (the website on the same VM, through nginx), `WEBSITE_FEED_TOKEN` (= the website vault's `vault_django_feed_token`) and `WEBSITE_COMPETITION`
   - `ENGAGEMENT_DAYS=1=…,2=…,3=…`
3. Run `sudo ./ai-api/deploy/install.sh --reset-db`. This empties the database: no scenario data, decisions or actions remain.
4. Give OBS the ingest token and the certificate (`docs/ai-integration.md` §1). After they reload Vector, a request to any test app should appear in `GET /telemetry/events` within seconds, with its `team_label`.
5. Run `sudo /opt/jengasec-ai/repo/ai-api/deploy/smoke.sh` (must report `0 failed`), then `sudo /opt/jengasec-ai/repo/ai-api/deploy/platform-check.sh` (docs/platform-vm.md §8).
6. Check the marks timer with `systemctl list-timers jengasec-ai-marks.timer`, and its last run with `journalctl -u jengasec-ai-marks -n 20`.

## 7. Connecting Observability and the website

- **Observability → this VM:** OBS renders and loads `ai-api/deploy/vector-ai-sink.yaml`. Exact steps are in `docs/ai-integration.md` §1. While the VM is down, Vector buffers up to 1 GB, and replaying its spool later is safe.
- **This VM → website:** set the four `WEBSITE_*` / `ENGAGEMENT_DAYS` values above. `jengasec-ai-marks.timer` pushes every 5 minutes.

  To push now, or to see the marks first:
  ```bash
  sudo bash -c 'set -a; . /etc/jengasec-ai/ai-api.env; set +a; /opt/jengasec-ai/venv/bin/python /opt/jengasec-ai/repo/ai-api/scripts/publish-marks.py --api https://127.0.0.1:8443/api/v1 --cacert /etc/jengasec-ai/tls/server.crt --preview'
  ```
  Drop `--preview` to send them.

## 8. Rehearse the OBS link on a laptop (no VMs)

From the repository, with Docker running:

```bash
# 1. an AI API that only receives what Vector sends
cd ai-api && INGEST_TOKEN=rehearsal-ingest ADMIN_TOKEN=dev SANDBOX_SEED=0 uvicorn app.main:app --host 0.0.0.0 --port 8766 &
cd ..
# 2. OBS's dev stack plus the AI sink
python3 ai-api/deploy/render-vector-ai-sink.py --url http://host.docker.internal:8766/api/v1/ingest \
    --secret-file /etc/vector/ai/ai-secret.json --out out/obs-ai-link/vector-ai-sink.yaml
printf '{"ingest_token":"rehearsal-ingest"}' > out/obs-ai-link/ai-secret.json
python3 scripts/prepare-observability-runtime.py --runtime-dir observability/.runtime \
    --access-principals observability/tests/fixtures/access/access-principals.csv
docker compose -f observability/compose.yaml -f ai-api/deploy/obs-ai-link.compose.yaml up -d --build
# 3. make OBS's fixtures emit, then look
curl "http://127.0.0.1:8080/emit?marker=x"; curl "http://127.0.0.1:8081/emit?marker=y"
curl -s localhost:9598/metrics | grep 'component_id="ai_api_ingest"' | grep sent_events_total
```

On Windows Git Bash, prefix the render command with `MSYS_NO_PATHCONV=1`, or the `/etc/...` paths get rewritten.

## If something is wrong

| Symptom | Fix |
|---|---|
| `service did not come up` | `journalctl -u jengasec-ai-api -n 50`. Usually a bad edit in `ai-api.env`, or the port is in use (`ss -ltnp \| grep 8443`) |
| 401 for a team | Is the team `enabled: true` in `scripts/ai-teams.yaml`, and was its token issued after that? |
| Clients reject the certificate | Use `--cacert server.crt`. The certificate lists the VM's addresses at install time; if the IP changed, delete `/etc/jengasec-ai/tls/*` and run the installer again |
| No events | `SANDBOX_SEED=1` loads `scenarios/*/events.jsonl` at start. On the live range, check that Vector is posting: its `ai_api_ingest` sink metrics, and `ingest_rejected` in this journal |
| AI Red sees nothing, recall stays 0 | Events arrive with `team_label: unknown`, so OBS's attribution is stale (its refresh alert should have fired). This VM never guesses identities |
| Website rejects marks (`202`, "no team matched") | `scripts/ai-teams.yaml` is stale: re-import from the website's `allocation.csv` and re-run the installer |
| Marks timer does nothing | `WEBSITE_FEED_URL` or `WEBSITE_FEED_TOKEN` is empty, or no day in `ENGAGEMENT_DAYS` has started yet (`journalctl -u jengasec-ai-marks`) |
