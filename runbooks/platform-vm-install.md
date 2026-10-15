# Install the platform VM 101 (website + AI API + scoring), step by step

**Owner:** AIC · **VM:** 101 `jengasec-vm`, `192.168.40.11`, Debian 12, 4 vCPU / 8 GB · **Design:** [`docs/platform-vm.md`](../docs/platform-vm.md)

Three repositories, and only one of them is cloned on the VM:

| What | Repository | How it reaches the VM |
|---|---|---|
| Website's Ansible | `jengasec-website-infrastructure` | **Cloned on the VM.** The VM is its own Ansible control node (`inventories/v1`). |
| The website itself | `jengasec-competition-platform` | Ansible's `make platform` checks it out into `/opt/jengasec`. You do nothing. |
| AI API and scoring | `jengasec-cyberrange-infrastructure` (this repo) | **Not cloned.** One tarball, `out/jengasec-ai-api.tar.gz`, built on your PC and copied with `scp`. |

The website's database is the database VM `192.168.40.45`, not Neon, because the campus blocks outgoing 5432. `scripts/cutover/` in the website-infrastructure repo has the steps.

**You only need Windows.** Linux runs on the VMs alone. Windows 10/11 already has `ssh`, `scp` and `curl.exe`, and Git for Windows gives you Git Bash. If you have no SSH login on a VM yet, use its **Console** in the Proxmox web interface.

Do the steps in order. Steps 1–8 work **today** on `192.168.40.11`. Step 9 waits for NET's VLAN 109.

---

## 1. Database VM (`192.168.40.45`): the website's database

Done once with `scripts/cutover/setup-database-vm.sh` (website-infrastructure). It is safe to run again. A good run prints, among others:

```text
==> Role jengasec_web already exists ...      (or "Created role", plus the database URL ONCE)
==> pg_hba.conf already allows 192.168.40.11
==> Listening on: 192.168.40.45,localhost
==> Hourly backups of jengasec_web to /var/backups/jengasec_web ...
```

- **No "Hourly backups" line?** The copy on the VM is older than the one in the repository. Copy the current one over and run it again.
- **Lost the database URL?** `sudo bash setup-database-vm.sh --new-password` prints a new one, once. Anything already using the old password stops working until you update it.
- **`could not change directory to "/home/netadmin"`** is harmless. The `postgres` user cannot enter your home folder. Run it from `/tmp` to silence it:
  ```bash
  cd /tmp && sudo bash ~/setup-database-vm.sh
  ```

## 2. Website VM: the website, with Ansible

On the VM (`ssh netadmin@192.168.40.11`), clone `jengasec-website-infrastructure` and follow its `docs/deployment-guide.md`, "v1" section. In order, with `export INVENTORY=inventories/v1 ANSIBLE_ARGS=-K`:
1. `make bootstrap`
2. `make networking` (keep the Proxmox console open)
3. `make security`
4. `make database`
5. `make platform`

Its vault file is `inventories/v1/vault.yml`.

In the vault (`ansible-vault edit inventories/v1/vault.yml`), set at least these:

```yaml
vault_jengasec_db_url: "postgresql://jengasec_web:<password>@192.168.40.45:5432/jengasec_web?sslmode=prefer"
vault_django_feed_token: "<new: openssl rand -hex 32>"     # the AI API pushes its marks with this
```

Then deploy:

```bash
make platform INVENTORY=inventories/v1 ANSIBLE_ARGS="-K -e @inventories/v1/vault.yml"
curl -sk -o /dev/null -w '%{http_code}\n' https://192.168.40.11/healthz/     # 200; keep the trailing slash (without it: 301)
```

The website-infrastructure repo has uncommitted edits made for this layout: the feed token, the AI API's 8443 firewall rules, and the Wi-Fi as a `/24`. Get them onto the VM either way:
- Commit and push them, then `git pull` on the VM.
- Or copy the changed files with `scp` from your PC. `git status` on your PC lists them.

## 3. On your PC (Windows): build and copy the AI bundle

In PowerShell, from the root of this repository:

```powershell
& "C:\Program Files\Git\bin\bash.exe" ai-api/deploy/make-bundle.sh
scp out\jengasec-ai-api.tar.gz netadmin@192.168.40.11:~/
```

The bundle step refuses to pack a script with Windows line endings (CRLF), which would fail on Debian. If it complains, run `git config core.autocrlf false`, then check the files out again: `git checkout -- ai-api scenarios`.

## 4. Website VM: install the AI API

```bash
mkdir -p ~/jengasec-ai && tar -xzf ~/jengasec-ai-api.tar.gz -C ~/jengasec-ai
cd ~/jengasec-ai
sudo ./ai-api/deploy/install.sh          # no --bind on the platform VM
sudo ./ai-api/deploy/smoke.sh            # must end "0 failed"
```

| Path | What |
|---|---|
| `/etc/jengasec-ai/ai-api.env` | Settings, `INGEST_TOKEN`, `ADMIN_TOKEN` |
| `/etc/jengasec-ai/team-tokens.txt` | One token per AI team |
| `/etc/jengasec-ai/tls/server.crt` | The AI API's own certificate (8443), valid for `192.168.40.11` and `10.109.0.10` |

None of these go into Git or chat. The AI API uses only 8443. It does not touch nginx, gunicorn, ufw or the website's certificate.

## 5. Connect the AI marks to the website

```bash
sudo nano /etc/jengasec-ai/ai-api.env
```

```ini
# Through nginx: gunicorn is a unix socket, and the website's certificate names 192.168.40.11.
# The website's CA is in the system trust store (Ansible's certificates role), so no CA file is needed.
WEBSITE_FEED_URL=https://192.168.40.11/api/feed/
WEBSITE_FEED_TOKEN=<the same value as vault_django_feed_token>
WEBSITE_CA_FILE=
# Empty = the website's open / in-progress competition; or its numeric id from the admin
WEBSITE_COMPETITION=
# The three engagement days, UTC
ENGAGEMENT_DAYS=1=YYYY-MM-DD,2=YYYY-MM-DD,3=YYYY-MM-DD
```

```bash
sudo systemctl restart jengasec-ai-api
```

Then load the real AI teams and issue their tokens: `runbooks/ai-api-vm.md`, "Real teams".

## 6. Firewall: nothing to do by hand

The website's Ansible owns the firewall (ufw). Do not add nftables rules beside it.
- `firewall_rules_venue` opens 443 to the Wi-Fi and every WireGuard range.
- `firewall_rules_ai_api` in `host_vars/jengasec.yml` opens 8443 to observability, AI Blue, AI Red and staff only.

```bash
sudo ufw status numbered | grep -E '443|8443'
```

If 8443 is missing, the edited `host_vars/jengasec.yml` has not reached the VM yet. Run `make networking INVENTORY=inventories/v1 ...` after it has (see the website-infrastructure runbook first: it can drop SSH).

## 7. Ollama for proposal scoring (optional)

```bash
curl -fsSL https://ollama.com/install.sh | sh
sudo systemctl enable --now ollama
ollama pull llama3          # the model group_vars/web names (ollama_model)
ss -ltn | grep 11434        # must show 127.0.0.1:11434 only
```

8 GB is shared with everything else on this VM. An 8B model needs about 5 GB while it scores, so run scoring outside the busy hours of the event.

## 8. Check everything

On the VM:

```bash
sudo ~/jengasec-ai/ai-api/deploy/smoke.sh
sudo ~/jengasec-ai/ai-api/deploy/platform-check.sh
```

Every line should be `ok`, except these warnings until the other owners finish:
- "10.109.0.10 is not configured" (NET)
- k8s-blue, until APP runs `website-access.sh grant`
- OBS, until their VM is up

From your PC, in PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File ai-api\deploy\platform-probe.ps1 192.168.40.11
```

Then open `https://192.168.40.11/` and sign in as a test competitor.

Send OBS the two things their Vector sink needs, and nothing else:
- `INGEST_TOKEN` from `/etc/jengasec-ai/ai-api.env`, over a private channel
- `/etc/jengasec-ai/tls/server.crt`

Then ask them to run this from their VM:

```bash
platform-check.sh probe 192.168.40.11
```

## 9. When NET makes VLAN 109 live

1. In Proxmox (NET, or whoever has Proxmox access): add a network card to VM 101 on `vmbr1`, VLAN tag 109.
2. On the VM, add it with the return routes in `docs/platform-vm.md` §4, then check:
   ```bash
   sudo ~/jengasec-ai/ai-api/deploy/platform-check.sh
   ```
   The website's `networking` role writes `/etc/network/interfaces`. Put the second card in its host_vars too, or the next `make networking` removes it.
3. From a Windows laptop on WireGuard, run the probe below. Repeat from a laptop on the Wi-Fi alone: port 443 should be open there, and 8443 should not.
   ```powershell
   powershell -ExecutionPolicy Bypass -File ai-api\deploy\platform-probe.ps1 10.109.0.10
   ```

## Before the competition starts

The sandbox loads the scripted scenarios so you can try things. Switch it off so only real telemetry is scored:

```bash
sudo sed -i 's/^SANDBOX_SEED=.*/SANDBOX_SEED=0/' /etc/jengasec-ai/ai-api.env
cd ~/jengasec-ai && sudo ./ai-api/deploy/install.sh --reset-db
```

## Updating later

| Part | How |
|---|---|
| AI API | Rebuild the bundle on your PC (step 3), `scp` it, untar it over `~/jengasec-ai`, then rerun `sudo ./ai-api/deploy/install.sh`. Tokens, secrets and data are kept. |
| Website | `git pull` in website-infrastructure on the VM, then `make platform INVENTORY=inventories/v1 ...` again |
