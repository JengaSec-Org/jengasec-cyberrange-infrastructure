# The AI VM: how it talks to Observability, the website and the teams

**Owner:** AIC · **Status:** proposed 2026-10-14 · **Contract:** [`contracts/ai-api/openapi.yaml`](../contracts/ai-api/openapi.yaml) v1.3

> **Update 2026-10-14 (later the same day):** the AI API now runs **on the platform VM 101, next to the website**, not on a VM of its own. NET has given `10.109.0.40` to wireguard-vm. The addresses below change accordingly:
> - **AI teams** reach `10.109.0.10:8443`.
> - **OBS's Vector** reaches `192.168.40.11:8443`.
> - **The marks** go to the website on `127.0.0.1`.
>
> The flows, the sink and the mismatches are unchanged. The full layout, routing and firewall are in [`docs/platform-vm.md`](platform-vm.md), and that page wins where they differ.

The AI API runs on its **own VM** (not on the OBS VM as Competition Architecture §15.2 first drew it). It hosts no AI: AI teams run their agents on their own machines. The VM holds four things:
- the telemetry the AI teams read,
- the shadow-mode action gateway,
- the decision log,
- the ground-truth scoring that turns all of that into the website's AI marks.

## Where it sits

| Item | Value |
|---|---|
| VM | Debian 12, 2 vCPU / 4 GB / 40 GB is plenty (SQLite; PostgreSQL 16 optional through `DATABASE_URL`) |
| Network | One leg on the **Functions VLAN 109**. Proposed address **`10.109.0.40`**, the next free row in `contracts/address-plan.md` (*Function addresses*). NET to confirm |
| Listens on | `https://192.168.40.11:8443` only (`install.sh --bind 10.109.0.40`). TLS from the range's internal CA, or the self-signed certificate the installer makes |
| Name | `ai.range.<domain>` → `10.109.0.40` (the address plan already reserves the name) |
| Inbound | Only the four flows below. SSH 22 from the Staff VLAN for administration |
| Outbound | Only the website feed, plus `apt`/`pip` while it is being built. No route to applications, no internet during the rounds |

## The flows

```
                AI Blue laptops 10.62.n.x ─┐          ┌─ AI Red laptops 10.64.n.x
                                           │ WireGuard│
                                           ▼          ▼
 k3s-blue ──OTLP 4317──▶ ┌──────────┐   ┌────────── gateway (NET) ──────────┐
 gateway ─syslog/NetFlow▶│  OBS VM  │   │ allows 10.62/10.64 → .40:8443 only │
                         │10.109.0.30│  └──────────────────┬────────────────┘
                         │  Vector   │──(1) HTTPS 8443 ───▶ ┌──────────────┐ ──(3) HTTPS 443──▶ ┌──────────────┐
                         └──────────┘   POST /ingest NDJSON │   AI VM      │  POST /api/feed     │   Website    │
                                                            │ 10.109.0.40  │  AI marks per team  │ 10.109.0.10  │
                       staff 10.102/10.63 ──(4) 8443───────▶│  AI API      │                     │ (Render+on-  │
                                         kill switch, export└──────────────┘                     │  server hub) │
                                                                ▲ (2) team tokens                └──────────────┘
                                                                └── AI teams' agents: events, stream, alerts, decisions, actions
```

| # | From | To | Port | What | Authentication |
|---|---|---|---:|---|---|
| 1 | OBS VM `10.109.0.30` (Vector) | AI VM `10.109.0.40` | TCP 8443 | `POST /api/v1/ingest`: every normalized telemetry v2 event, as NDJSON | Bearer `INGEST_TOKEN`, TLS verified against the AI VM's CA |
| 2 | AI Blue `10.62.0.0/16`, AI Red `10.64.0.0/16` (WireGuard, via the gateway) | AI VM | TCP 8443 | The AI API: events, stream, assets, alerts; decisions and actions (AI Blue only) | One bearer token per team (`scripts/ai-teams.yaml`), rate-limited |
| 3 | AI VM | Website `10.109.0.10` | TCP 443 | `POST /api/feed`: proposed AI marks (AI Blue `precision` `recall` `correlation` `decisions` `safety`; AI Red `missed` `false` `breadth`) every 5 minutes, idempotent per criterion and day | `X-Feed-Token` = the website's `DJANGO_FEED_TOKEN` |
| 4 | Staff `10.102.0.0/24`, `10.63.0.0/24` | AI VM | TCP 8443 (+22) | Kill switch, team overview, judges' export (`/api/v1/admin/...`) | Bearer `ADMIN_TOKEN` |

Nothing else talks to the AI VM.
- Judges read the AI results on the website (flow 3) or in the export a staff member hands them.
- The website never reads raw telemetry (Architecture §8.2).
- The AI VM never talks to an application or to the platform database.

## (1) Observability → AI VM

OBS's Vector already writes the AI hand-off as a file spool (`/var/lib/vector/ai-handoff/`) and leaves "the AI network endpoint, transport and authentication" to AIC (`runbooks/observability.md`). This is that endpoint. OBS adds one Vector sink, next to the spool and fed by the same inputs:

1. Render it: `python3 ai-api/deploy/render-vector-ai-sink.py --url https://192.168.40.11:8443/api/v1/ingest --ca-file /etc/vector/ai/ai-ca.crt --secret-file /etc/vector/ai/ai-secret.json --out <release>/vector-ai-sink.yaml`
2. Put `{"ingest_token": "<INGEST_TOKEN from the AI VM>"}` in `/etc/vector/ai/ai-secret.json` (mode 0600, Vector user). Copy the AI VM's `/etc/jengasec-ai/tls/server.crt` (or the internal CA) to `/etc/vector/ai/ai-ca.crt`.
3. Load it as a second config: `vector --config …/vector.yaml --config …/vector-ai-sink.yaml`, and mount `/etc/vector/ai` read-only.

Notes on the sink:
- **Why a rendered file and a secret file.** Vector 0.58 does not interpolate `${ENV}` in configuration without `--dangerously-allow-env-var-interpolation`. That is why OBS renders `__WEBSITE_FEED_URL__`. The sink follows the same pattern, and reads the token through Vector's `secret` file backend, so the token is never in a rendered config.
- **Delivery.** The sink sends NDJSON batches of up to 500, with retries and a 1 GB disk buffer. The AI API stores each `event_id` once, so a retry, a duplicate, or a replay of the spool is harmless. To catch up after an outage, POST the spool files as they are: `curl --data-binary @telemetry-YYYY-MM-DD.ndjson -H 'Content-Type: application/x-ndjson' -H "Authorization: Bearer $INGEST_TOKEN" https://192.168.40.11:8443/api/v1/ingest`.
- **Validation.** Every event is checked against `contracts/telemetry-event.schema.json` (v2) and `scripts/cells.yaml`. Bad events are rejected one by one, with their index. Vector's `integrity_hash` is recomputed, and mismatches are counted in the AI API log (`ingest_integrity_mismatch`).
- **Attribution is OBS's.** The AI API stores `actor.team_id` / `actor.team_label` as OBS sends them and never guesses. Those labels are the AI track's ground truth: AI Red's view (`actor.team_id` = its own) and every precision/recall figure depend on them. Stale attribution (`unknown`) means AI Red sees nothing and scoring has no ground truth. OBS's refresh alert (two missed intervals) is therefore an AI-track alert too.

**Tested 2026-10-14.** I ran OBS's own development stack with this sink (`ai-api/deploy/obs-ai-link.compose.yaml`). Vector normalized 8 fixture events across application, ingress, firewall, IDS, NetFlow, host and Kubernetes, and delivered all 8 in one NDJSON batch. The AI API accepted them with 0 rejections and 0 integrity mismatches.

## (2) The teams → AI VM

- Tokens are issued on the AI VM: `issue-tokens.py`, one per team. The VM keeps only the hashes. Each team's token goes to that team privately; the website has no token page yet (see below).
- The team list comes from the website. Run `python manage.py export_range --competition <id> --out <dir>` (website), then `python ai-api/scripts/import-ai-teams.py <dir>/allocation.csv` on the AI side. That writes `scripts/ai-teams.yaml`: `team_id` is the website's `team_identifier`, which is also what OBS puts in `actor.team_id`.
- Gateway (NET): allow `10.62.0.0/16` and `10.64.0.0/16` to `10.109.0.10:8443` only (platform VM 101), plus `10.109.0.10:443` for everyone. That reaches the AI API and nothing else on VLAN 109, rate-limited like other AI traffic. AI Red's attack traffic to the applications is a separate, existing rule.

## (3) AI VM → website

- The website already defines the receiver: `POST /api/feed` (website repo `docs/CONTRACT-feed.md`, `scoring/ingest.py`). Its AI criteria and caps are exactly what `ai-api/app/marks.py` produces.
- On the AI VM, set these in `/etc/jengasec-ai/ai-api.env`:
  - `WEBSITE_FEED_URL=https://<website on VLAN 109>/api/feed/`
  - `WEBSITE_FEED_TOKEN=<DJANGO_FEED_TOKEN>`
  - `WEBSITE_COMPETITION=<id>`
  - `ENGAGEMENT_DAYS=1=YYYY-MM-DD,2=…,3=…`
  - `WEBSITE_CA_FILE` if the website uses the internal CA.

  `jengasec-ai-marks.timer` then pushes each started day's marks every 5 minutes.
- Marks are addressed by `team` = the website `team_identifier`, with key `aic:<criterion>:day<N>`. Republishing replaces a mark; it never adds a second one. The website answers `200`, or `202` with per-row rejections: an unknown `team_id` means `ai-teams.yaml` is stale, so re-import it.
- **Tested 2026-10-14** against the real website code (a scratch copy with its own database, 370/370 website tests passing). 33 marks were pushed, all accepted, and stored as `ScoreEvent`s. The website totalled them per team (e.g. AI-01: 26.79 of 40). Republishing kept exactly 33 rows.

The marks are **proposals** (Architecture §11): the scoring agent proposes, judges decide, and overrides happen on the website.

## Mismatches found while wiring this up (each needs its owner)

| # | Where | Problem | Proposed fix | Owner |
|---|---|---|---|---|
| 1 | OBS `website_feed_publisher` vs website `/api/feed` | OBS posts sanitized **raw events** (NDJSON, no `X-Feed-Token`). The website's `/api/feed` accepts only **marks** (`{"scores":[…]}`) with `X-Feed-Token`, and answers 404 when the token is unset. As built, OBS's publisher cannot deliver to the website | Agree one of: a second website endpoint for the live per-app event chart, or OBS publishes availability/detection marks in the `scores` shape. The AI VM already uses the `scores` shape | OBS + website |
| 2 | OBS `contracts/scope-assignments.example.csv` | Uses AI Red team id `JS26-AIR-001`. The website only issues `JS26-B-nnn` / `JS26-R-nnn` (`services/team_service.assign_identifier`) | Use the website's identifiers everywhere. `ai-teams.yaml` follows the website | OBS |
| 3 | Website `services/range_service.py` on `main` | Exports old cell names (`enta-app03`) and numbers **all** Red teams, AI Red included, as `10.60.n.0/24`. The address plan puts AI Red at `10.64.n.0/24` | The website's `Tallam` branch aligns namespaces. The AI Red range numbering still needs a fix | Website (Tallam) + NET |
| 4 | Website `docs/CONTRACT-feed.md` | Says "Vector → AI API `/api/v1/ingest` on the obs VM" | Update to "on the platform VM 101, `192.168.40.11:8443`" | Website |
| 5 | OBS dev fixture `ip-allocations.csv` on `main` | Attribution validity ended 2026-10-12, so every rehearsal event is now `team_label: unknown` | Merge OBS's `obs/fixture-clock` branch, which fixes exactly this | OBS |
| 6 | OBS telemetry fixtures | `attributed-request.json` and `refused-flow.json` share the placeholder `event_id` `evt_aaaa…` | Give each fixture its own id | OBS |
| 7 | Website | No place to show an AI team its AI API token | Add a token field to the team page, or keep handing tokens over by hand | Website |
| 8 | `contracts/address-plan.md` | Lists the AI API on the obs VM (`10.109.0.30`) | Move it to `web 10.109.0.10` (platform VM 101: website + AI API + scoring) | NET |
| 9 | NET's WireGuard worker | No participant can reach the website or the AI API, and AI Blue cannot be provisioned at all | `docs/net-platform-services.patch` (`docs/platform-vm.md` §6) | NET |
