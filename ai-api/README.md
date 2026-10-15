# AI API

**Owner:** AIC · **Contract:** [`contracts/ai-api/openapi.yaml`](../contracts/ai-api/openapi.yaml) (v1.3) · **Design:** Competition Architecture §3, §15 · **Tasks:** AIC-05, AIC-11, AIC-15, AIC-18, AIC-20, base for AIC-17

With `SCORING_MODE=1`, this service also exposes
[`/api/v1/scoring`](../contracts/ai-api/scoring-openapi.yaml). The website's
versioned scoring policy owns official marks. Existing v1 telemetry, stream,
asset and alert routes keep their client shapes and permissions. Legacy
decision/action/revert writes and both admin marks routes return 409. Use the
structured scoring namespace with its original bearer token, case, event time,
epoch and sequence; the facade does not infer those values or translate IDs.
The `X-JengaSec-Scoring-Mode` response header identifies `website-v2` or
`legacy-shadow`. The sandbox examples and heuristic scoring described below
apply only when scoring mode is disabled.

Install the private scoring backend on the same host as this facade. Its
address is fixed at `127.0.0.1`, with port
`SCORING_GATEWAY_PORT` (default 9681). It receives private `/api/v1/*` requests
from the public `/api/v1/scoring/*` facade. It authenticates the original
bearer independently; observer and operator tokens need their own grants in
its protected token configuration. There is no shared credential substitution.
Requests are limited to 64 KiB, responses to 1 MiB, backend response headers
to 16 KiB, and backend connections to 16. `SCORING_GATEWAY_TIMEOUT_SECONDS` defaults to 35
and cannot exceed 60. Oversized receipt pages return 413; request a smaller
page. Redirects, encoded paths and unavailable backends are rejected. Scoring
SSE uses bounded resumable batches; the existing v1 stream remains live SSE.
Keep action keys and producer epoch/sequence unchanged on retry. A transport
timeout does not establish whether an action ran; inspect its native state.

In scoring mode, `/admin/kill-switch` forwards the staff caller's original
token to the actual gateway. Register that same reviewed `ADMIN_TOKEN` as a
gateway operator; otherwise the backend denies it. GET reads the actuator's
current switch. POST translates only `{on: boolean}` to `{enabled: boolean}`
and requires confirmed revocation before reporting success. A failed backend
or unresolved revocation returns an error; the legacy database flag is unused.

`SANDBOX_SEED` defaults to 0 in scoring mode; explicitly enabling it prevents
startup. Use a reviewed database without rehearsal fixtures. Clear the legacy
website feed credentials and disable `jengasec-ai-marks.timer` when enabling
scoring mode. The installer disables that timer in scoring mode, and the
publisher itself exits without any request. Admin exports of legacy activity
are marked non-scoring and omit the heuristic ground-truth summary.

`snapshot-evidence` captures telemetry evidence only. It does not snapshot or
restore a VM or application. Real revert removes the gateway's own block-ip
lease and verifies recovery. Other restoration actions are unsupported. See
the [scoring rollout](../runbooks/observability.md) for private service paths,
identity refresh, source access and actuator configuration.

**Try it on a Debian 12 VM:** [`runbooks/ai-api-vm.md`](../runbooks/ai-api-vm.md). There, `make-bundle.sh`, then `install.sh`, then `smoke.sh`.

`smoke.sh` and `tour.sh` are legacy shadow rehearsals. Both reject local
scoring mode and check the selected server's mode header before any writes,
including URL overrides. Failed or ambiguous checks stop the script. Older
legacy APIs without the header remain supported.

JengaSec hosts no AI. This service is the data side the AI teams' own agents connect to over WireGuard. There is one token per team (`scripts/ai-teams.yaml`) and two roles:

| | AI Blue (AI-01 … AI-03) | AI Red (RI-01 … RI-06, two paired with each AI Blue) |
|---|---|---|
| Reads | Every event for all 18 apps in both enterprises: events, stream, assets, alerts | Only events about its own traffic, and the baseline alerts that traffic triggered (evidence trimmed to its own events); assets |
| Writes | Decisions (scored), and actions in **shadow mode** (recorded and scored, only `alert` takes effect) | Nothing: `POST /decisions` and `/actions` return 403. Its output is traffic to the apps |

Events are **telemetry contract v2** (`contracts/telemetry-event.schema.json`), normalized and attributed by Observability. Every event carries `actor.team_id` and `actor.team_label` (`red-app`, `blue-app`, `red-ai`, `blue-ai`, `staff`, `judge`), which OBS resolves from the platform's `ip_allocations`; this service stores them and never guesses. Those labels are the **ground truth**:
- `/admin/export/<team>` scores AI Blue's precision, recall and false actions against them, and AI Red's success at being missed by its paired AI Blue.
- `/admin/publish-marks` turns the same numbers into the website's AI marks.

**Where it runs:** on the platform VM 101 next to the website and the scoring model ([`docs/platform-vm.md`](../docs/platform-vm.md)). **How it connects** to OBS (`/ingest`), the website (`/api/feed`) and the teams: [`docs/ai-integration.md`](../docs/ai-integration.md).

The contract is the YAML file. This folder is one implementation of it, and `tests/test_api.py::test_every_contract_path_is_implemented` fails if the two drift apart.

## Run it on your machine (sandbox)

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r ai-api/requirements-dev.txt
python ai-api/scripts/issue-tokens.py            # prints one token per AI team ONCE; writes ai-api/tokens.yaml (hashes)
cd ai-api
INGEST_TOKEN=dev-ingest ADMIN_TOKEN=dev-admin TOKENS_FILE=tokens.yaml uvicorn app.main:app --port 8000
```

With `SANDBOX_SEED=1` (the default), it loads every `scenarios/*/events.jsonl` at start-up, so there is data straight away. Loading twice does no harm, because events are unique by `event_id`.

Or as a container, built from the **repository root**:

```bash
docker build -f ai-api/Dockerfile -t jengasec/ai-api .
docker run -p 8000:8000 -e INGEST_TOKEN=dev-ingest -e ADMIN_TOKEN=dev-admin -v "$PWD/ai-api/tokens.yaml:/run/secrets/tokens.yaml:ro" jengasec/ai-api
```

## Quickstart for AI teams

```bash
TOKEN=jsai_ai01_...               # your team's token, from your team page
API=https://10.109.0.10:8443/api/v1     # platform VM 101 on VLAN 109 (docs/platform-vm.md)

curl -s -H "Authorization: Bearer $TOKEN" "$API/telemetry/events?limit=200"     # {events, next_cursor, has_more}
curl -s -H "Authorization: Bearer $TOKEN" "$API/telemetry/events?cursor=<next_cursor>"
curl -sN -H "Authorization: Bearer $TOKEN" "$API/telemetry/stream"              # live, server-sent events
curl -s -H "Authorization: Bearer $TOKEN" "$API/assets"                         # the 18 apps: namespace, reserved IP
curl -s -H "Authorization: Bearer $TOKEN" "$API/alerts"                         # platform baseline, to compare with
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"target":{"namespace":"jengasec-ent-a-app03","ip":"10.60.5.14"},"justification":"40 failed logins across 40 users from one address","evidence":["<event_id>"]}' \
  "$API/actions/block-ip"                                                        # 202, effective:false (shadow mode)
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"incident_id":"inc-1","summary":"Credential stuffing, then k.otieno taken over","confidence":0.85,"evidence":["<event_id>"]}' \
  "$API/decisions"                                                               # 201: what judges score
```

```python
import requests, time
API, H = "https://10.109.0.10:8443/api/v1", {"Authorization": "Bearer jsai_ai01_..."}
cursor = None
while True:
    page = requests.get(f"{API}/telemetry/events", headers=H, params={"cursor": cursor} if cursor else {}, verify="jengasec-root.pem").json()
    for event in page["events"]:
        ...                                   # your detector
    cursor = page["next_cursor"]
    if not page["has_more"]:
        time.sleep(5)                         # caught up: poll gently (rate limit: 600 requests/minute)
```

The range uses an internal CA (ADR 0003). Use the root certificate from the info pack (`verify=`), not `verify=False`.

## Rules the gateway applies

| Rule | Result |
|---|---|
| Missing or unknown token, or a token for a team that is not `enabled` in `scripts/ai-teams.yaml` | 401 |
| An AI Red token posting a decision or an action | 403 |
| Over 600 requests a minute for one token (`RATE_LIMIT_PER_MINUTE`) | 429 |
| Action on something that is not one of the range's applications | 403 |
| More than 20 actions in one engagement day for one team (`ACTION_BUDGET`) | 403 |
| Kill switch on | 423. The request is still recorded with `status: halted` |
| Decision evidence that is not a known event_id, or a handoff that breaks `handoff.schema.json` | 422 |
| Acting on a sender who is not a Red team (`target.ip`, by attribution) | Accepted, but counted as a **false action** in the judges' export |
| Any action except `alert` | `effective: false`. Recorded, scored, and never applied (event one) |

## For Observability: posting to `/ingest`

- Send a `POST /api/v1/ingest` with `Authorization: Bearer $INGEST_TOKEN`. The body is a JSON **array** of telemetry events (at most 5000). Vector's `http` sink with `encoding.codec: json` sends batches in exactly this form.
- Each item is checked against `contracts/telemetry-event.schema.json` (v2) on its own. Its `namespace` must be in `scripts/cells.yaml`, and its `enterprise`/`application` must match that namespace. `integrity_hash` is recomputed; a mismatch is logged (`ingest_integrity_mismatch`), not rejected.
- The body is a JSON array or NDJSON (`Content-Type: application/x-ndjson`). The ready-made Vector sink is `ai-api/deploy/vector-ai-sink.yaml`; render it with `render-vector-ai-sink.py` (see `docs/ai-integration.md`).
- The response is `202 {accepted, rejected:[{index, error}]}`. Re-posting an `event_id` is harmless.
- To test the normaliser, use `contracts/fixtures/ingress/` (Traefik sample in, expected events out) and `contracts/fixtures/telemetry/valid/`.

## Staff only: the kill switch (AIC-18, SEC-12)

```bash
curl -s -X POST -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' -d '{"on":true}' "$API/admin/kill-switch"
```

These staff and judges' endpoints are intentionally left out of the AI team contract:
- `GET /admin/teams`: every team, whether its token is issued, and its activity.
- `GET /admin/export/<code>`: one file per team for the Scoring lead, with decisions, actions and ground-truth numbers (AIC-20).

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `DATABASE_URL` | `sqlite:///./ai-api.db` | Use `postgresql+psycopg://…` on the platform (PostgreSQL 16) |
| `TOKENS_FILE` | `tokens.yaml` | Token hashes from `scripts/issue-tokens.py`. Keep it out of Git; on the cluster it is a Secret |
| `INGEST_TOKEN` / `ADMIN_TOKEN` | empty (endpoint refuses everyone) | Vector's token and the staff token |
| `SCORING_MODE` | `0` | Enable the additive scoring protocol; disable legacy writes and marks |
| `SCORING_GATEWAY_PORT` | `9681` | Private backend port on fixed `127.0.0.1`; 1024–65535 |
| `SCORING_GATEWAY_TIMEOUT_SECONDS` | `35` | Total backend request deadline; 0.1–60 seconds |
| `SANDBOX_SEED` | `1` in legacy mode, `0` in scoring mode | Load scripted scenarios at start-up; forbidden in scoring mode |
| `ACTION_BUDGET` | `20` | Actions per AI Blue team per engagement day |
| `RATE_LIMIT_PER_MINUTE` | `600` | Requests per token per minute |
| `REPO_ROOT` | the repository | Where `contracts/`, `scripts/cells.yaml`, `scripts/ai-teams.yaml` and `scenarios/` are read from |
| `WEBSITE_FEED_URL` / `WEBSITE_FEED_TOKEN` | empty (nothing is published) | The website's `POST /api/feed` and its `DJANGO_FEED_TOKEN` |
| `WEBSITE_COMPETITION` / `WEBSITE_CA_FILE` | empty | Competition id on the website; CA bundle if it uses the internal CA |
| `ENGAGEMENT_DAYS` | empty | `1=YYYY-MM-DD,2=…,3=…`: marks are computed and published per engagement day |

## Tests

```bash
cd ai-api && pytest                              # 38 tests
python ai-api/scripts/validate-scenarios.py      # scenario events vs telemetry v2, the catalogue and the answer keys
```

The tests cover:
- roles: AI Blue sees everything, AI Red only its own `team_id`
- OBS's own v2 fixtures, NDJSON ingest, and namespace checks
- ground-truth labels against the answer keys, cursor paging and SSE
- baseline alerts, which catch s01 but not s04's evasion
- shadow mode, budget, kill switch and revert
- decisions with handoffs
- the export and the website marks scheme, plus a real HTTP push to a feed receiver
- contract parity

## Tools

| Script | Does |
|---|---|
| `scripts/issue-tokens.py` | One token per enabled AI team; keeps only hashes |
| `scripts/import-ai-teams.py` | `scripts/ai-teams.yaml` from the website's `allocation.csv` |
| `scripts/publish-marks.py` | Push proposed AI marks to the website (what the timer runs) |
| `scripts/make-test-event.py` | Print one valid v2 event, as Vector would send it |
| `scripts/validate-scenarios.py` | Check the scenario data and `ai-teams.yaml` |
| `deploy/install.sh`, `smoke.sh`, `tour.sh`, `make-bundle.sh` | The Debian 12 VM: `runbooks/ai-api-vm.md` |
| `deploy/vector-ai-sink.yaml`, `render-vector-ai-sink.py` | What OBS adds to Vector to feed this VM |
| `deploy/obs-ai-link.compose.yaml` | Rehearsal: OBS's dev stack posting to a local AI API |

## Not built yet

- A website page that shows an AI team its token (`docs/ai-integration.md`, mismatch 7). Until then, tokens are handed over privately.
- Model-endpoint egress for AI teams: a gateway rule (NET), not part of this service.
