# Contracts index

A contract is the agreement between two areas. Everything else is an implementation detail you can change freely.

| Contract | File | Owner | Consumed by | Says |
|---|---|---|---|---|
| Cell template | `contracts/cell-template.md` | Application Platform (with Security) | Platform, Observability, Automation scripts | What every team environment contains and its limits |
| Deploy contract | `contracts/deploy-contract.md` | Application Platform | Blue teams, deploy desk | What a team repository must contain for push-to-deploy to work |
| Logging contract | `contracts/logging-contract.md`, `contracts/logging-contract.schema.json` | AI Track (with Observability) | Blue teams, Vector, judges | The fields every application must log |
| Event catalogue | `contracts/telemetry-event-catalogue.yaml` | AI Track (with Observability, Application Briefs and Scoring) | Blue teams, Vector, judges | Raw names, normalized types and permitted details |
| Telemetry event | `contracts/telemetry-event.schema.json` | AI Track (with Observability) | Observability, AI cells, scoring | The normalized attributable observation |
| Infrastructure telemetry | `contracts/infrastructure-telemetry.md`, `contracts/infrastructure-source.schema.json`, `contracts/infrastructure-event.schema.json` | Observability (with host, gateway and Kubernetes owners) | Infrastructure collectors, staff dashboards | Sanitized global observations, provenance and optional native attribution |
| Event boundaries | `contracts/event-boundaries.md` | Observability (with Platform and Scoring) | All telemetry consumers | Keeps telemetry, platform audit and competition records separate |
| OBS platform data | `contracts/observability-data-interface.md`, `contracts/observability-finding.schema.json` | Competition Platform and Observability | Attribution, access and evidence automation | Versioned read-only platform database views |
| Evidence pack | `contracts/evidence-pack.md`, `contracts/evidence-pack.schema.json` | Observability (with Scoring) | Judges and staff | Sanitized, integrity-checked finding export |
| Infrastructure evidence | `contracts/evidence-pack.md`, `contracts/infrastructure-evidence.schema.json` | Observability | Staff | Verified infrastructure records selected by resource, time and event ID |
| AI API | `contracts/ai-api/openapi.yaml` (v1.3), integration in `docs/ai-integration.md`, hosting in `docs/platform-vm.md` | AI Track | AI teams, Observability (`/ingest`), website (marks) | Endpoints, authentication, limits; how the AI VM talks to OBS, the website and the teams |
| AI teams | `scripts/ai-teams.yaml` (imported from the website's `allocation.csv`) | AI Track | AI API, Network (WireGuard ranges), Scoring | The 3 AI Blue and 6 AI Red teams, their website `team_id` and pairings |
| OBS → AI sink | `ai-api/deploy/vector-ai-sink.yaml` (rendered by `render-vector-ai-sink.py`) | AI Track (with Observability) | Observability's Vector | How normalized telemetry reaches the AI VM |
| Detect-to-respond handoff | `contracts/handoff.schema.json` | AI Track | AI cells | What a detection cell hands the response cell |
| Address plan | `contracts/address-plan.md` | Network & Access | Everyone | Networks, address ranges, hostnames |
| Red scope | `contracts/scope-assignments.example.csv` | Engagement & Operations | Security, Application Platform, marshals | Which Red team may attack which cell |
| Findings | `contracts/findings.md` | Scoring & Evaluation | Red teams, judges | What a reported finding must contain |

**Rule:** if your change breaks one of these, it is not your change to make alone.

The AI API remains AI-owned. Its all-estate scope, authentication and the
ingestion endpoint OBS posts to are defined in `contracts/ai-api/openapi.yaml`
and `docs/ai-integration.md` (proposed, awaiting OBS and NET confirmation).
The AI API remains AI-owned. Its all-estate scope and authentication must be
agreed by that owner before implementation; Observability does not create a
replacement ingestion endpoint.

Application ingress allowlists are updated from imported platform exports
using [`runbooks/application-scope.md`](../runbooks/application-scope.md).
For competition day resets, the platform lifecycle command is authoritative:
it restores frozen image digests and seed data, then calls the scope updater.
The legacy infrastructure `reset-cell.sh` Helm-revision workflow is not the
competition reset path.
