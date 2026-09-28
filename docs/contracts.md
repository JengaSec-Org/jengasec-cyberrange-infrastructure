# Contracts index

A contract is the agreement between two areas. Everything else is an implementation detail you can change freely.

| Contract | File | Owner | Consumed by | Says |
|---|---|---|---|---|
| Cell template | `contracts/cell-template.md` | Application Platform (with Security) | Platform, Observability, Automation scripts | What every team environment contains and its limits |
| Deploy contract | `contracts/deploy-contract.md` | Application Platform | Blue teams, deploy desk | What a team repository must contain for push-to-deploy to work |
| Logging contract | `contracts/logging-contract.schema.json` | AI Track (with Observability) | Blue teams, Vector, judges | The fields every application must log |
| Telemetry event | `contracts/telemetry-event.schema.json` | AI Track | Observability, AI cells, scoring | The normalised event the AI API serves |
| AI API | `contracts/ai-api/openapi.yaml` | AI Track | AI cells | Endpoints, authentication, limits |
| Detect-to-respond handoff | `contracts/handoff.schema.json` | AI Track | AI cells | What a detection cell hands the response cell |
| Address plan | `contracts/address-plan.md` | Network & Access | Everyone | Networks, address ranges, hostnames |
| Red scope | `contracts/scope-assignments.example.csv` | Engagement & Operations | Security, Application Platform, marshals | Which Red team may attack which cell |
| Findings | `contracts/findings.md` | Scoring & Evaluation | Red teams, judges | What a reported finding must contain |

**Rule:** if your change breaks one of these, it is not your change to make alone.
