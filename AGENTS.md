# JengaSec infrastructure operating rules

These rules apply to the whole repository. Read them before planning, changing,
reviewing, or operating the platform. More specific repository guidance may add
constraints; when rules overlap, follow the stricter safe rule.

## Sources of truth

Read these before starting substantive work:

1. `CONTRIBUTING.md` for branches, commits, pull requests, and review.
2. `docs/standards.md` for environments, automation, naming, versions, secrets,
   contracts, and definition of done.
3. `docs/contracts.md` and the affected files in `contracts/` for cross-area
   interfaces.
4. `docs/access-tiers.md`, the relevant runbook, and current ADRs for any
   operational change.

The repository is the platform description that counts. Plans, meeting notes,
chat exports, and screenshots provide context but do not override checked-in
standards or contracts. Do not copy private conversations, personal data, or
credentials into repository or GitHub artifacts.

## Start with scope and ownership

- Inspect the working tree, current branch, upstream `main`, relevant issues or
  Ops Board task, open pull requests, and recent changes before editing.
- Preserve unrelated work. Do not rewrite, discard, or bundle someone else's
  changes into the task.
- Identify the owning area and every consumed contract. A change that breaks a
  shared contract is not one area's decision to make alone.
- Use the supplied task ID. Never invent one. If no task is supplied, state that
  plainly in the pull request rather than fabricating traceability.
- Branch from current `main` using `<area>/<short-thing>`. Keep one pull request
  to one purpose and one acceptance path.

## Build changes that can be operated

- Keep versions pinned in `docs/versions.md`; pin container images and external
  actions immutably where the tool supports it.
- Put repeatable work in the owning area's scripts. Follow the script header,
  safety, idempotence, naming, dependency, and runbook rules in
  `docs/standards.md`.
- Read addresses, names, and environment values from contracts, variables, or
  explicit arguments. Do not hide environment assumptions in code.
- Keep secrets, keys, tokens, passwords, `.env` values, private configurations,
  participant data, and credential-bearing evidence out of Git and GitHub.
- Update the durable runbook when startup, validation, failure recovery,
  rollback, or shutdown behavior changes. Add an ADR only for a lasting,
  cross-cutting architectural decision.
- Validate the smallest affected boundary while iterating, then run the full
  repository gate relevant to the change before push. Test failure behavior as
  well as the happy path.

## Protect contracts

- Keep contract ownership exactly as listed in `docs/contracts.md`.
- A contract change requires the owning and consuming areas, a pull request
  labelled `contract`, and stand-up notice. After checkpoint C2, make only
  backward-compatible optional additions unless the team explicitly agrees to
  a breaking change.
- Add valid and invalid fixtures for machine-readable contract changes. Do not
  weaken validation merely to accept incompatible producers.
- Record unresolved interfaces as dependencies. Never make up an endpoint,
  authentication mechanism, schema, hostname, or address to unblock a demo.

## Keep GitHub artifacts human

- Write as the project author. Do not mention assistants, generated provenance,
  or implementation narration in commits, issues, pull requests, reviews,
  releases, ADRs, or documentation.
- Keep pull requests concise: explain the purpose, observable behavior,
  important decisions, operational boundary, and unresolved risk. Complete the
  repository template, but omit routine command dumps, pass counts, and raw
  logs unless they explain a failure or material limitation.
- Use focused `<area>: <what changed>` commits. Inspect the staged diff and scan
  for secrets before every push.
- Keep non-trivial work draft until required acceptance evidence is available.
  Do not merge, deploy, close tasks, or resolve review threads without the
  requested authority and the actual evidence.
- Another lead must review and someone other than the author must run the change
  successfully before it meets the repository definition of done.

## Keep live operations deliberate

- Develop and prove changes on the documented dev VM or another disposable
  development environment first. Do not experiment on Server 3.
- Live changes reach Server 3 through reviewed repository automation and an
  operator with the access tier in `docs/access-tiers.md`, not through an
  undocumented terminal session.
- Before a k3s, Proxmox, network, shared-service, or Server 3 mutation, confirm
  the exact target, acting identity, current health, dependencies, scope,
  secrets path, verification, rollback, and human approval. Pair on changes
  that can break the platform.
- Use the lowest sufficient access tier. Do not broaden credentials, bypass
  isolation, weaken TLS, or modify another area's resources to make a check
  pass.
- Restrict cleanup to explicit, owned resources. Prefer a reversible
  configuration rollback and verify the result.

## Observability and telemetry boundary

The OBS mission is to make cell activity attributable by source and time,
visible on dashboards, and exportable through agreed interfaces for judges and
the AI platform.

- OBS owns common collection, normalization, telemetry storage, monitoring,
  dashboards, alert primitives, telemetry validation, and operator runbooks.
- Workload and infrastructure owners emit contract-compliant signals. OBS may
  provide reference instrumentation and fixtures but does not silently assume
  ownership of application behavior.
- Keep platform audit, infrastructure telemetry, and competition events as
  separate layers. Raw logs and metrics are evidence inputs; they do not award
  points. Scoring owns competition-event interpretation and score rules.
- Follow the logging and telemetry schemas and their owners in
  `docs/contracts.md`. Preserve enterprise, cell, source, timestamp, event type,
  severity, outcome, and traceability where required.
- Do not collect secrets, request bodies, unnecessary personal data, or
  unbounded high-cardinality fields. "Every request" means useful coverage and
  attribution, not unrestricted payload capture.
- Do not invent the unresolved AI ingestion path. Until the owners agree on an
  authenticated interface, expose the dependency and keep storage queryable
  through its native development interface.
- A telemetry acceptance test proves the actual path: emission, collection,
  normalization, storage, native query, metric scraping, Grafana data-source
  health, dashboard availability, repeat startup, and clean shutdown. Container
  health alone is insufficient.
- Distinguish a development proof, hosted CI result, k3s rehearsal, and Server 3
  deployment. Never claim a later stage from evidence gathered at an earlier
  one.

## Completion language

A pull request with focused commits, relevant validation, green required CI,
durable runbooks, and visible blockers is ready for review. It is not fully done
until it is merged and independently run as required by `docs/standards.md`.
Always report the pull request, material evidence, deployment state, and
remaining integration or human-review blockers.
