# ADR 0001: One repository, folder per area

**Status:** accepted

**Context.** Nine areas, forty-one people, two weeks, one server. Splitting the code per area hides how the pieces fit and lets the shared formats drift.

**Decision.** One private repository, `jengasec-infra`, with a folder per area and a `contracts/` folder for anything two areas share.

**Consequences.** Everyone sees every change. Reviews cross areas. The repository is the description of the platform: if it is not here, it does not exist.
