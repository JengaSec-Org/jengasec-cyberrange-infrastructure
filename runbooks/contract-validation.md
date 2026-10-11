# Runbook: contract validation

Owner: Observability with the named contract owners

Scope: local Debian 12/Codespaces and hosted CI. It changes no infrastructure.

## Prepare

Use an isolated environment so the pinned validation packages do not alter the
system Python:

```bash
python3 -m venv .venv-contracts
.venv-contracts/bin/pip install -r contracts/requirements.txt
```

`.venv-contracts` is ignored and may be removed after validation.

## Validate

```bash
PATH="$PWD/.venv-contracts/bin:$PATH" \
  .venv-contracts/bin/python scripts/validate-contracts.py
```

The command validates the catalogue schema, mapping semantics, all 18
application identifiers and addresses, scope rows, positive fixtures and
negative fixtures. It is safe to repeat and writes no repository files.

If a valid fixture fails, correct either the fixture or the owning contract;
do not add permissive defaults. If an invalid fixture passes, strengthen the
schema or semantic check before merging.
