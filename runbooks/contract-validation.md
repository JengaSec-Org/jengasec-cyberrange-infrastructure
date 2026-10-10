# Runbook: contract validation

Owner: Observability with the named contract owners

Use a disposable Python environment:

```bash
python3 -m venv .venv-contracts
.venv-contracts/bin/pip install -r contracts/requirements.txt
PATH="$PWD/.venv-contracts/bin:$PATH" \
  .venv-contracts/bin/python scripts/validate-contracts.py
```

If validation fails, fix the owning contract or fixture. Do not weaken a check
to accept invalid data.
