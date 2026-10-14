# Application ingress scope

The application chart's Traefik middleware permits only the owning Blue team,
staff, and active Red teams assigned to that application. Update the generated
contracts from the competition platform before applying a new round's
assignments:

```sh
python3 scripts/import_platform_exports.py \
  --cells /path/to/platform/cells.yaml \
  --scope /path/to/platform/scope-assignments.csv \
  --cells-output scripts/cells.yaml \
  --scope-output contracts/scope-assignments.csv
python3 scripts/make-scope.py --dry-run
python3 scripts/make-scope.py
```

The scope updater changes only `ingress.allowedRanges` and uses Helm
`--reuse-values`, so it preserves the currently deployed image and release
settings. It updates existing releases only; a missing release or a Helm error
fails the command rather than creating or silently skipping the application.
Inactive Red assignments are validated but are not added to the allowlist.

The updater maps Blue team `JS26-B-NNN` to `10.61.N.0/24`, App Red
`JS26-R-NNN` to `10.60.N.0/24`, and AI Red `JS26-AIR-NNN` to
`10.64.N.0/24`. Those mappings and limits must remain consistent with
`contracts/address-plan.md`.

When called by the platform's day-reset command, `JENGASEC_COMPETITION_ID` is
set and the updater fetches the current exports from the authenticated
`/deployments/api/range-exports/` endpoint instead of reading local export
files. Set `JENGASEC_BASE` if the website is not at its default URL and ensure
`JENGASEC_DEPLOY_TOKEN` is available in the reset process. The reset command
performs this live-export validation in dry-run mode before restoring any
application data. Scope activity comes from the platform's current
`TargetAssignment.is_active` flag; there is not yet a day-indexed scope
schedule, so organisers must set the desired assignments active before reset.
