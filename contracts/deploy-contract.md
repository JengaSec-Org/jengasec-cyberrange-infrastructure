# Contract: application image delivery

Owner: Application Platform. Audience: Application Blue teams.

Teams submit Linux `amd64` container images to the JengaSec registry. The
platform scans the image, records the accepted digest in `applications`, and
deploys only that digest through the standard cell chart. A submission may
contain an application, worker and migration image; every image follows the
same security requirements.

## Workload requirements

1. Run as a non-root user without added Linux capabilities.
2. Listen on the declared HTTP port, normally `8080`.
3. Answer `GET /healthz` with HTTP 200 when ready.
4. Expose Prometheus text metrics at `GET /metrics`.
5. Write one JSON object per line to stdout following
   `logging-contract.schema.json` and the event catalogue.
6. Read database settings from `DB_HOST`, `DB_NAME`, `DB_USER` and
   `DB_PASSWORD`.
7. Start within 60 seconds and keep each image below 500 MB.
8. Require no manual cluster installation or privileged host access.

The platform supplies enterprise, application and namespace identifiers as
environment variables. Workloads must log those values unchanged and must not
accept them from users.

## Repository requirements

The team repository contains its Dockerfile(s), application source, dependency
locks and a README describing endpoints and the health/metrics paths. It must
not contain secrets, credentials, participant data, generated WireGuard files,
or copied production data.

Before a round, the platform freezes the last accepted image digest. Daily
reset redeploys that digest and restores seed data; pushing a tag during a
round cannot alter the running image.
