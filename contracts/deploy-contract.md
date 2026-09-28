# Contract: what a team repository must contain

Owner: Application Platform. Audience: Blue teams. If your repository follows this, pushing deploys your application.

```
your-repo/
├── Dockerfile          # builds and runs your app
├── .gitea/workflows/deploy.yml   # provided, do not edit
├── src/...             # your code
└── README.md           # what your service does, and your endpoints
```

**Your application must**

1. Listen on port `8080` inside the container.
2. Answer `GET /healthz` with HTTP 200 as soon as it can serve traffic.
3. Write logs as one JSON object per line to stdout, following `logging-contract.schema.json`.
4. Read its database connection from the environment variables `DB_HOST`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`.
5. Run as a non-root user and need no extra privileges.
6. Start within 60 seconds and keep the image under 500 MB.

**Your repository must not**

- contain secrets or credentials of any kind
- be larger than 50 MB
- need anything installed on the cluster by hand

**Pushing**

Push to `main`. The pipeline builds your image in the lab, deploys it to your namespace, and shows the result in the build log. Failed build: nothing changes, your previous version keeps running.
