# Build from the repository root, so the contracts travel with the service:
#   docker build -f ai-api/Dockerfile -t jengasec/ai-api .
FROM python:3.11-slim

WORKDIR /srv/ai-api
COPY ai-api/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# The contract files are read at runtime: the API validates against them, it does not copy them.
COPY contracts /srv/repo/contracts
COPY scripts/cells.yaml scripts/ai-teams.yaml /srv/repo/scripts/
# Scenario events for the sandbox. Answer keys are excluded by .dockerignore.
COPY scenarios /srv/repo/scenarios
COPY ai-api/app ./app

RUN useradd --uid 10001 --no-create-home --system api && mkdir /data && chown api /data
ENV REPO_ROOT=/srv/repo \
    DATABASE_URL=sqlite:////data/ai-api.db \
    TOKENS_FILE=/run/secrets/tokens.yaml \
    PYTHONUNBUFFERED=1
USER 10001
EXPOSE 8000
HEALTHCHECK CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz')"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
