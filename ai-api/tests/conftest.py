import hashlib
import json
import pathlib
from datetime import datetime, timedelta, timezone

import pytest
import yaml
from fastapi.testclient import TestClient

from app.auth import token_hash
from app.config import Settings
from app.main import create_app

REPO = pathlib.Path(__file__).resolve().parents[2]
BLUE = "tok-ai-01"        # AI Blue AI-01
BLUE2 = "tok-ai-02"       # AI Blue AI-02
RED = "tok-ri-01"         # AI Red RI-01, paired with AI-01 (scenario s04 is RI-01's traffic)
RED2 = "tok-ri-02"        # AI Red RI-02, no traffic in the scenarios
INGEST = "ingest-secret"
ADMIN = "admin-secret"

TEAMS = {t["code"]: t for t in yaml.safe_load((REPO / "scripts/ai-teams.yaml").read_text(encoding="utf-8"))["teams"]}
SCENARIO_EVENTS = {"s01": 142, "s02": 87, "s03": 61, "s04": 99}
RI01_EVENTS = 45          # s04's malicious events, all from RI-01's 10.64.1.0/24


def auth(token):
    return {"Authorization": f"Bearer {token}"}


def fixture_event(name):
    return json.loads((REPO / "contracts/fixtures/telemetry" / name).read_text(encoding="utf-8"))


def v2_event(n, ip, team_id, label, *, ts=None, enterprise="ENT-A", application="APP03",
             event_type="authentication_failure", user="u", severity="low"):
    """A valid telemetry v2 event, with the integrity hash Vector would give it."""
    ns = f"jengasec-{enterprise.lower()}-{application.lower()}"
    ts = ts or datetime(2026, 10, 10, 10, 0, tzinfo=timezone.utc) + timedelta(seconds=5 * n)
    iso = ts.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    ev = {
        "schema_version": "2.0", "catalogue_version": 1, "stream": "telemetry",
        "event_id": "evt_" + hashlib.sha256(f"{ip}-{ns}-{n}-{event_type}".encode()).hexdigest(),
        "ts": iso, "received_ts": iso, "enterprise": enterprise, "application": application, "namespace": ns,
        "asset": f"{ns}/app", "source": "application", "event_type": event_type, "severity": severity,
        "outcome": "failure", "verdict": "allowed",
        "actor": {"ip": ip, "team_id": team_id, "team_label": label, "user_id": f"{user}{n}"},
        "target": {"ip": "10.108.0.13", "enterprise": enterprise, "application": application, "namespace": ns},
    }
    body = json.dumps(ev, sort_keys=True, separators=(",", ":"))
    ev["integrity_hash"] = "sha256:" + hashlib.sha256(body.encode()).hexdigest()
    return ev


@pytest.fixture
def make_client(tmp_path):
    def make(**overrides):
        tokens = tmp_path / "tokens.yaml"
        tokens.write_text(
            "tokens:\n"
            f"  AI-01: {token_hash(BLUE)}\n  AI-02: {token_hash(BLUE2)}\n"
            f"  RI-01: {token_hash(RED)}\n  RI-02: {token_hash(RED2)}\n"
            f"  XX-99: {token_hash('tok-unknown-team')}\n", encoding="utf-8")
        settings = Settings(**{
            "repo": REPO, "database_url": f"sqlite:///{tmp_path / 'test.db'}", "tokens_file": tokens,
            "ingest_token": INGEST, "admin_token": ADMIN, "sandbox_seed": True, "action_budget": 3,
            "rate_limit_per_minute": 100000, **overrides})
        return TestClient(create_app(settings))
    return make


@pytest.fixture
def client(make_client):
    with make_client() as c:
        yield c


@pytest.fixture
def empty_client(make_client):
    with make_client(sandbox_seed=False) as c:
        yield c
