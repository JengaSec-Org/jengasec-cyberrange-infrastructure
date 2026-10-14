"""Compatibility and real loopback transport; firewall effects stay in memory."""

import contextlib
import importlib.util
import json
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest
import yaml
from sqlalchemy import func, select

from app.config import Settings
from app.marks import marks_for, publish
from app.models import Action, Decision, Setting
from app.scoring_proxy import MAX_BODY, MAX_RESPONSE, PUBLIC_PREFIX, ProxyFailure, ScoringProxy
from conftest import ADMIN, BLUE, REPO, auth

TOKEN = "scoring-test-token-" + "a" * 40
API = "/api/v1"


@contextlib.contextmanager
def backend(reply):
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.do_POST()

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            calls.append((self.command, self.path, self.headers, body))
            try:
                reply(self)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        yield server.server_port, calls
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)


def response(handler, body=b'{"ok":true}', status=200, headers=()):
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    for name, value in headers:
        handler.send_header(name, value)
    handler.end_headers()
    handler.wfile.write(body)


def client_options(port, **overrides):
    return {"scoring_mode": True, "sandbox_seed": False, "scoring_gateway_port": port, **overrides}


def test_mode_keeps_legacy_defaults_and_disallows_seeded_official_data(monkeypatch):
    monkeypatch.delenv("SANDBOX_SEED", raising=False)
    monkeypatch.delenv("SCORING_MODE", raising=False)
    assert Settings().sandbox_seed is True
    monkeypatch.setenv("SCORING_MODE", "1")
    assert Settings().sandbox_seed is False
    with pytest.raises(ValueError, match="sandbox_seed_disabled"):
        Settings(sandbox_seed=True)
    for value in (0, 80, 65536, True):
        with pytest.raises(ValueError, match="invalid_scoring_gateway_port"):
            Settings(scoring_gateway_port=value)
    for value in (0, 61, float("nan"), float("inf")):
        with pytest.raises(ValueError, match="invalid_scoring_gateway_timeout"):
            Settings(scoring_gateway_timeout_seconds=value)
    monkeypatch.setenv("SCORING_MODE", "misspelled")
    with pytest.raises(ValueError, match="invalid_scoring_mode"):
        Settings()


def test_original_bearer_body_query_and_native_response_survive(make_client, capsys):
    payload = b'{ "epoch":"boot-1", "case_id":"case-example", "source_sequence": 7 }'
    answer = b'{"receipt":{"receipt_id":"native-receipt-id"},"duplicate":false}'
    with backend(lambda h: response(h, answer, 201, [("Set-Cookie", "must-not-forward=1")])) as (port, calls):
        with make_client(**client_options(port)) as client:
            result = client.post(PUBLIC_PREFIX + "/decisions", content=payload,
                                 headers={**auth(TOKEN), "Content-Type": "application/json", "X-Feed-Token": "not-forwarded"})
            assert result.status_code == 201 and result.content == answer
            assert "set-cookie" not in result.headers
            assert result.headers["x-jengasec-scoring-mode"] == "website-v2"
            assert calls[0][0:2] == ("POST", "/api/v1/decisions")
            assert calls[0][2].get_all("Authorization") == ["Bearer " + TOKEN]
            assert calls[0][2].get("X-Feed-Token") is None
            assert calls[0][3] == payload
            client.get(PUBLIC_PREFIX + "/receipts?after=opaque%2Bcursor&limit=3", headers=auth(TOKEN))
            assert calls[1][1] == "/api/v1/receipts?after=opaque%2Bcursor&limit=3"
    output = capsys.readouterr().out
    assert TOKEN not in output and "case-example" not in output and "not-forwarded" not in output


@pytest.mark.parametrize("status", [401, 403, 409, 413, 429, 503])
def test_backend_failure_is_preserved_without_shadow_fallback(make_client, status):
    answer = b'{"error":"backend_rejected"}'
    with backend(lambda h: response(h, answer, status, [("Retry-After", "5")])) as (port, _):
        with make_client(**client_options(port)) as client:
            result = client.post(PUBLIC_PREFIX + "/actions/block-ip", json={}, headers=auth(TOKEN))
            assert result.status_code == status and result.content == answer
            with client.app.state.sessions() as db:
                assert db.scalar(select(func.count(Action.id))) == 0


def test_missing_backend_and_legacy_writes_cannot_create_official_or_shadow_facts(make_client):
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))  # A reserved port with no listener rejects connections.
        with make_client(**client_options(reserved.getsockname()[1])) as client:
            result = client.post(PUBLIC_PREFIX + "/actions/block-ip", json={}, headers=auth(TOKEN))
            assert result.status_code == 503
            assert result.json()["detail"]["shadow_fallback"] is False
            old_action = {"target": {"namespace": "jengasec-ent-a-app03"}, "justification": "example"}
            old_decision = {"incident_id": "example", "summary": "example", "confidence": 0.5, "evidence": ["event"]}
            for path, body in (("actions/alert", old_action), ("decisions", old_decision), ("actions/act-000001/revert", {})):
                result = client.post(API + "/" + path, json=body, headers=auth(BLUE))
                assert result.status_code == 409
                assert result.json()["detail"]["api_prefix"] == PUBLIC_PREFIX
            for method, path in (("GET", "admin/marks"), ("POST", "admin/publish-marks")):
                assert client.request(method, API + "/" + path, headers=auth(ADMIN)).status_code == 409
            export = client.get(API + "/admin/export/AI-01", headers=auth(ADMIN)).json()
            assert export["scoring"]["official"] is False and "ground_truth" not in export
            assert client.get(API + "/assets", headers=auth(BLUE)).status_code == 200
            assert client.get(API + "/telemetry/events", headers=auth(BLUE)).json()["events"] == []
            with client.app.state.sessions() as db:
                assert db.scalar(select(func.count(Action.id))) == 0
                assert db.scalar(select(func.count(Decision.id))) == 0


def test_disabled_namespace_does_not_contact_backend_and_retains_legacy_shape(make_client):
    with backend(response) as (port, calls):
        with make_client(sandbox_seed=False, scoring_gateway_port=port) as client:
            assert client.get(PUBLIC_PREFIX + "/capabilities", headers=auth(TOKEN)).status_code == 404
            result = client.post(API + "/actions/block-ip", headers=auth(BLUE),
                                 json={"target": {"namespace": "jengasec-ent-a-app03"}, "justification": "example"})
            assert result.status_code == 202 and result.json()["effective"] is False
            assert result.json()["status"] == "recorded"
            assert result.headers["x-jengasec-scoring-mode"] == "legacy-shadow"
            assert not calls


def test_bounded_requests_reject_ambiguous_headers_paths_and_encodings(make_client):
    with backend(response) as (port, calls):
        with make_client(**client_options(port)) as client:
            cases = [
                (PUBLIC_PREFIX + "/decisions", b"x" * (MAX_BODY + 1), auth(TOKEN), 413),
                (PUBLIC_PREFIX + "/decisions", b"{}", [("Authorization", "Bearer " + TOKEN)] * 2, 401),
                (PUBLIC_PREFIX + "/decisions", b"{}", {**auth(TOKEN), "Content-Encoding": "gzip"}, 400),
                (PUBLIC_PREFIX + "/decisions", b"{}", {**auth(TOKEN), "Content-Length": "1000000000000"}, 400),
                (PUBLIC_PREFIX + "/decisions", b"{}", {**auth(TOKEN), "Content-Length": "4"}, 400),
                (PUBLIC_PREFIX + "/admin/publish-marks", b"{}", auth(TOKEN), 404),
                (PUBLIC_PREFIX + "/actions%2Fblock-ip", b"{}", auth(TOKEN), 400),
            ]
            for path, body, headers, status in cases:
                result = client.post(path, content=body, headers=headers)
                assert result.status_code == status, result.text
            assert not calls


@pytest.mark.parametrize("failure", ["redirect", "oversize", "headers", "truncated", "slow"])
def test_backend_limits_and_redirect_refusal(make_client, failure):
    def reply(handler):
        if failure == "redirect":
            response(handler, b"{}", 307, [("Location", "https://example.invalid/collect")])
            return
        handler.send_response(200)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(MAX_RESPONSE + 1 if failure == "oversize" else 10))
        if failure == "headers":
            handler.send_header("X-Large", "x" * 16385)
        handler.end_headers()
        if failure == "slow":
            for _ in range(10):
                handler.wfile.write(b" ")
                handler.wfile.flush()
                time.sleep(0.1)

    with backend(reply) as (port, _):
        with make_client(**client_options(port, scoring_gateway_timeout_seconds=0.2)) as client:
            started = time.monotonic()
            result = client.get(PUBLIC_PREFIX + "/receipts", headers=auth(TOKEN))
            assert result.status_code == {"redirect": 502, "oversize": 413}.get(failure, 503)
            assert time.monotonic() - started < 1
            assert "location" not in result.headers


def test_bounded_sse_batch_and_connection_capacity():
    data = b'event: cursor\ndata: {"next_cursor":"next"}\n\n'

    def reply(handler):
        handler.send_response(200)
        handler.send_header("Content-Type", "text/event-stream")
        handler.send_header("Content-Length", str(len(data)))
        handler.end_headers()
        handler.wfile.write(data)

    with backend(reply) as (port, _):
        proxy = ScoringProxy(port)
        assert proxy.forward("GET", "telemetry/stream", "Bearer " + TOKEN).body == data
        for _ in range(16):
            assert proxy.slots.acquire(False)
        try:
            with pytest.raises(ProxyFailure, match="scoring_backend_busy"):
                proxy.forward("GET", "receipts", "Bearer " + TOKEN)
        finally:
            for _ in range(16):
                proxy.slots.release()


@pytest.fixture
def actual_gateway():
    spec = importlib.util.spec_from_file_location("scoring_boundary_fixtures", REPO / "observability/tests/test-scoring-ai.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    fixture = module.Fixture()
    fixture.setUp()
    server = module.Server(("127.0.0.1", 0), fixture.gateway)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        yield module, fixture, server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)
        fixture.doCleanups()


def test_actual_gateway_authentication_provenance_and_kill_switch(make_client, actual_gateway):
    module, fixture, port = actual_gateway
    with make_client(**client_options(port, admin_token=module.OPERATOR_TOKEN)) as client:
        # This token is not in AIC's static team list. The canonical backend
        # authenticates it; the facade neither substitutes nor guesses grants.
        headers = auth(module.TOKEN)
        assert client.get(PUBLIC_PREFIX + "/assets", headers=headers).status_code == 200
        assert client.get(PUBLIC_PREFIX + "/assets", headers=auth(TOKEN)).status_code == 401
        decision = fixture.decision()
        incomplete = {key: value for key, value in decision.items() if key != "case_id"}
        assert client.post(PUBLIC_PREFIX + "/decisions", json=incomplete, headers=headers).status_code == 400
        result = client.post(PUBLIC_PREFIX + "/decisions", json=decision, headers=headers)
        assert result.status_code == 201 and result.json()["receipt"]["team_id"] == module.TEAM
        assert client.post(PUBLIC_PREFIX + "/decisions", json=decision, headers=headers).json()["duplicate"] is True
        request = module.block()
        result = client.post(PUBLIC_PREFIX + "/actions/block-ip", json=request, headers=headers)
        assert result.status_code == 202 and result.json()["state"] == "verified"
        action_id = result.json()["action_id"]
        assert action_id.startswith("aia_") and fixture.nft.active == {action_id}
        assert client.get(API + "/admin/kill-switch", headers=auth(module.OPERATOR_TOKEN)).json() == {"on": False}
        assert client.post(PUBLIC_PREFIX + "/kill-switch", json={"enabled": True}, headers=headers).status_code == 403
        result = client.post(API + "/admin/kill-switch", json={"on": True}, headers=auth(module.OPERATOR_TOKEN))
        assert result.status_code == 200 and result.json() == {"on": True}
        assert fixture.act_store.meta("kill_switch") == "on" and not fixture.nft.active
        assert fixture.act_store.action(action_id=action_id)["state"] == "reverted"
        assert client.get(API + "/admin/kill-switch", headers=auth(module.OPERATOR_TOKEN)).json() == {"on": True}
        assert client.post(PUBLIC_PREFIX + "/decisions", json=fixture.decision(2), headers=headers).status_code == 201
        assert client.get(PUBLIC_PREFIX + "/assets", headers=headers).status_code == 200
        assert client.post(PUBLIC_PREFIX + "/actions/block-ip", json=module.block("later"), headers=headers).status_code == 403
        with client.app.state.sessions() as db:
            assert db.get(Setting, "kill_switch") is None
            assert db.scalar(select(func.count(Action.id))) == 0
            assert db.scalar(select(func.count(Decision.id))) == 0


def test_admin_authorization_cannot_elevate_without_backend_operator_grant(make_client, actual_gateway):
    module, fixture, port = actual_gateway
    with make_client(**client_options(port, admin_token=module.TOKEN)) as client:
        result = client.post(API + "/admin/kill-switch", json={"on": True}, headers=auth(module.TOKEN))
        assert result.status_code == 403
        assert fixture.act_store.meta("kill_switch") != "on"


def test_unconfirmed_revocation_and_missing_backend_never_report_success(make_client):
    with backend(lambda h: response(h, b'{"kill_switch":true,"unresolved_actions":1}')) as (port, calls):
        with make_client(**client_options(port, admin_token=TOKEN)) as client:
            result = client.post(API + "/admin/kill-switch", content=b'{"on":true}',
                                 headers={**auth(TOKEN), "Content-Type": "application/json", "Content-Length": "1"})
            assert result.status_code == 400 and not calls
            result = client.post(API + "/admin/kill-switch", json={"on": True}, headers=auth(TOKEN))
            assert result.status_code == 503 and result.json()["on"] is True
            assert result.json()["error"] == "scoring_revocation_incomplete"
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))
        with make_client(**client_options(reserved.getsockname()[1], admin_token=TOKEN)) as client:
            assert client.post(API + "/admin/kill-switch", json={"on": True}, headers=auth(TOKEN)).status_code == 503
            assert client.get(API + "/admin/kill-switch", headers=auth(TOKEN)).status_code == 503


def test_legacy_publisher_is_disabled_even_with_configured_credentials(monkeypatch, capsys):
    monkeypatch.setenv("SCORING_MODE", "1")
    monkeypatch.setenv("ADMIN_TOKEN", TOKEN)
    monkeypatch.setenv("WEBSITE_FEED_URL", "https://example.invalid/api/feed")
    monkeypatch.setenv("WEBSITE_FEED_TOKEN", TOKEN)
    monkeypatch.delenv("SANDBOX_SEED", raising=False)
    settings = Settings()
    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **kw: pytest.fail("legacy publication attempted"))
    with pytest.raises(ValueError, match="website_scoring_authority"):
        marks_for(None, SimpleNamespace(settings=settings))
    with pytest.raises(RuntimeError, match="website_scoring_authority"):
        publish(settings, [])
    spec = importlib.util.spec_from_file_location("legacy_publisher", REPO / "ai-api/scripts/publish-marks.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(sys, "argv", ["publish-marks.py", "--api", "https://example.invalid", "--preview"])
    assert module.main() == 0
    assert "disabled" in capsys.readouterr().out
    monkeypatch.setenv("SCORING_MODE", "misspelled")
    assert module.main() == 2
    assert "publication refused" in capsys.readouterr().err


def test_contracts_keep_separate_public_namespaces_and_evidence_semantics():
    legacy = yaml.safe_load((REPO / "contracts/ai-api/openapi.yaml").read_text())
    scoring = yaml.safe_load((REPO / "contracts/ai-api/scoring-openapi.yaml").read_text())
    assert legacy["info"]["version"] == "1.3.0"
    assert scoring["servers"] == [{"url": PUBLIC_PREFIX}]
    assert "get" in scoring["paths"]["/kill-switch"]
    assert "workload restoration" in scoring["x-snapshot-and-revert"]
