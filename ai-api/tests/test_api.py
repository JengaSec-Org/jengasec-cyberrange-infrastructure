import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import yaml

from app.auth import Team
from app.routers import stream_events
from conftest import (ADMIN, BLUE, BLUE2, INGEST, RED, RED2, REPO, RI01_EVENTS, SCENARIO_EVENTS, TEAMS, auth,
                      fixture_event, v2_event)

API = "/api/v1"
RI01 = TEAMS["RI-01"]["team_id"]
NS = "jengasec-ent-a-app03"


def all_events(client, token, limit=1000):
    out, cursor = [], None
    while True:
        params = {"limit": limit} | ({"cursor": cursor} if cursor else {})
        r = client.get(f"{API}/telemetry/events", params=params, headers=auth(token))
        assert r.status_code == 200, r.text
        page = r.json()
        out += page["events"]
        cursor = page["next_cursor"]
        if not page["has_more"]:
            return out, cursor


def burst(ip, team_id, label, n=6, **kw):
    return [v2_event(i, ip, team_id, label, **kw) for i in range(n)]


def ndjson(events):
    return "\n".join(json.dumps(e) for e in events) + "\n"


# --------------------------------------------------------------------------- auth and roles

def test_healthz_needs_no_token(client):
    assert client.get("/healthz").json() == {"status": "ok"}


def test_missing_and_unknown_tokens(client):
    assert client.get(f"{API}/telemetry/events").status_code == 401
    assert client.get(f"{API}/telemetry/events", headers=auth("nope")).status_code == 401
    assert client.get(f"{API}/assets", headers=auth("tok-unknown-team")).status_code == 401
    assert client.get(f"{API}/telemetry/events", headers=auth(INGEST)).status_code == 401


def test_ai_blue_sees_everything_in_both_enterprises(client):
    events, _ = all_events(client, BLUE)
    assert len(events) == sum(SCENARIO_EVENTS.values())
    assert {e["enterprise"] for e in events} == {"ENT-A", "ENT-B"}
    assert all(e["schema_version"] == "2.0" for e in events)
    assert all_events(client, BLUE2)[0] == events          # identical data: a fair head-to-head


def test_ai_red_sees_only_its_own_traffic(client):
    events, _ = all_events(client, RED)
    assert len(events) == RI01_EVENTS
    assert {e["actor"]["team_id"] for e in events} == {RI01}
    assert {e["actor"]["team_label"] for e in events} == {"red-ai"}
    assert all_events(client, RED2)[0] == []


def test_ai_red_cannot_decide_or_act(client):
    body = {"target": {"namespace": NS}, "justification": "x"}
    assert client.post(f"{API}/actions/alert", json=body, headers=auth(RED)).status_code == 403
    events, _ = all_events(client, RED)
    decision = {"incident_id": "i", "summary": "x", "confidence": 0.5, "evidence": [events[0]["event_id"]]}
    assert client.post(f"{API}/decisions", json=decision, headers=auth(RED)).status_code == 403


# --------------------------------------------------------------------------- ground truth

def test_scenario_labels_match_the_answer_keys(client):
    events, _ = all_events(client, BLUE)
    keys = [yaml.safe_load(p.read_text(encoding="utf-8")) for p in (REPO / "scenarios").glob("s*/answer-key.yaml")]
    malicious = {i for k in keys for i in k["malicious_event_ids"]}
    for e in events:
        assert (e.get("actor", {}).get("team_label", "").startswith("red-")) == (e["event_id"] in malicious)


def test_ingest_keeps_obs_attribution_and_never_guesses(empty_client):
    unattributed = v2_event(1, "10.60.2.14", None, None)
    unattributed["actor"] = {"ip": "10.60.2.14"}
    assert empty_client.post(f"{API}/ingest", json=[unattributed], headers=auth(INGEST)).json()["rejected"] == []
    stored = all_events(empty_client, BLUE)[0][0]
    assert stored["actor"] == {"ip": "10.60.2.14"}       # no label invented: OBS owns attribution


# --------------------------------------------------------------------------- cursor paging

def test_cursor_paging_has_no_gaps_or_duplicates(client):
    small, _ = all_events(client, BLUE, limit=7)
    big, _ = all_events(client, BLUE, limit=1000)
    assert [e["event_id"] for e in small] == [e["event_id"] for e in big]
    assert len({e["event_id"] for e in small}) == len(small)


def test_red_paging_skips_other_teams(client):
    assert len(all_events(client, RED, limit=4)[0]) == RI01_EVENTS


def test_caught_up_cursor_keeps_position(client):
    _, cursor = all_events(client, BLUE)
    page = client.get(f"{API}/telemetry/events", params={"cursor": cursor}, headers=auth(BLUE)).json()
    assert page == {"events": [], "next_cursor": cursor, "has_more": False}


def test_bad_cursor_and_limit(client):
    assert client.get(f"{API}/telemetry/events", params={"cursor": "!!"}, headers=auth(BLUE)).status_code == 400
    assert client.get(f"{API}/telemetry/events", params={"limit": 1001}, headers=auth(BLUE)).status_code == 422


def test_since_filter(client):
    page = client.get(f"{API}/telemetry/events", params={"since": "2026-10-10T09:07:00Z", "limit": 1000},
                      headers=auth(BLUE)).json()
    assert page["events"] and all(e["ts"] >= "2026-10-10T09:07:00" for e in page["events"])


# --------------------------------------------------------------------------- ingest

def test_ingest_obs_fixtures_json_array(empty_client):
    valid = [fixture_event(f"valid/{n}") for n in ("attributed-request.json", "refused-flow.json", "observability-smoke.json")]
    invalid = [fixture_event("invalid/extra-top-level-field.json"), fixture_event("invalid/platform-event.json")]
    r = empty_client.post(f"{API}/ingest", json=[valid[0], invalid[0], valid[1], "junk", invalid[1], valid[2], valid[0]],
                          headers=auth(INGEST))
    assert r.status_code == 202
    body = r.json()
    assert body["accepted"] == 4                      # three valid, plus valid[0] again (stored once)
    assert [x["index"] for x in body["rejected"]] == [1, 3, 4]
    # OBS's attributed-request and refused-flow fixtures share the placeholder id evt_aaaa…, so one is a re-send
    assert len(all_events(empty_client, BLUE)[0]) == len({e["event_id"] for e in valid}) == 2


def test_ingest_ndjson_like_vector(empty_client):
    events = burst("10.60.5.14", "JS26-R-005", "red-app", n=3)
    r = empty_client.post(f"{API}/ingest", content=ndjson(events) + "not json\n",
                          headers={**auth(INGEST), "Content-Type": "application/x-ndjson"})
    assert r.json() == {"accepted": 3, "rejected": [{"index": 3, "error": "not a JSON object"}]}


def test_ingest_rejects_unknown_namespace_and_mismatched_identity(empty_client):
    bad_ns = v2_event(1, "10.60.1.10", "JS26-R-001", "red-app")
    bad_ns["namespace"] = bad_ns["target"]["namespace"] = "jengasec-ent-a-app09"
    bad_ns["application"] = "APP08"                   # namespace says APP09
    r = empty_client.post(f"{API}/ingest", json=[bad_ns], headers=auth(INGEST)).json()
    assert r["accepted"] == 0 and "APP09" in r["rejected"][0]["error"]


def test_ingest_needs_ingest_token(empty_client):
    assert empty_client.post(f"{API}/ingest", json=[], headers=auth(BLUE)).status_code == 401


def test_every_scenario_event_is_contract_valid(empty_client):
    for path in sorted((REPO / "scenarios").glob("s*/events.jsonl")):
        r = empty_client.post(f"{API}/ingest", content=path.read_text(encoding="utf-8"), headers=auth(INGEST)).json()
        assert r["rejected"] == [], (path.parent.name, r["rejected"][:2])


# --------------------------------------------------------------------------- stream

def collect_stream(client, team):
    class FakeRequest:
        app = client.app

        async def is_disconnected(self):
            return True

    async def run():
        return [chunk async for chunk in stream_events(FakeRequest(), team, 0, once=True)]

    return asyncio.run(run())


def test_stream_is_sse_and_filtered_per_team(client):
    chunks = collect_stream(client, Team("RI-01", "ai-red", "AI-01", RI01))
    assert len(chunks) == RI01_EVENTS
    first = chunks[0].split("\n")
    assert first[0].startswith("id: ") and first[1].startswith("data: ")
    assert json.loads(first[1][6:])["actor"]["team_id"] == RI01
    assert len(collect_stream(client, Team("AI-01", "ai-blue", None, TEAMS["AI-01"]["team_id"]))) == sum(SCENARIO_EVENTS.values())


# --------------------------------------------------------------------------- assets and alerts

def test_assets_cover_all_applications(client):
    assets = client.get(f"{API}/assets", headers=auth(RED)).json()
    assert len(assets) == 18 and {a["enterprise"] for a in assets} == {"ENT-A", "ENT-B"}
    assert {a["ip"] for a in assets} == {f"10.108.0.{n}" for n in [*range(11, 20), *range(21, 30)]}
    assert assets[0] == {"asset_id": "jengasec-ent-a-app01/app", "enterprise": "ENT-A", "application": "APP01",
                         "namespace": "jengasec-ent-a-app01", "ip": "10.108.0.11", "service": "Internet Banking Portal",
                         "optional": False, "enabled": True}


def test_baseline_alerts_catch_s01_but_not_ai_red_evasion(client):
    alerts = client.get(f"{API}/alerts", headers=auth(BLUE)).json()
    bursts = [a for a in alerts if a["rule"] == "auth_failure_burst"]
    assert [b["namespace"] for b in bursts] == [NS] and bursts[0]["severity"] == "high"
    key = yaml.safe_load((REPO / "scenarios/s01-credential-stuffing/answer-key.yaml").read_text(encoding="utf-8"))
    assert set(bursts[0]["evidence"]) <= set(key["malicious_event_ids"])
    assert any(a["rule"] == "high_severity_event" and a["namespace"] == "jengasec-ent-a-app01" for a in alerts)
    assert client.get(f"{API}/alerts", headers=auth(RED)).json() == []        # low and slow: nothing fired


def test_ai_red_sees_only_alerts_its_traffic_triggered(client):
    mine = burst("10.64.1.10", RI01, "red-ai")
    theirs = burst("10.60.9.9", "JS26-R-009", "red-app", application="APP04")
    client.post(f"{API}/ingest", json=mine + theirs, headers=auth(INGEST))
    red = client.get(f"{API}/alerts", headers=auth(RED)).json()
    assert len(red) == 1 and red[0]["rule"] == "auth_failure_burst"
    assert set(red[0]["evidence"]) <= {e["event_id"] for e in mine}
    blue = client.get(f"{API}/alerts", headers=auth(BLUE)).json()
    assert len([a for a in blue if a["rule"] == "auth_failure_burst"]) == 3


# --------------------------------------------------------------------------- actions

def act(client, type_, namespace=NS, token=BLUE, ip="10.60.5.14", **extra):
    body = {"target": {"namespace": namespace, "ip": ip}, "justification": "credential stuffing burst", **extra}
    return client.post(f"{API}/actions/{type_}", json=body, headers=auth(token))


def test_shadow_mode_only_alert_is_effective(client):
    r = act(client, "block-ip")
    assert r.status_code == 202
    assert r.json()["effective"] is False and r.json()["status"] == "recorded"
    assert act(client, "alert").json()["effective"] is True


def test_ai_blue_may_act_in_both_enterprises(client):
    assert act(client, "block-ip", namespace="jengasec-ent-b-app03").status_code == 202
    assert act(client, "block-ip", namespace="jengasec-ent-c-app03").status_code == 422
    assert act(client, "block-ip", namespace="enta-app03").status_code == 422      # retired naming


def test_unknown_action_type_and_missing_justification(client):
    assert act(client, "delete-everything").status_code == 422
    r = client.post(f"{API}/actions/alert", json={"target": {"namespace": NS}, "justification": ""}, headers=auth(BLUE))
    assert r.status_code == 422


def test_budget_is_per_team(client):
    for remaining in (2, 1, 0):
        assert act(client, "rate-limit").json()["budget_remaining"] == remaining
    assert act(client, "rate-limit").status_code == 403
    assert act(client, "rate-limit", token=BLUE2).status_code == 202


def test_kill_switch_halts_and_records(client):
    assert client.post(f"{API}/admin/kill-switch", json={"on": True}, headers=auth(BLUE)).status_code == 401
    assert client.post(f"{API}/admin/kill-switch", json={"on": True}, headers=auth(ADMIN)).json() == {"on": True}
    r = act(client, "alert")
    assert r.status_code == 423 and r.json()["status"] == "halted" and r.json()["effective"] is False
    client.post(f"{API}/admin/kill-switch", json={"on": False}, headers=auth(ADMIN))
    assert act(client, "alert").status_code == 202


def test_revert(client):
    action_id = act(client, "block-ip").json()["action_id"]
    assert client.post(f"{API}/actions/{action_id}/revert", headers=auth(BLUE2)).status_code == 403
    assert client.post(f"{API}/actions/act-999999/revert", headers=auth(BLUE)).status_code == 404
    r = client.post(f"{API}/actions/{action_id}/revert", headers=auth(BLUE))
    assert r.status_code == 202 and r.json()["status"] == "reverted"


# --------------------------------------------------------------------------- decisions

def test_decision_with_valid_evidence_and_handoff(client):
    events, _ = all_events(client, BLUE)
    evidence = [events[0]["event_id"]]
    handoff = {"handoff_id": "h1", "ts": "2026-10-10T09:10:00Z", "from_cell": "AI-01", "to_cell": "AI-01",
               "incident_id": "inc-1", "hypothesis": "credential stuffing", "confidence": 0.8, "severity": "high",
               "evidence": evidence, "recommended_actions": [{"type": "block-ip"}]}
    r = client.post(f"{API}/decisions", headers=auth(BLUE), json={
        "incident_id": "inc-1", "summary": "Burst of failed logins then a takeover", "confidence": 0.8,
        "evidence": evidence, "handoff": handoff})
    assert r.status_code == 201 and r.json()["decision_id"].startswith("dec-")


def test_decision_evidence_must_exist(client):
    body = {"incident_id": "inc-2", "summary": "x", "confidence": 0.5, "evidence": ["evt_does-not-exist"]}
    assert client.post(f"{API}/decisions", json=body, headers=auth(BLUE)).status_code == 422
    body["evidence"] = []
    assert client.post(f"{API}/decisions", json=body, headers=auth(BLUE)).status_code == 422


def test_decision_bad_handoff(client):
    events, _ = all_events(client, BLUE)
    body = {"incident_id": "i", "summary": "x", "confidence": 0.5, "evidence": [events[0]["event_id"]],
            "handoff": {"handoff_id": "h"}}
    assert client.post(f"{API}/decisions", json=body, headers=auth(BLUE)).status_code == 422


# --------------------------------------------------------------------------- judges' export and ground truth

def play_ai_01(client):
    """AI-01 cites 10 RI-01 events and 10 legitimate ones, blocks the framed Blue owner and the real sender."""
    events, _ = all_events(client, BLUE)
    red_ai = [e["event_id"] for e in events if e.get("actor", {}).get("team_label") == "red-ai"][:10]
    benign = [e["event_id"] for e in events if e.get("actor", {}).get("team_label") == "blue-app"][:10]
    client.post(f"{API}/decisions", headers=auth(BLUE), json={
        "incident_id": "inc-ri", "summary": "low and slow password guessing from 10.64.1.0/24 across both APP03s",
        "confidence": 0.7, "evidence": red_ai + benign})
    act(client, "block-ip", ip="10.61.1.12", evidence=red_ai[:1])   # the spoofed Blue owner: a false action
    act(client, "block-ip", ip="10.64.1.12")                         # the real sender: fine
    return red_ai


def test_export_scores_ai_blue_and_ai_red_against_labels(client):
    play_ai_01(client)
    blue = client.get(f"{API}/admin/export/AI-01", headers=auth(ADMIN)).json()
    gt = blue["ground_truth"]
    assert blue["team_id"] == TEAMS["AI-01"]["team_id"]
    assert gt["precision"] == 0.5 and gt["evidence_attack"] == 10
    assert gt["recall"] == round(10 / gt["attack_events_total"], 4)
    assert [f["target"]["ip"] for f in gt["false_actions"]] == ["10.61.1.12"]
    assert gt["correlated_decisions"] == 1 and gt["substantive_decisions"] == 1

    red = client.get(f"{API}/admin/export/RI-01", headers=auth(ADMIN)).json()["ground_truth"]
    assert red["own_events"] == RI01_EVENTS and red["detected_by_paired_blue"] == 10
    assert red["missed_by_paired_blue"] == RI01_EVENTS - 10 and len(red["false_actions_caused"]) == 1
    assert red["applications_targeted"] == 4          # s04: both APP03s, ENT-A APP01, ENT-B APP02
    assert client.get(f"{API}/admin/export/AI-01", headers=auth(BLUE)).status_code == 401
    assert client.get(f"{API}/admin/export/ZZ-01", headers=auth(ADMIN)).status_code == 404


def test_marks_follow_the_website_marking_scheme(client):
    play_ai_01(client)
    rows = client.get(f"{API}/admin/marks", headers=auth(ADMIN)).json()
    by = {(r["code"], r["criterion"]): r for r in rows}
    caps = {"precision": 12, "recall": 10, "correlation": 8, "decisions": 6, "safety": 4,
            "missed": 16, "false": 16, "breadth": 8}
    assert all(0 <= r["marks"] <= caps[r["criterion"]] for r in rows)
    assert by[("AI-01", "precision")]["marks"] == 6.0          # 12 x 0.5
    assert by[("AI-01", "safety")]["marks"] == 2.0             # 4 x (1 - 1/2)
    assert by[("AI-03", "safety")]["marks"] == 0.0             # did nothing: safety is not free
    assert by[("RI-01", "false")]["marks"] == round(16 / 3, 2)
    assert by[("AI-01", "precision")]["team"] == TEAMS["AI-01"]["team_id"]
    assert by[("AI-01", "precision")]["key"] == "aic:precision:all" and "day" not in by[("AI-01", "precision")]
    assert len(rows) == 3 * 5 + 6 * 3


def test_marks_per_engagement_day(make_client):
    with make_client(engagement_days="1=2026-10-10,2=2026-10-11") as c:
        rows = c.get(f"{API}/admin/marks", params={"day": 1}, headers=auth(ADMIN)).json()
        assert {r["key"].rsplit(":", 1)[1] for r in rows} == {"day1"} and {r["day"] for r in rows} == {1}
        assert c.get(f"{API}/admin/marks", params={"day": 3}, headers=auth(ADMIN)).status_code == 422


def test_publish_marks_reaches_the_website_feed(make_client):
    received = []

    class Feed(BaseHTTPRequestHandler):
        def do_POST(self):
            received.append((self.path, dict(self.headers), json.loads(self.rfile.read(int(self.headers["Content-Length"])))))
            body = json.dumps({"accepted": len(received[-1][2]["scores"]), "rejected": []}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    server = HTTPServer(("127.0.0.1", 0), Feed)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_port}/api/feed/"
    try:
        with make_client(website_feed_url=url, website_feed_token="feed-secret", website_competition="6") as c:
            r = c.post(f"{API}/admin/publish-marks", headers=auth(ADMIN)).json()
        assert r["website_status"] == 200 and r["sent"] == 33
        path, headers, body = received[0]
        assert path == "/api/feed/" and headers["X-Feed-Token"] == "feed-secret" and body["competition"] == 6
        assert set(body["scores"][0]) <= {"team", "stage", "criterion", "marks", "note", "key", "day"}
    finally:
        server.shutdown()


def test_publish_marks_needs_configuration(client):
    assert client.post(f"{API}/admin/publish-marks", headers=auth(ADMIN)).status_code == 409


def test_admin_teams_overview(client):
    teams = {t["code"]: t for t in client.get(f"{API}/admin/teams", headers=auth(ADMIN)).json()}
    assert len(teams) == 9
    assert teams["AI-01"]["token_issued"] and not teams["AI-03"]["token_issued"]
    assert teams["RI-01"]["own_events"] == RI01_EVENTS and teams["RI-01"]["paired"] == "AI-01"


# --------------------------------------------------------------------------- the contract and the code agree

def test_every_contract_path_is_implemented(client):
    spec = yaml.safe_load((REPO / "contracts/ai-api/openapi.yaml").read_text(encoding="utf-8"))
    routes = {(m.lower(), r.path) for r in client.app.routes for m in getattr(r, "methods", set())}
    # Included routers may be stored lazily. Generated OpenAPI resolves their
    # mounted paths; the direct route list also covers hidden health endpoints.
    routes.update((method, path) for path, methods in client.app.openapi()["paths"].items() for method in methods)
    for path, ops in spec["paths"].items():
        for method in ops:
            assert (method, f"/api/v1{path}") in routes, f"{method.upper()} {path} is in the contract but not implemented"


def test_seed_is_idempotent(make_client):
    with make_client() as c:
        first, _ = all_events(c, BLUE)
    with make_client() as c:          # same database, seeded again
        second, _ = all_events(c, BLUE)
    assert len(first) == len(second)
