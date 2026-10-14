#!/usr/bin/env python3
"""AI boundary tests use private files and disposable loopback HTTP servers."""

import copy
import contextlib
import hashlib
import http.client
import json
import os
import pathlib
import socket
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from scoring_ai.actuator import Actuator, Nft, RemoteActuator, Verifier
from scoring_ai.authority import Authority, Tokens
from scoring_ai.common import Rejected, canonical, decode_json, digest, run_bounded, stamp
from scoring_ai.gateway import Gateway
from scoring_ai.http_api import Server
from scoring_ai.probe import FunctionalProbe
from scoring_ai.platform_bridge import PlatformBridge, receipt_uuid
from scoring_ai.store import Store
from scoring_ai.telemetry import Cursors, Telemetry


NOW = 1791979200.0
TEAM = "JS26-AIB-001"
RED = "JS26-AIR-001"
TARGET = "ENT-A/APP01"
TOKEN = "cell-fixture-token-" + "a" * 40
OTHER_TOKEN = "other-fixture-token-" + "b" * 40
OBSERVER_TOKEN = "observer-fixture-token-" + "c" * 40
OPERATOR_TOKEN = "operator-fixture-token-" + "d" * 40


def write_json(path, value):
    path.write_bytes(canonical(value))
    path.chmod(0o600)


def identity(now=NOW):
    interval = {"revision": 1, "valid_from": stamp(now - 3600), "valid_until": stamp(now + 3600)}
    blue = {**interval, "team": TEAM, "side": "blue", "track": "ai", "enterprise": "ENT-A", "cell_id": "AIB01", "namespace": "ai-blue-01"}
    red = {**interval, "team": RED, "side": "red", "track": "ai", "enterprise": "ENT-A", "cell_id": "AIR01", "namespace": "ai-red-01"}
    return {"schema_version": "scoring-identity/2.0", "revision": 1, "captured_at": stamp(now - 1), "expires_at": stamp(now + 119),
            "competition": {"id": 1, "start": stamp(now - 3600), "end": stamp(now + 3600)},
            "teams": [blue, red], "allocations": [{**interval, "team": RED, "source_ip": "10.50.0.12"}],
            "targets": [{**interval, "target_id": TARGET, "team": TEAM, "enterprise": "ENT-A", "application": "APP01", "namespace": "jengasec-ent-a-app01",
                         "ip_address": "10.60.0.11", "port": 8080, "protocol": "tcp", "frozen_digest": "sha256:" + "1" * 64, "verified_at": stamp(now - 100)}],
            "scopes": [{**interval, "scope_id": "test-scope-1", "team": TEAM, "target_id": TARGET, "source_cidr": "10.50.0.12/32",
                        "allowed_actions": ["alert", "block-ip", "snapshot-evidence"], "active": True}]}


def block(key="block-1"):
    return {"key": key, "case_id": "case-1", "target_id": TARGET, "source_ip": "10.50.0.12", "ttl_seconds": 60, "evidence_refs": []}


class FakeNft:
    """In-memory rule effects only; no test changes the host firewall."""

    def __init__(self):
        self.active, self.applied, self.removed = set(), 0, 0
        self.after_apply = None

    def setup(self):
        pass

    def apply(self, action, now):
        self.active.add(action["action_id"])
        self.applied += 1
        if self.after_apply:
            self.after_apply()

    def contains(self, action):
        return action["action_id"] in self.active

    def remove(self, action):
        self.active.discard(action["action_id"])
        self.removed += 1


class FakeVerifier:
    def __init__(self):
        self.fail_phase, self.callback, self.calls = None, None, []

    def check(self, action, phase):
        self.calls.append(phase)
        if self.callback:
            self.callback(phase)
        success = phase != "after"
        if phase == self.fail_phase:
            success = not success
        return {"functional_success": success, "control_success": True,
                "evidence_refs": [{"family": "ai", "id": "air_" + "a" * 64}]}


class LocalTransport:
    def __init__(self, actuator):
        self.actuator = actuator

    def call(self, operation, token=None, **kwargs):
        return self.actuator.dispatch({"operation": operation, "token": token or OPERATOR_TOKEN, **kwargs})


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)
        self.now = NOW
        self.snapshot = self.root / "identity.json"
        write_json(self.snapshot, identity())
        self.token_file = self.root / "tokens.json"
        principals = []
        for token, kind, team, cell, source in ((TOKEN, "competitor", TEAM, "AIB01", "blue-detector"),
                                               (OTHER_TOKEN, "competitor", RED, "AIR01", "red-agent"),
                                               (OBSERVER_TOKEN, "observer", TEAM, "AIB01", "runtime-observer"),
                                               (OPERATOR_TOKEN, "operator", None, None, "gateway-sync")):
            principals.append({"sha256": hashlib.sha256(token.encode()).hexdigest(), "kind": kind,
                               "team": team, "cell_id": cell, "source_id": source, "epoch": "boot-1",
                               "checks": ["deterministic", "model", "combined", "fallback", "scope", "budget", "reversal", "kill_switch"]})
        write_json(self.token_file, {"principals": principals})
        self.tokens = Tokens(self.token_file)
        self.authority = Authority(self.snapshot, ["10.50.0.0/24", "10.60.0.0/24"], ["10.50.0.1/32", "10.60.0.1/32"], [9090])
        self.act_store = Store(self.root / "actuator" / "state.sqlite", "actuator")
        self.store = Store(self.root / "gateway" / "state.sqlite", "gateway")
        self.nft, self.verifier = FakeNft(), FakeVerifier()
        self.actuator = Actuator(self.tokens, self.authority, self.act_store, self.nft, self.verifier, lambda: self.now)
        self.spool = self.root / "spool"
        self.spool.mkdir()
        self.telemetry = Telemetry(self.spool, self.authority, Cursors("cursor-fixture-secret-" + "z" * 32))
        self.gateway = Gateway(self.tokens, self.authority, self.store, self.telemetry, LocalTransport(self.actuator), self.root / "archive", lambda: self.now)
        self.principal = self.tokens.authenticate(TOKEN)

    def mutate_identity(self, change):
        value = json.loads(self.snapshot.read_text())
        change(value)
        write_json(self.snapshot, value)

    def expect_code(self, code, function, *args):
        with self.assertRaises(Rejected) as error:
            function(*args)
        self.assertEqual(error.exception.code, code)

    def decision(self, sequence=1):
        return {"epoch": "boot-1", "source_sequence": sequence, "occurred_at": stamp(self.now), "target_id": TARGET,
                "case_id": "case-1", "classification": "attack", "incident_id": "incident-1", "rationale_code": "model_anomaly",
                "evidence_refs": [{"family": "application", "id": "evt_" + "1" * 64}], "action_id": None, "clock_uncertainty_seconds": 0.5}

    def event(self, **changes):
        return {"schema_version": "2.0", "catalogue_version": 1, "stream": "telemetry", "event_id": "evt_" + "1" * 64,
                "integrity_hash": "sha256:" + "2" * 64, "ts": stamp(self.now), "received_ts": stamp(self.now),
                "enterprise": "ENT-A", "application": "APP01", "namespace": "jengasec-ent-a-app01", "asset": "app",
                "source": "application", "event_type": "http_request", "severity": "low", "outcome": "success", "verdict": "allowed", **changes}

    def spool_events(self, *events):
        import datetime
        name = datetime.datetime.fromtimestamp(self.now, datetime.timezone.utc).strftime("telemetry-%Y-%m-%d-%H-%M.ndjson")
        path = self.spool / name
        path.write_bytes(b"".join(canonical(e) + b"\n" for e in events))
        return path


class AuthorityTests(Fixture):
    def test_tokens_are_scoped_and_owner_only(self):
        self.assertEqual(self.principal["team"], TEAM)
        self.assertNotIn("sha256", self.principal)
        self.expect_code("unauthorized", self.tokens.authenticate, "unregistered" * 10)
        self.token_file.chmod(0o644)
        self.expect_code("insecure_secret_permissions", self.tokens.authenticate, TOKEN)

    def test_tampered_and_duplicate_identity_fail_closed(self):
        for mutate, code in (
            (lambda s: s.update(expires_at=stamp(self.now)), "stale_identity"),
            (lambda s: s["targets"].append(copy.deepcopy(s["targets"][0])), "unresolved_or_ambiguous_identity"),
            (lambda s: s["allocations"].append(copy.deepcopy(s["allocations"][0])), "unresolved_or_ambiguous_identity"),
            (lambda s: s["scopes"].append(copy.deepcopy(s["scopes"][0])), "unresolved_or_ambiguous_identity"),
            (lambda s: s["targets"][0].update(port=22), "protected_service"),
            (lambda s: s["targets"][0].update(ip_address="10.60.0.1"), "protected_network"),
            (lambda s: s["targets"][0].update(ip_address="127.0.0.1"), "invalid_address"),
            (lambda s: s["targets"][0].update(frozen_digest="image:latest"), "unverified_workload"),
            (lambda s: s["scopes"][0].update(active=False), "unresolved_or_ambiguous_identity"),
        ):
            with self.subTest(code=code):
                write_json(self.snapshot, identity())
                self.mutate_identity(mutate)
                self.expect_code(code, self.actuator.execute, TOKEN, block())
                self.assertEqual(self.nft.applied, 0)

    def test_unassigned_source_and_principal_cannot_act(self):
        self.expect_code("unresolved_or_ambiguous_identity", self.actuator.execute, OTHER_TOKEN, block())
        body = block()
        body["source_ip"] = "10.50.0.15"
        self.expect_code("unresolved_or_ambiguous_identity", self.actuator.execute, TOKEN, body)

    def test_expiry_shortens_lease_and_source_change_stops_action(self):
        self.mutate_identity(lambda s: s["scopes"][0].update(valid_until=stamp(self.now + 20)))
        result = self.actuator.execute(TOKEN, block())
        self.assertEqual(result["lease_expires_at"], stamp(self.now + 20))
        self.now += 21
        self.actuator.dispatch({"operation": "reconcile", "token": OPERATOR_TOKEN})
        self.assertFalse(self.nft.active)
        self.assertEqual(self.act_store.action(action_id=result["action_id"])["state"], "reverted")

    def test_disjoint_attacker_scopes_allow_reads_but_exact_block_scope(self):
        def add(snapshot):
            extra = {**snapshot["scopes"][0], "scope_id": "second-source", "source_cidr": "10.50.0.13/32"}
            snapshot["scopes"].append(extra)
            snapshot["allocations"].append({**snapshot["allocations"][0], "source_ip": "10.50.0.13"})
        self.mutate_identity(add)
        self.assertEqual(len(self.authority.assets(self.principal, self.now)), 1)
        grant = self.authority.resolve(self.principal, TARGET, self.now, "block-ip", "10.50.0.13")
        self.assertEqual(grant.scope["scope_id"], "second-source")


class ActionTests(Fixture):
    def test_real_states_and_no_duplicate_execution(self):
        result = self.gateway.action(TOKEN, "block-ip", block())
        self.assertEqual(result["state"], "verified")
        self.assertEqual([r["payload"]["state"] for r in result["receipts"]], ["requested", "authorized", "executed", "verified"])
        repeated = self.gateway.action(TOKEN, "block-ip", block())
        self.assertEqual(result, repeated)
        self.assertEqual(self.nft.applied, 1)
        changed = block()
        changed["case_id"] = "different-case"
        self.expect_code("idempotency_conflict", self.gateway.action, TOKEN, "block-ip", changed)
        self.assertEqual(self.store.receipts()["receipts"][:4], result["receipts"])
        self.assertEqual(self.store.receipts()["receipts"][-1]["payload"]["state"], "rejected")

    def test_concurrent_retries_execute_once(self):
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: self.actuator.execute(TOKEN, block()), range(8)))
        self.assertEqual(self.nft.applied, 1)
        self.assertTrue(all(r["state"] == "verified" for r in results))

    def test_failed_verification_reverses_and_never_earns_verified(self):
        self.verifier.fail_phase = "after"
        result = self.actuator.execute(TOKEN, block())
        self.assertEqual(result["state"], "reverted")
        self.assertFalse(self.nft.active)
        self.assertNotIn("verified", [r["payload"]["state"] for r in result["receipts"]])
        self.assertEqual(result["receipts"][-1]["payload"]["reason_code"], "effect_not_verified")

    def test_baseline_failure_does_not_apply(self):
        self.verifier.fail_phase = "before"
        self.assertEqual(self.actuator.execute(TOKEN, block())["state"], "failed")
        self.assertEqual(self.nft.applied, 0)

    def test_authority_is_checked_after_probe_at_actuator_boundary(self):
        def change(phase):
            if phase == "before":
                self.mutate_identity(lambda s: s["scopes"][0].update(active=False))
        self.verifier.callback = change
        self.assertEqual(self.actuator.execute(TOKEN, block())["state"], "failed")
        self.assertEqual(self.nft.applied, 0)

    def test_actuator_reauthenticates_after_probe(self):
        def change(phase):
            if phase == "before":
                config = json.loads(self.token_file.read_text())
                config["principals"] = [p for p in config["principals"] if p["source_id"] != "blue-detector"]
                write_json(self.token_file, config)
        self.verifier.callback = change
        self.assertEqual(self.actuator.execute(TOKEN, block())["state"], "failed")
        self.assertEqual(self.nft.applied, 0)

    def test_disk_failure_after_kernel_apply_still_revokes(self):
        original = self.act_store.emit
        def write(*args, **kwargs):
            if args[0] == "action" and args[3].get("state") == "executed":
                raise Rejected("receipt_store_unavailable", 503)
            return original(*args, **kwargs)
        with patch.object(self.act_store, "emit", side_effect=write):
            result = self.actuator.execute(TOKEN, block())
        self.assertEqual(result["state"], "reverted")
        self.assertFalse(self.nft.active)

    def test_total_state_write_failure_after_apply_still_removes_rule(self):
        original = self.act_store.emit
        def write(*args, **kwargs):
            if self.nft.applied:
                raise Rejected("receipt_store_unavailable", 503)
            return original(*args, **kwargs)
        with patch.object(self.act_store, "emit", side_effect=write):
            self.expect_code("receipt_store_unavailable", self.actuator.execute, TOKEN, block())
        self.assertFalse(self.nft.active)

    def test_full_receipt_store_prevents_effects(self):
        self.act_store.max_receipts = 2
        self.expect_code("receipt_store_full", self.actuator.execute, TOKEN, block())
        self.assertEqual(self.nft.applied, 0)

    def test_one_active_per_target_and_both_budgets(self):
        first = self.actuator.execute(TOKEN, block())
        self.expect_code("active_action_limit", self.actuator.execute, TOKEN, block("second"))
        self.actuator.revert(TOKEN, first["action_id"])
        for i in range(1, 5):
            result = self.actuator.execute(TOKEN, block(str(i)))
            self.actuator.revert(TOKEN, result["action_id"])
        self.expect_code("action_budget_exhausted", self.actuator.execute, TOKEN, block("minute-limit"))
        for minute in range(1, 6):
            self.now = NOW + minute * 61
            write_json(self.snapshot, identity(self.now))
            for i in range(5):
                result = self.actuator.execute(TOKEN, block(f"{minute}-{i}"))
                self.actuator.revert(TOKEN, result["action_id"])
        self.now += 61
        write_json(self.snapshot, identity(self.now))
        self.expect_code("action_budget_exhausted", self.actuator.execute, TOKEN, block("hour-limit"))

    def test_kill_switch_reverses_and_decisions_continue(self):
        result = self.gateway.action(TOKEN, "block-ip", block())
        killed = self.gateway.kill_switch(self.tokens.authenticate(OPERATOR_TOKEN), True)
        self.assertTrue(killed["kill_switch"])
        self.assertFalse(self.nft.active)
        self.expect_code("kill_switch_active", self.gateway.action, TOKEN, "block-ip", block("after-kill"))
        receipt, _ = self.gateway.observation(self.principal, self.decision(), "decision")
        self.assertEqual(receipt["kind"], "decision")
        self.expect_code("action_not_found", self.actuator.revert, OTHER_TOKEN, result["action_id"])

    def test_kill_switch_persists_while_execution_lock_is_busy(self):
        with self.act_store.execution_lock():
            self.expect_code("actuator_busy", self.actuator.dispatch,
                             {"operation": "kill-switch", "token": OPERATOR_TOKEN, "enabled": True})
            self.assertEqual(self.act_store.meta("kill_switch"), "on")
        self.expect_code("kill_switch_active", self.actuator.execute, TOKEN, block())

    def test_kill_during_effect_probe_reverses_before_verified_receipt(self):
        self.verifier.callback = lambda phase: self.act_store.meta("kill_switch", "on") if phase == "after" else None
        result = self.actuator.execute(TOKEN, block())
        self.assertEqual(result["state"], "reverted")
        self.assertFalse(self.nft.active)
        self.assertNotIn("verified", [r["payload"]["state"] for r in result["receipts"]])

    def test_rebuild_does_not_replay_missing_rules(self):
        result = self.actuator.execute(TOKEN, block())
        self.nft.active.clear()
        self.actuator.dispatch({"operation": "reconcile", "token": OPERATOR_TOKEN})
        self.assertEqual(self.nft.applied, 1)
        self.assertEqual(self.act_store.action(action_id=result["action_id"])["state"], "reverted")

    def test_interrupted_execution_is_revoked_after_restart(self):
        def crash():
            raise SystemExit("simulated process crash")
        self.nft.after_apply = crash
        with self.assertRaises(SystemExit):
            self.actuator.execute(TOKEN, block())
        self.assertTrue(self.nft.active)
        self.nft.after_apply = None
        restarted = Actuator(self.tokens, self.authority, Store(self.act_store.path, "actuator"), self.nft, self.verifier, lambda: self.now)
        restarted.dispatch({"operation": "reconcile", "token": OPERATOR_TOKEN})
        self.assertFalse(self.nft.active)

    def test_gateway_restart_mirrors_unacknowledged_receipts(self):
        remote_result = self.actuator.execute(TOKEN, block())
        self.assertEqual(self.store.receipts()["receipts"], [])
        self.gateway.synchronize()
        self.assertEqual(self.store.receipts()["receipts"], remote_result["receipts"])
        self.gateway.synchronize()
        self.assertEqual(len(self.store.receipts()["receipts"]), 4)

    def test_unsupported_actions_are_explicit(self):
        for kind in ("revoke-session", "disable-account", "rate-limit", "isolate-workload", "anything"):
            self.expect_code("unsupported_capability", self.gateway.action, TOKEN, kind, {})

    def test_rejected_scope_is_recorded_without_copied_request_body(self):
        body = {**block(), "source_ip": "10.50.0.99"}
        self.expect_code("unresolved_or_ambiguous_identity", self.gateway.action, TOKEN, "block-ip", body)
        receipt = self.store.receipts()["receipts"][-1]
        self.assertEqual(receipt["payload"]["state"], "rejected")
        self.assertIsNone(receipt["assignment_id"])
        self.assertNotIn("10.50.0.99", canonical(receipt).decode())

    def test_snapshot_is_real_private_and_limited_to_the_request(self):
        self.spool_events(self.event())
        request = {"key": "snapshot-1", "case_id": "case-1", "target_id": TARGET,
                   "evidence_refs": [{"family": "application", "id": "evt_" + "1" * 64}]}
        result = self.gateway.action(TOKEN, "snapshot-evidence", request)
        self.assertEqual(result["state"], "verified")
        archive = self.gateway.evidence(self.principal, result["action_id"])
        self.assertEqual(len(archive["events"]), 1)
        self.assertEqual(archive["events"][0]["schema_version"], "ai-telemetry/1.0")
        self.expect_code("action_not_found", self.gateway.evidence, self.tokens.authenticate(OTHER_TOKEN), result["action_id"])
        request = {**request, "key": "missing-snapshot", "evidence_refs": [{"family": "application", "id": "evt_" + "2" * 64}]}
        self.assertEqual(self.gateway.action(TOKEN, "snapshot-evidence", request)["state"], "failed")

    def test_alert_is_durable_and_deduplicated(self):
        request = {"key": "alert-1", "case_id": "case-1", "target_id": TARGET, "evidence_refs": []}
        result = self.gateway.action(TOKEN, "alert", request)
        self.assertEqual(result["state"], "verified")
        self.assertEqual(self.gateway.action(TOKEN, "alert", request), result)
        self.assertEqual(len(self.store.receipts()["receipts"]), 4)


class ObservationTests(Fixture):
    def test_retries_gaps_epochs_and_no_raw_rationale(self):
        first, duplicate = self.gateway.observation(self.principal, self.decision(), "decision")
        self.assertFalse(duplicate)
        same, duplicate = self.gateway.observation(self.principal, self.decision(), "decision")
        self.assertTrue(duplicate)
        self.assertEqual(first, same)
        later, _ = self.gateway.observation(self.principal, self.decision(3), "decision")
        self.assertEqual(later["payload"]["sequence_gap"], 1)
        self.expect_code("stale_sequence", self.gateway.observation, self.principal, self.decision(2), "decision")
        invalid = self.decision(4)
        invalid["prompt"] = "must never be stored"
        self.expect_code("invalid_fields", self.gateway.observation, self.principal, invalid, "decision")
        invalid.pop("prompt")
        invalid["epoch"] = "reset-by-team"
        self.expect_code("unregistered_source_epoch", self.gateway.observation, self.principal, invalid, "decision")
        self.assertNotIn(TOKEN.encode(), self.store.path.read_bytes())

    def test_competitor_cannot_claim_trusted_checks(self):
        body = {"epoch": "boot-1", "source_sequence": 1, "occurred_at": stamp(self.now), "target_id": TARGET, "case_id": "case-1",
                "check": "model", "passed": True, "evidence_refs": [{"family": "ai", "id": "air_" + "1" * 64}]}
        self.expect_code("trusted_observer_required", self.gateway.observation, self.principal, body, "runtime_check")
        result, _ = self.gateway.observation(self.tokens.authenticate(OBSERVER_TOKEN), body, "runtime_check")
        self.assertEqual(result["payload"]["producer_kind"], "observer")

    def test_clock_uncertainty_is_preserved_and_late_records_rejected(self):
        body = self.decision()
        body["clock_uncertainty_seconds"] = 25
        result, _ = self.gateway.observation(self.principal, body, "decision")
        self.assertEqual(result["payload"]["clock_uncertainty_seconds"], 25)
        body = self.decision(2)
        body["occurred_at"] = stamp(self.now - 121)
        self.expect_code("observation_too_late", self.gateway.observation, self.principal, body, "decision")

    def test_receipt_tampering_rejected(self):
        receipt, _ = self.gateway.observation(self.principal, self.decision(), "decision")
        modified = copy.deepcopy(receipt)
        modified["team_id"] = RED
        self.expect_code("invalid_actuator_receipt", self.act_store.import_receipts, [modified])


class ReadTests(Fixture):
    def test_only_assigned_target_and_no_raw_body_or_identity(self):
        self.spool_events(self.event(actor={"user_id": "private-person"}, http={"path": "/secret"}, metadata={"untrusted": "do not forward"}),
                          self.event(namespace="jengasec-ent-b-app01", enterprise="ENT-B"))
        result = self.telemetry.read(self.principal, self.now)
        self.assertEqual(len(result["events"]), 1)
        encoded = canonical(result)
        self.assertNotIn(b"private-person", encoded)
        self.assertNotIn(b"secret", encoded)
        self.assertNotIn(b"untrusted", encoded)
        self.expect_code("invalid_cursor", self.telemetry.read, self.tokens.authenticate(OTHER_TOKEN), self.now, 200, result["next_cursor"])

    def test_invalid_and_partial_records_have_visible_quality(self):
        path = self.spool_events(self.event())
        with path.open("ab") as handle:
            handle.write(b'{"broken": true}\n{"incomplete":')
        result = self.telemetry.read(self.principal, self.now)
        self.assertEqual(len(result["events"]), 1)
        self.assertEqual(result["coverage"]["invalid_records"], 1)
        resumed = self.telemetry.read(self.principal, self.now, cursor=result["next_cursor"])
        self.assertEqual(resumed["events"], [])

    def test_expired_cursor_and_symlink_are_not_followed(self):
        path = self.spool_events(self.event())
        result = self.telemetry.read(self.principal, self.now)
        path.unlink()
        self.expect_code("telemetry_cursor_expired", self.telemetry.read, self.principal, self.now, 200, result["next_cursor"])
        path.symlink_to(self.token_file)
        with self.assertRaises(OSError):
            self.telemetry.read(self.principal, self.now)

    def test_receipts_are_tenant_bound(self):
        self.gateway.observation(self.principal, self.decision(), "decision")
        first = self.gateway.receipts(self.principal)
        self.assertEqual(len(first["receipts"]), 1)
        self.assertEqual(self.gateway.receipts(self.tokens.authenticate(OTHER_TOKEN))["receipts"], [])
        self.expect_code("invalid_cursor", self.gateway.receipts, self.tokens.authenticate(OTHER_TOKEN), first["next_cursor"])

    def test_only_operator_can_acknowledge_durably_retained_pages(self):
        self.gateway.observation(self.principal, self.decision(), "decision")
        self.gateway.observation(self.principal, self.decision(2), "decision")
        operator = self.tokens.authenticate(OPERATOR_TOKEN)
        page = self.gateway.receipts(operator)
        self.expect_code("forbidden", self.gateway.acknowledge, self.principal, page["next_cursor"])
        self.gateway.acknowledge(operator, page["next_cursor"])
        self.expect_code("receipt_cursor_expired", self.gateway.receipts, operator)
        self.assertEqual(self.gateway.receipts(operator, page["next_cursor"])["receipts"], [])
        receipt, duplicate = self.gateway.observation(self.principal, self.decision(2), "decision")
        self.assertTrue(duplicate)
        self.assertEqual(receipt["payload"]["source_sequence"], 2)


class HttpTests(Fixture):
    def setUp(self):
        super().setUp()
        self.server = Server(("127.0.0.1", 0), self.gateway)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def request(self, method, path, body=None, token=TOKEN, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        wire_headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
        wire_headers.update(headers or {})
        connection.request(method, path, None if body is None else canonical(body), wire_headers)
        response = connection.getresponse()
        result = response.status, json.loads(response.read())
        connection.close()
        return result

    def test_real_http_auth_body_validation_and_persisted_decision(self):
        status, body = self.request("GET", "/api/v1/capabilities")
        self.assertEqual(status, 200)
        self.assertFalse(body["shadow"])
        self.assertEqual(self.request("GET", "/api/v1/assets", token="wrong")[0], 401)
        self.assertEqual(self.request("POST", "/api/v1/decisions", self.decision())[0], 201)
        self.assertEqual(self.request("POST", "/api/v1/decisions", self.decision())[0], 200)
        self.assertEqual(self.request("GET", "/api/v1/receipts")[0], 200)
        self.assertEqual(self.request("POST", "/api/v1/actions/block-ip", block())[0], 202)
        self.assertEqual(self.request("POST", "/api/v1/kill-switch", {"enabled": True})[0], 403)

    def test_http_rejects_oversized_duplicate_auth_and_raw_secrets(self):
        status, result = self.request("POST", "/api/v1/decisions", {"raw": "x" * 70000})
        self.assertEqual((status, result["error"]), (413, "body_too_large"))
        status, result = self.request("POST", "/api/v1/decisions", {}, headers={"Content-Type": "text/plain"})
        self.assertEqual(status, 415)
        with socket.create_connection(("127.0.0.1", self.server.server_port), timeout=5) as connection:
            connection.sendall(("GET /api/v1/assets HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " + TOKEN + "\r\nAuthorization: Bearer " + OTHER_TOKEN + "\r\n\r\n").encode())
            data = connection.recv(2048)
        self.assertIn(b"401", data)
        self.assertNotIn(TOKEN.encode(), data)


class CommandTests(Fixture):
    def test_fixed_argv_output_and_deadline_bounds(self):
        data = run_bounded([sys.executable, "-c", "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())"], b"request")
        self.assertEqual(data, b"request")
        self.expect_code("adapter_output_too_large", run_bounded, [sys.executable, "-c", "print('x'*4096)"], b"", 5, 1024)
        self.expect_code("adapter_timeout", run_bounded, [sys.executable, "-c", "import time; time.sleep(2)"], b"", 0.05)
        self.expect_code("adapter_requires_absolute_path", run_bounded, ["echo", "not permitted"])

    def test_remote_credentials_use_stdin_not_argv(self):
        captured = []
        def run(argv, payload, **kwargs):
            captured.append((argv, json.loads(payload)))
            return b'{"state":"verified"}'
        client = RemoteActuator(["/usr/bin/ssh", "gateway-forced-command"], OPERATOR_TOKEN, run)
        client.call("execute", token=TOKEN, request=block())
        self.assertNotIn(TOKEN, repr(captured[0][0]))
        self.assertEqual(captured[0][1]["token"], TOKEN)

    def test_nft_commands_are_drop_only_exact_tuples_with_kernel_timeout(self):
        commands = []
        structure = {"nftables": [{"table": {"family": "inet", "name": "jengasec_ai_test", "handle": 1}}]}
        def run(argv, payload=b"", **kwargs):
            commands.append((argv, payload))
            if argv[-2:] == ["list", "tables"]:
                return b'{"nftables":[]}'
            if "list" in argv:
                return canonical(structure)
            return b""
        nft = Nft(self.act_store, table="jengasec_ai_test", runner=run)
        nft.setup()
        action = {"expires": self.now + 60, "tuple": {"source_ip": "10.50.0.12", "target_ip": "10.60.0.11", "protocol": "tcp", "port": 8080}}
        nft.apply(action, self.now)
        text = b"".join(data for _, data in commands).decode()
        self.assertIn("10.50.0.12 . 10.60.0.11 . tcp . 8080 timeout 60s", text)
        self.assertIn("flags timeout", text)
        self.assertIn("hook forward priority -10", text)
        self.assertNotIn("flush ruleset", text)
        self.assertNotIn("forward_guard", text)
        self.assertNotIn(" accept\n", text)
        self.expect_code("invalid_nft_table", Nft, self.act_store, "/usr/sbin/nft", "injected\nflush ruleset")

    def test_nft_validation_delay_is_subtracted_from_kernel_lease(self):
        commands = []
        def run(argv, payload=b"", **kwargs):
            commands.append((argv, payload, kwargs))
            return b""
        nft = Nft(self.act_store, table="jengasec_ai_test", runner=run)
        action = {"expires": self.now + 60, "tuple": {"source_ip": "10.50.0.12", "target_ip": "10.60.0.11", "protocol": "tcp", "port": 8080}}
        with patch("scoring_ai.actuator.time.monotonic", side_effect=[100, 103]):
            nft.apply(action, self.now)
        self.assertIn(b"timeout 55s", commands[-1][1])
        self.assertEqual(commands[-1][2]["timeout"], 2)


class FunctionalProbeTests(Fixture):
    def test_actual_source_bound_requests_hashes_and_control_flow(self):
        requests = []
        class App(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_GET(self):
                requests.append(self.client_address[0])
                data = b'{"ready":true}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
        server = ThreadingHTTPServer(("127.0.0.1", 0), App)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        check = {"competition": 1, "target_id": TARGET, "source_ip": "127.0.0.2", "control_source_ip": "127.0.0.3",
                 "target_ip": "127.0.0.1", "protocol": "tcp", "port": server.server_port, "tls": False,
                 "host": "localhost", "path": "/ready", "expected_status": 200,
                 "expected_body_sha256": "sha256:" + hashlib.sha256(b'{"ready":true}').hexdigest(), "frozen_digest": "sha256:" + "1" * 64}
        probe = FunctionalProbe({"checks": [check], "evidence_directory": str(self.root / "probe")}, lambda: self.now)
        request = {"schema_version": "ai-effect-probe/1.0", "phase": "before", "action_id": "aia_" + "b" * 64,
                   "case_id": "case-1", "competition": 1, "target_id": TARGET, "frozen_digest": check["frozen_digest"],
                   "tuple": {key: check[key] for key in ("source_ip", "target_ip", "protocol", "port")}}
        result = probe.execute(request)
        self.assertTrue(result["functional_success"])
        self.assertTrue(result["control_success"])
        self.assertEqual(requests, ["127.0.0.2", "127.0.0.3"])
        artifacts = list((self.root / "probe").glob("air_*.json"))
        self.assertEqual(len(artifacts), 1)
        self.assertNotIn(b'"ready":true', artifacts[0].read_bytes())
        self.assertEqual(artifacts[0].stat().st_mode & 0o777, 0o600)
        action = {"action_id": request["action_id"], "request": {"case_id": "case-1", "target_id": TARGET},
                  "context": {"competition": 1}, "tuple": request["tuple"], "frozen_digest": request["frozen_digest"]}
        verifier = Verifier(["/operator-owned/probe"], lambda argv, payload, **kwargs: canonical(result))
        self.assertTrue(verifier.check(action, "before")["functional_success"])
        result["proof"]["functional"]["status"] = 500
        self.expect_code("invalid_probe_proof", verifier.check, action, "before")
        request["tuple"]["port"] += 1
        self.expect_code("unregistered_effect_probe", probe.execute, request)


class TestQueue:
    def __init__(self):
        self.payloads, self.cursors = {}, {}
        self.fail_after, self.calls, self.in_transaction = None, 0, False

    def enqueue_receipt(self, payload):
        if self.in_transaction:
            raise RuntimeError("nested transactions are not supported")
        self.calls += 1
        if self.fail_after is not None and self.calls >= self.fail_after:
            raise Rejected("test_outbox_full", 503)
        key = (payload["producer_id"], payload["receipt_id"])
        if key in self.payloads and self.payloads[key] != payload:
            raise Rejected("conflicting_receipt_retry", 503)
        self.payloads[key] = copy.deepcopy(payload)

    def cursor(self, name, value=None):
        if value is None:
            return self.cursors.get(name)
        self.cursors[name] = value

    @contextlib.contextmanager
    def transaction(self):
        if self.in_transaction:
            raise RuntimeError("nested transactions are not supported")
        before = copy.deepcopy(self.cursors)
        self.in_transaction = True
        try:
            yield
        except BaseException:
            self.cursors = before
            raise
        finally:
            self.in_transaction = False


class PlatformBridgeTests(Fixture):
    CASE = "da0b30ef-703a-4a4f-a350-04cd648f3025"

    def setUp(self):
        super().setUp()
        self.queue, self.retained = TestQueue(), []
        self.bindings = [
            {"team": TEAM, "source_id": "blue-detector", "kind": "competitor", "producer_id": "19442571-b7c2-40d5-8c13-e10df3bf117c", "clock_uncertainty_ms": 100},
            {"team": TEAM, "source_id": "actuator", "kind": "gateway", "producer_id": "19442571-b7c2-40d5-8c13-e10df3bf117d", "clock_uncertainty_ms": 100},
            {"team": TEAM, "source_id": "runtime-observer", "kind": "verifier", "producer_id": "19442571-b7c2-40d5-8c13-e10df3bf117e", "clock_uncertainty_ms": 100},
        ]

    def bridge(self, rows, cursor="next-1", bindings=None, retain=None):
        return PlatformBridge(lambda previous, limit: {"receipts": rows, "next_cursor": cursor}, self.queue, 1,
                              self.bindings if bindings is None else bindings, retain or self.retained.append)

    def actual_decision(self, **changes):
        body = {**self.decision(), "case_id": self.CASE, **changes}
        return self.gateway.observation(self.principal, body, "decision")[0]

    def test_competitor_detection_and_raw_decision_retain_original(self):
        receipt = self.actual_decision()
        result = self.bridge([receipt]).step()
        self.assertEqual((result["retained"], result["enqueued"]), (1, 2))
        outputs = {row["kind"]: row for row in self.queue.payloads.values()}
        self.assertEqual(set(outputs), {"decision", "detection"})
        self.assertEqual(outputs["detection"]["measurements"], {"classification": "attack", "incident_id": "incident-1"})
        self.assertEqual(outputs["decision"]["measurements"]["rationale_reference"], receipt["receipt_id"])
        self.assertEqual(outputs["decision"]["clock_uncertainty_ms"], 500)
        self.assertEqual(self.retained, [receipt])
        self.assertEqual(self.queue.cursor("ai-platform:1"), "next-1")
        self.assertEqual(outputs["decision"]["receipt_id"], receipt_uuid(receipt["receipt_id"], "decision"))

    def test_abstain_does_not_become_a_false_detection(self):
        result = self.bridge([self.actual_decision(classification="abstain")]).step()
        self.assertEqual(result["enqueued"], 1)
        self.assertEqual(next(iter(self.queue.payloads.values()))["kind"], "decision")

    def test_failed_second_queue_keeps_cursor_for_safe_retry(self):
        receipt = self.actual_decision()
        bridge = self.bridge([receipt])
        self.queue.fail_after = 2
        self.expect_code("test_outbox_full", bridge.step)
        self.assertIsNone(self.queue.cursor("ai-platform:1"))
        self.assertEqual(len(self.queue.payloads), 1)
        self.queue.fail_after = None
        bridge.step()
        self.assertEqual(len(self.queue.payloads), 2)
        self.assertEqual(self.queue.cursor("ai-platform:1"), "next-1")

    def test_retention_failure_prevents_queue_and_cursor(self):
        receipt = self.actual_decision()
        def fail(_):
            raise OSError("archive unavailable")
        with self.assertRaises(OSError):
            self.bridge([receipt], retain=fail).step()
        self.assertFalse(self.queue.payloads)
        self.assertIsNone(self.queue.cursor("ai-platform:1"))

    def test_unknown_mapping_holds_and_unissued_cases_are_explicit_audit_only(self):
        receipt = self.actual_decision()
        held = self.bridge([receipt], bindings=[]).step()
        self.assertEqual(held["held_reasons"][0]["reason"], "unmapped_ai_producer")
        self.assertFalse(held["cursor_advanced"])
        self.assertFalse(self.queue.payloads)
        self.assertIsNone(self.queue.cursor("ai-platform:1"))
        unscheduled = self.gateway.observation(self.principal, {**self.decision(2), "case_id": "not-a-platform-case"}, "decision")[0]
        result = self.bridge([receipt, unscheduled]).step()
        self.assertEqual(result["audited"], 1)
        self.assertEqual(result["audit_reasons"][0]["reason"], "case_not_platform_issued")
        self.assertEqual(result["enqueued"], 2)
        self.assertTrue(result["cursor_advanced"])

    def test_tampering_never_reaches_archive_or_queue(self):
        receipt = self.actual_decision()
        receipt["payload"]["classification"] = "legitimate"
        self.expect_code("invalid_ai_receipt_integrity", self.bridge([receipt]).step)
        self.assertFalse(self.retained)
        self.assertFalse(self.queue.payloads)

    def test_verified_action_does_not_infer_harm_or_success(self):
        action = self.actuator.execute(TOKEN, {**block(), "case_id": self.CASE})
        result = self.bridge(action["receipts"]).step()
        self.assertEqual(result["enqueued"], 4)
        for row in self.queue.payloads.values():
            self.assertEqual(row["kind"], "action")
            self.assertEqual(set(row["measurements"]), {"action_id", "action_type", "state"})
        self.assertEqual(self.retained[-1]["payload"]["verification"]["after"]["functional_success"], False)

    def test_source_health_requires_two_real_observations_and_keeps_gaps(self):
        observer = self.tokens.authenticate(OBSERVER_TOKEN)
        def source(sequence, gaps=0):
            body = {"epoch": "boot-1", "source_sequence": sequence, "occurred_at": stamp(self.now), "target_id": TARGET,
                    "case_id": self.CASE, "healthy": True, "gap_count": gaps, "clock_uncertainty_seconds": 0.1}
            return self.gateway.observation(observer, body, "source_health")[0]
        first = source(1)
        self.assertEqual(self.bridge([first], cursor="first").step()["enqueued"], 0)
        self.now += 10
        second = source(2)
        self.bridge([second], cursor="second").step()
        row = next(iter(self.queue.payloads.values()))
        self.assertEqual(row["measurements"], {"start": first["occurred_at"], "end": second["occurred_at"], "expected": 1, "completed": 1, "lost": 0})
        self.now += 10
        third = source(5, gaps=2)
        self.bridge([third], cursor="third").step()
        newest = [r for r in self.queue.payloads.values() if r["observed_at"] == third["occurred_at"]][0]
        self.assertEqual(newest["measurements"]["completed"], 0)
        self.assertEqual(newest["measurements"]["lost"], 2)
        self.assertNotIn("case_id", newest)

    def test_health_baselines_are_separate_for_each_target(self):
        observer = self.tokens.authenticate(OBSERVER_TOKEN)
        body = {"epoch": "boot-1", "source_sequence": 1, "occurred_at": stamp(self.now), "target_id": TARGET,
                "case_id": self.CASE, "healthy": True, "gap_count": 0, "clock_uncertainty_seconds": 0.1}
        first = self.gateway.observation(observer, body, "source_health")[0]
        self.bridge([first], cursor="first-target").step()
        second = copy.deepcopy(first)
        second["target_id"] = "ENT-A/APP02"
        second["sequence"] += 1
        second["payload"]["source_sequence"] += 1
        second["occurred_at"] = stamp(self.now + 10)
        second.pop("receipt_id")
        second.pop("integrity_hash")
        second["receipt_id"] = "air_" + hashlib.sha256(canonical(second)).hexdigest()
        second["integrity_hash"] = digest(second)
        result = self.bridge([second], cursor="second-target").step()
        self.assertEqual(result["enqueued"], 0)
        self.assertFalse(self.queue.payloads)

    def test_gaps_in_intermediate_runtime_records_make_health_incomplete(self):
        observer = self.tokens.authenticate(OBSERVER_TOKEN)
        base = {"epoch": "boot-1", "source_sequence": 1, "occurred_at": stamp(self.now), "target_id": TARGET,
                "case_id": self.CASE, "healthy": True, "gap_count": 0, "clock_uncertainty_seconds": 0.1}
        first = self.gateway.observation(observer, base, "source_health")[0]
        self.bridge([first], cursor="start").step()
        self.now += 5
        check = {"epoch": "boot-1", "source_sequence": 3, "occurred_at": stamp(self.now), "target_id": TARGET,
                 "case_id": self.CASE, "check": "model", "passed": True,
                 "evidence_refs": [{"family": "ai", "id": "air_" + "a" * 64}]}
        middle = self.gateway.observation(observer, check, "runtime_check")[0]
        self.bridge([middle], cursor="middle").step()
        self.now += 5
        last = self.gateway.observation(observer, {**base, "source_sequence": 4, "occurred_at": stamp(self.now)}, "source_health")[0]
        self.bridge([last], cursor="end").step()
        health = [r for r in self.queue.payloads.values() if r["kind"] == "source_health"][0]
        self.assertEqual(health["measurements"]["completed"], 0)
        self.assertEqual(health["measurements"]["lost"], 1)

    def test_acknowledgement_happens_after_proof_queue_and_cursor(self):
        receipt = self.actual_decision()
        events = []
        def retain(value):
            events.append("retained")
        def ack(cursor):
            self.assertEqual(len(self.queue.payloads), 2)
            self.assertEqual(self.queue.cursor("ai-platform:1"), cursor)
            self.assertEqual(events, ["retained"])
            events.append("acknowledged")
        bridge = PlatformBridge(lambda cursor, limit: {"receipts": [receipt], "next_cursor": "next"},
                                self.queue, 1, self.bindings, retain, acknowledge=ack)
        bridge.step()
        self.assertEqual(events, ["retained", "acknowledged"])

    def test_runtime_checks_use_trusted_verifier_outcome(self):
        observer = self.tokens.authenticate(OBSERVER_TOKEN)
        body = {"epoch": "boot-1", "source_sequence": 1, "occurred_at": stamp(self.now), "target_id": TARGET,
                "case_id": self.CASE, "check": "model", "passed": True, "evidence_refs": [{"family": "ai", "id": "air_" + "a" * 64}]}
        receipt = self.gateway.observation(observer, body, "runtime_check")[0]
        self.bridge([receipt]).step()
        row = next(iter(self.queue.payloads.values()))
        self.assertEqual(row["kind"], "outcome")
        self.assertEqual(row["measurements"], {"runtime_checks": {"model": True}})


if __name__ == "__main__":
    unittest.main()
