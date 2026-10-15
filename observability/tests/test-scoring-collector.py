#!/usr/bin/env python3
"""Delivery failures must not erase evidence, multiply marks or invent outcomes."""

import datetime as dt
import copy
import fcntl
import hashlib
import http.server
import json
import os
import pathlib
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
import urllib.parse
from unittest.mock import Mock, patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "scripts"))

from scoring_obs.cache import SourceCache
from scoring_obs.cli import Collector, load_config, main
from scoring_obs.common import Invalid, canonical, digest, timestamp, utc
from scoring_obs.evidence import ProofResolver
from scoring_obs.facts import availability, build
from scoring_obs.outbox import Full, Outbox
from scoring_obs.probes import _get, measure
from scoring_obs.publisher import archive, deliver
from scoring_obs.transport import Client, Failure, client_tls


START = timestamp("2026-01-01T00:00:00Z")
END = START + dt.timedelta(minutes=10)


def tls_fixture(directory):
    """Short-lived local certificates, also used by the hosted nginx test."""
    root = pathlib.Path(directory)

    def openssl(*args):
        subprocess.run(["openssl", *map(str, args)], check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.PIPE, timeout=10)

    for ca in ("ca", "foreign-ca"):
        openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                "-nodes", "-sha256", "-days", "1", "-subj", "/CN=" + ca,
                "-addext", "basicConstraints=critical,CA:TRUE", "-keyout", root / (ca + ".key"),
                "-out", root / (ca + ".crt"))
    settings = {}
    for serial, name in enumerate(("server", "wrong-name", "collector", "retired", "generic", "foreign"), 1):
        server = name in {"server", "wrong-name"}
        issuer = "foreign-ca" if name == "foreign" else "ca"
        subject = "jengasec-scoring-collector" if name in {"collector", "retired"} else name
        openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                "-nodes", "-sha256", "-subj", "/CN=" + subject,
                "-keyout", root / (name + ".key"), "-out", root / (name + ".csr"))
        extensions = "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
        extensions += "extendedKeyUsage=" + ("serverAuth" if server else "clientAuth") + "\n"
        if server:
            extensions += "subjectAltName=" + ("DNS:localhost,IP:127.0.0.1" if name == "server" else "DNS:wrong.invalid") + "\n"
        ext = root / (name + ".ext")
        ext.write_text(extensions)
        openssl("x509", "-req", "-in", root / (name + ".csr"), "-CA", root / (issuer + ".crt"),
                "-CAkey", root / (issuer + ".key"), "-set_serial", serial, "-days", "1", "-sha256",
                "-extfile", ext, "-out", root / (name + ".crt"))
        (root / (name + ".key")).chmod(0o600)
        settings[name] = {"ca_file": str(root / "ca.crt"), "cert_file": str(root / (name + ".crt")),
                          "key_file": str(root / (name + ".key"))}
    return settings


def score_row(marks="12.00"):
    return {"team": "JS26-B-014", "stage": "main", "criterion": "availability",
            "key": "main:availability", "marks": marks}


class QueueTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = pathlib.Path(self.directory.name) / "outbox.sqlite3"
        self.box = Outbox(self.path)

    def tearDown(self):
        self.box.close()
        self.directory.cleanup()

    def test_restart_keeps_pending_revision_and_idempotent_component(self):
        self.assertEqual(self.box.enqueue_score(7, score_row()), 1)
        self.box.close()
        self.box = Outbox(self.path)
        self.assertEqual(self.box.enqueue_score(7, score_row()), 1)
        self.assertEqual(len(self.box.due()), 1)
        self.assertEqual(self.box.enqueue_score(7, score_row("6.00")), 2)
        rows = self.box.due()
        self.assertEqual([row["payload"]["scores"][0]["revision"] for row in rows], [1, 2])
        for row in rows:
            self.box.finish(row["id"], "accepted")
        self.assertEqual(self.box.enqueue_score(7, score_row("6.00")), 2)
        self.assertEqual(self.box.stats()["rows"], 0)

    def test_full_queue_does_not_consume_revision_or_drop_earlier_row(self):
        self.box.max_rows = 1
        self.box.enqueue_score(7, score_row())
        with self.assertRaises(Full):
            self.box.enqueue_score(7, score_row("8.00"))
        row = self.box.due()[0]
        self.assertEqual(row["payload"]["scores"][0]["marks"], "12.00")
        self.box.finish(row["id"], "accepted")
        self.assertEqual(self.box.enqueue_score(7, score_row("8.00")), 2)

    def test_probe_two_destinations_are_atomic_on_full_queue(self):
        self.box.max_rows = 1
        receipt = {"producer_id": "p", "receipt_id": "r"}
        with self.assertRaises(Full):
            self.box.enqueue_probe(receipt, "probe:target", 3, {"streams": []})
        self.assertEqual(self.box.stats()["rows"], 0)
        self.assertIsNone(self.box.cursor("probe:target"))

    def test_http202_rejection_is_not_a_successful_delivery(self):
        self.box.enqueue_score(7, score_row())

        class Receiver:
            def call(self, path, body):
                return 202, {"accepted": 0, "outcomes": [{"index": 0, "status": "rejected", "retryable": False}]}
        self.assertEqual(deliver(self.box, Receiver(), now=0), 0)
        self.assertEqual(self.box.stats()["rejected"], 1)
        self.assertEqual(self.box.due(now=10000), [])

    def test_accepted_rows_and_retryable_rows_reconcile_independently(self):
        self.box.enqueue_score(7, score_row())
        self.box.enqueue_score(7, score_row("8.00"))

        class Receiver:
            def call(self, path, body):
                row = body["scores"][0]
                if row["revision"] == 1:
                    return 200, {"accepted": 1, "outcomes": [{"index": 0, "key": row["key"], "revision": 1, "status": "accepted"}]}
                return 202, {"outcomes": [{"index": 0, "status": "pending", "retryable": True}]}
        self.assertEqual(deliver(self.box, Receiver(), now=0), 1)
        self.assertEqual(self.box.stats()["rows"], 1)
        self.assertEqual(self.box.due(now=0), [])
        self.assertEqual(len(self.box.due(now=300)), 1)

    def test_mismatched_ack_does_not_delete_pending_score(self):
        self.box.enqueue_score(7, score_row())

        class Receiver:
            def call(self, path, body):
                return 200, {"outcomes": [{"index": 0, "key": "main:availability", "revision": 9, "status": "accepted"}]}
        deliver(self.box, Receiver(), now=0)
        self.assertEqual(self.box.stats()["rows"], 1)

    def test_network_outage_and_auth_failure_remain_recoverable(self):
        self.box.enqueue_score(7, score_row())

        class Receiver:
            def call(self, path, body):
                raise Failure(403, "http_403")
        deliver(self.box, Receiver(), now=0)
        self.assertEqual(self.box.stats()["rejected"], 0)
        self.assertEqual(len(self.box.due(now=301)), 1)

    def test_raw_errors_cannot_enter_reason_labels(self):
        with self.assertRaises(Invalid):
            self.box.fail(1, "Bearer secret\n")


class CalculationCorrectionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = pathlib.Path(self.directory.name) / "delivery.sqlite3"
        self.box = Outbox(self.path)
        self.addCleanup(lambda: self.box.close())
        self.collector = Collector.__new__(Collector)
        self.collector.outbox = self.box
        self.collector.competition, self.collector.start, self.collector.end = 7, START, END
        self.collector.platform, self.collector.proof = Mock(), Mock()
        self.collector.identity = Mock(return_value={
            "teams": [{"team": "JS26-B-014", "track": "application", "side": "blue", "revision": 1}],
            "targets": [],
        })
        self.collector.collect = Mock(return_value=True)
        self.collector.cache = Mock()
        self.collector.cache.window.return_value = ([], [], [])
        self.result = types.SimpleNamespace(status="ready", marks="12.00")
        self.facts, self.quality = {"expected": 2, "successful": 1}, {}
        policy = types.SimpleNamespace(calculate=Mock(side_effect=lambda *args, **kwargs: self.result))
        patches = [
            patch.dict(sys.modules, {"jengasec_scoring_policy": policy}),
            patch("scoring_obs.cli.CRITERIA", {"application_blue": ("availability",)}),
            patch("scoring_obs.cli.build", return_value=(self.facts, self.quality, [])),
            patch("scoring_obs.cli.archive", return_value=[{"id": "immutable-input", "sha256": "fixed-input-hash"}]),
        ]
        for replacement in patches:
            replacement.start()
            self.addCleanup(replacement.stop)
        self.key = "score_input:JS26-B-014:availability"
        self.box.cursor("ai_receipts", {"after": "retained-source-cursor"})

    def score(self):
        return self.collector.score(now=END + dt.timedelta(minutes=3))["criteria"]["JS26-B-014:availability"]

    def restart(self):
        self.box.close()
        self.box = self.collector.outbox = Outbox(self.path)

    def test_changed_calculation_creates_next_revision_without_resetting_source_state(self):
        self.assertEqual(self.score(), "queued")
        original = copy.deepcopy(self.box.due()[0])
        self.result.marks = "6.00"
        self.assertEqual(self.score(), "queued")
        rows = self.box.due()
        self.assertEqual(rows[0], original)
        self.assertEqual([(row["payload"]["scores"][0]["revision"], row["payload"]["scores"][0]["marks"])
                          for row in rows], [(1, "12.00"), (2, "6.00")])
        self.assertTrue(all(row["payload"]["scores"][0]["key"] == "main:availability" for row in rows))
        self.assertTrue(all(row["payload"]["scores"][0]["policy_version"] == "main-scoring/1.0" for row in rows))
        self.restart()
        self.assertEqual(self.score(), "unchanged")
        self.assertEqual(self.box.due(), rows)
        self.assertEqual(self.box.cursor("ai_receipts"), {"after": "retained-source-cursor"})

    def test_upgrade_from_old_fingerprint_preserves_rejection_and_delivers_correction(self):
        self.score()
        original = copy.deepcopy(self.box.due()[0])
        # The earlier release persisted input-only fingerprints. Keep that
        # state and the uncommitted payload while the corrected release runs.
        self.box.cursor(self.key, digest({"policy_version": "main-scoring/1.0", "side": "application_blue",
                        "criterion": "availability", "facts": self.facts, "quality": self.quality,
                        "assignment_revisions": [1], "final_window": True}))
        self.result.marks = "6.00"
        self.restart()
        self.assertEqual(self.score(), "queued")
        attempted = []

        class Receiver:
            def call(self, path, body):
                row = body["scores"][0]
                attempted.append(row["revision"])
                if row["revision"] == 1:
                    return 202, {"outcomes": [{"index": 0, "status": "rejected", "retryable": False}]}
                return 200, {"outcomes": [{"index": 0, "key": row["key"], "revision": row["revision"], "status": "accepted"}]}

        self.assertEqual(deliver(self.box, Receiver(), now=time.time() + 1), 1)
        self.assertEqual(attempted, [1, 2])
        saved = self.box.db.execute("SELECT payload,state,reason FROM pending WHERE id=?", (original["id"],)).fetchone()
        self.assertEqual(saved, (canonical(original["payload"]), "rejected", "row_rejected"))
        self.restart()
        self.assertEqual(self.score(), "unchanged")
        self.assertEqual(self.box.stats()["rejected"], 1)
        self.assertEqual(deliver(self.box, Receiver(), now=time.time() + 3600), 0)
        self.assertEqual(attempted, [1, 2])
        self.assertEqual(self.box.cursor("ai_receipts"), {"after": "retained-source-cursor"})


class ClientTlsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="scoring-client-tls-")
        cls.addClassCleanup(cls.directory.cleanup)
        cls.material = tls_fixture(cls.directory.name)

    def test_private_tls_material_rejects_missing_unsafe_and_mismatched_files(self):
        valid = self.material["collector"]
        context = client_tls(valid)
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        bad_configs = [{}, {"ca_file": valid["ca_file"]}, dict(valid, unexpected=True),
                       dict(valid, key_file=self.material["generic"]["key_file"]),
                       dict(valid, ca_file=str(pathlib.Path(self.directory.name) / "missing")),
                       dict(valid, cert_file="relative.crt")]
        for config in bad_configs:
            with self.subTest(config_fields=sorted(config)), self.assertRaises(Invalid):
                client_tls(config)
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            path = root / "unsafe.key"
            shutil.copyfile(valid["key_file"], path)
            path.chmod(0o640)
            with self.assertRaises(Invalid):
                client_tls(dict(valid, key_file=str(path)))
            path.chmod(0o600)
            link = root / "link.key"
            link.symlink_to(path)
            with self.assertRaises(Invalid):
                client_tls(dict(valid, key_file=str(link)))
            link.unlink()
            os.mkfifo(link, 0o600)
            with self.assertRaises(Invalid):
                client_tls(dict(valid, key_file=str(link)))
            for field in ("ca_file", "cert_file"):
                public = root / field
                shutil.copyfile(valid[field], public)
                public.chmod(0o666)
                with self.assertRaises(Invalid):
                    client_tls(dict(valid, **{field: str(public)}))
        with self.assertRaises(Invalid):
            Client("http://127.0.0.1", loopback_http=True, tls=valid)

    def test_config_check_rejects_incomplete_or_missing_tls_before_network_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            config = {"schema_version": "scoring-collector/1.0", "competition": 7,
                      "platform_url": "https://platform.invalid", "feed_token_file": str(root / "token"),
                      "state_dir": str(root), "source_cache_bytes": 1048576,
                      "window_start": utc(START), "window_end": utc(END), "producers": {}, "probes": {}}
            path = root / "config.json"
            path.write_bytes(canonical(config))
            self.assertEqual(load_config(path), config)  # Existing configuration remains valid.
            for extra in ({"loki_tls": self.material["collector"]},
                          {"loki_url": "https://obs.invalid", "loki_tls": {}},
                          {"loki_url": "http://127.0.0.1", "loki_tls": self.material["collector"]},
                          {"loki_url": "https://obs.invalid", "loki_tls": dict(self.material["collector"], key_file=str(root / "missing"))}):
                path.write_bytes(canonical(dict(config, **extra)))
                with patch("scoring_obs.cli.Client") as client, self.assertRaises(Invalid):
                    main(["--config", str(path), "--check"])
                client.assert_not_called()

    def test_real_tls_requires_client_identity_trust_and_hostname_and_refuses_redirects(self):
        received = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                received.append(self.path)
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "/must-not-follow")
                    self.end_headers()
                    return
                body = canonical({"peer": self.connection.getpeercert()["subject"][0][0][1]})
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        for server_identity in ("server", "wrong-name"):
            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            material = self.material[server_identity]
            context.load_cert_chain(material["cert_file"], material["key_file"])
            context.load_verify_locations(material["ca_file"])
            context.verify_mode = ssl.CERT_REQUIRED
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            url = f"https://127.0.0.1:{server.server_port}"
            try:
                client = Client(url, tls=self.material["collector"], timeout=2)
                if server_identity == "wrong-name":
                    with self.assertRaises(Failure):
                        client.call("/query")
                    continue
                self.assertEqual(client.call("/query"), (200, {"peer": "jengasec-scoring-collector"}))
                with tempfile.TemporaryDirectory() as directory:
                    root = pathlib.Path(directory)
                    token, headers = root / "feed-token", root / "loki-headers"
                    token.write_text("fixture-only")
                    headers.write_text('{"X-Scope-OrgID":"application-other"}')
                    token.chmod(0o600)
                    headers.chmod(0o600)
                    collector = Collector({"platform_url": url, "feed_token_file": str(token),
                        "competition": 7, "state_dir": str(root / "state"), "source_cache_bytes": 1048576,
                        "window_start": utc(START), "window_end": utc(END), "loki_url": url,
                        "loki_headers_file": str(headers), "loki_tls": self.material["collector"]})
                    try:
                        self.assertEqual(collector.loki.headers["X-Scope-OrgID"], "staff")
                        self.assertEqual(collector.loki.call("/query"), (200, {"peer": "jengasec-scoring-collector"}))
                    finally:
                        collector.close()
                with self.assertRaises(Failure) as redirect:
                    client.call("/redirect")
                self.assertEqual(redirect.exception.code, 302)
                self.assertNotIn("/must-not-follow", received)
                for config in (None, self.material["foreign"],
                               dict(self.material["collector"], ca_file=str(pathlib.Path(self.directory.name) / "foreign-ca.crt"))):
                    with self.assertRaises(Failure):
                        Client(url, tls=config, timeout=2).call("/query")
            finally:
                server.shutdown()
                server.server_close()
                thread.join()


class EvidenceTests(unittest.TestCase):
    def test_every_chunk_is_integrity_checked_before_score_can_be_queued(self):
        snapshot = {"facts": {"expected": 2}}
        calls = []

        class Receiver:
            def call(self, path, body):
                calls.append(body)
                return 201, {"id": "artifact", "sha256": digest(body), "input_sha256": digest(body["snapshot"])}
        rows = [{"receipt_id": str(i), "case_id": "case"} for i in range(1001)]
        refs = archive(Receiver(), 7, "JS26-B-014", snapshot, rows)
        self.assertEqual(len(refs), 2)
        self.assertEqual(sum(len(call["records"]) for call in calls), 1001)

    def test_altered_archive_receipt_is_rejected(self):
        class Receiver:
            def call(self, path, body):
                return 201, {"id": "artifact", "sha256": "wrong", "input_sha256": digest(body["snapshot"])}
        with self.assertRaises(Invalid):
            archive(Receiver(), 7, "team", {}, [{"case_id": "c"}])


def case(*, kind="attack", detected=None, outcome=None, actor="red", identifier="case"):
    receipts = [{"receipt_id": identifier + "-delivered", "kind": "delivered", "producer_kind": "runner",
                 "producer_id": "runner", "observed_at": utc(START), "measurements": {"delivered": True}},
                {"receipt_id": identifier + "-outcome", "kind": "outcome", "producer_kind": "verifier",
                 "producer_id": "verifier", "observed_at": utc(START + dt.timedelta(seconds=61)), "measurements": outcome or {"objective_reached": True}}]
    if detected is not None:
        receipts.append({"receipt_id": identifier + "-detection", "kind": "detection", "producer_kind": "competitor",
                         "producer_id": "competitor", "team": "blue", "observed_at": utc(START + dt.timedelta(seconds=detected)),
                         "measurements": {"classification": "attack", "incident_id": "incident"}})
    return {"case_id": identifier, "scenario": {"label": kind, "family": "evasion", "assertions": []},
            "objective": {"id": 1}, "actor_team": actor, "target_team": "blue", "target_id": "target",
            "starts_at": utc(START), "deadline_at": utc(START + dt.timedelta(minutes=5)),
            "environment": "competition", "receipts": receipts,
            "required_producers": {"runner": ["runner"], "verifier": ["verifier"], "competitor": ["competitor"], "gateway": []}}


def health(team="blue"):
    return [{"receipt_id": "health-" + kind, "kind": "source_health", "producer_kind": kind, "team": team,
             "producer_id": kind, "target_id": "target",
             "measurements": {"start": utc(START), "end": utc(END), "expected": 40, "completed": 40, "lost": 0}}
            for kind in ("runner", "verifier")]


class FactTests(unittest.TestCase):
    def test_platform_ids_alerts_never_credit_competitor_detection(self):
        event = case(detected=3)
        event["receipts"][-1]["producer_kind"] = "gateway"
        facts, quality, _ = build("application_blue", "detected", "blue", [event], [], health(), START, END)
        self.assertEqual(facts, {"attacks": 1, "detected": 0})
        self.assertTrue(quality["receipts_complete"])

    def test_missing_source_health_stays_pending_not_a_verified_miss(self):
        _, quality, _ = build("ai_blue", "recall", "blue", [case()], [], [], START, END)
        self.assertFalse(quality["receipts_complete"])

    def test_healthy_unrelated_source_cannot_hide_a_defender_gap(self):
        rows = health()
        rows[1]["producer_id"] = "unrelated-verifier"
        _, quality, _ = build("ai_red", "missed", "red", [case()], [], rows, START, END)
        self.assertFalse(quality["receipts_complete"])
        rows[1]["producer_id"] = "verifier"
        rows[1]["target_id"] = "another-target"
        _, quality, _ = build("ai_blue", "recall", "blue", [case()], [], rows, START, END)
        self.assertFalse(quality["receipts_complete"])

    def test_independently_observed_silence_uses_the_paired_defenders_coverage(self):
        _, quality, _ = build("ai_red", "missed", "red", [case()], [], health("blue"), START, END)
        self.assertTrue(quality["receipts_complete"])

    def test_cross_team_workload_does_not_receive_the_ai_defenders_marks(self):
        event = case(detected=10)
        event.update(target_team="application-owner", defender_team="blue")
        facts, quality, _ = build("ai_blue", "recall", "blue", [event], [], health(), START, END)
        self.assertTrue(quality["receipts_complete"])
        self.assertEqual(facts["detection_seconds"], [10])
        facts, _, _ = build("ai_blue", "recall", "application-owner", [event], [], health(), START, END)
        self.assertEqual(facts["detection_seconds"], [])

    def test_late_reviewed_finding_removes_protection_credit(self):
        event = case(outcome={"objective_reached": False, "protected": True, "legitimate_ok": True})
        event.update(no_valid_finding=True, paired_build_verified=True, target_id="ENT-A/APP01", opportunity_key="paired")
        event["scenario"]["assertions"] = [{"key": key, "operator": "eq", "expected": True}
                                            for key in ("paired_build_verified", "no_valid_finding")]
        peer = dict(event, case_id="peer", target_team="peer", target_id="ENT-B/APP01")
        coverage = [dict(row, target_id="ENT-A/APP01") for row in health()]
        facts, quality, evidence = build("application_blue", "unfound", "blue", [event, peer], [], coverage, START, END)
        self.assertTrue(quality["receipts_complete"])
        self.assertIn("peer", {row.get("case_id") for row in evidence})
        self.assertEqual(facts, {"eligible": 1, "protected": 1})
        event["no_valid_finding"] = False
        facts, _, _ = build("application_blue", "unfound", "blue", [event, peer], [], coverage, START, END)
        self.assertEqual(facts["protected"], 0)

    def test_correct_inaction_requires_a_frozen_assertion(self):
        event = case(outcome={"objective_reached": False, "response_authorized": True, "mitigated": True,
                              "legitimate_ok": True, "response_no_action_required": True})
        facts, quality, _ = build("application_blue", "response", "blue", [event], [], health(), START, END)
        self.assertFalse(quality["receipts_complete"])
        event["scenario"]["assertions"] = [{"key": "response_no_action_required", "operator": "eq", "expected": True}]
        facts, quality, _ = build("application_blue", "response", "blue", [event], [], health(), START, END)
        self.assertTrue(quality["receipts_complete"])
        self.assertEqual(facts, {"required": 4, "passed": 4})

    def test_separate_runtime_checks_merge_without_overwriting(self):
        event = case()
        for key in ("scope", "budget", "reversal", "kill_switch"):
            event["receipts"].append({"receipt_id": key, "producer_kind": "verifier", "producer_id": "verifier",
                                      "kind": "outcome", "measurements": {"runtime_checks": {key: True}}})
        facts, quality, _ = build("ai_blue", "safety", "blue", [event], [], health(), START, END)
        self.assertTrue(quality["receipts_complete"])
        self.assertTrue(all(facts.values()))

    def test_late_transport_is_distinct_from_detection_latency(self):
        event = case(detected=10)
        event["receipts"][-1]["received_at"] = utc(END + dt.timedelta(minutes=5))
        facts, _, _ = build("ai_blue", "recall", "blue", [event], [], health(), START, END)
        self.assertEqual(facts, {"detection_seconds": [10.0]})

    def test_unverified_and_unrecovered_actions_never_earn_harm_marks(self):
        event = case(outcome={"induced": True, "harmful": True, "action_verified": False, "recovered": True})
        facts, _, _ = build("ai_red", "false", "red", [event], [], health("red"), START, END)
        self.assertEqual(facts["objective_ids"], [])
        event["receipts"][1]["measurements"].update(action_verified=True, recovered=False)
        facts, _, _ = build("ai_red", "false", "red", [event], [], health("red"), START, END)
        self.assertEqual(facts["objective_ids"], [])

    def test_same_objective_repeated_does_not_multiply_red_credit(self):
        facts, _, _ = build("ai_red", "missed", "red", [case(identifier="one"), case(identifier="two")], [], health("red"), START, END)
        self.assertEqual(len(facts["objective_ids"]), 1)

    def test_induced_harm_requires_one_matching_executed_verified_reversed_action(self):
        event = case(outcome={"objective_reached": False, "induced": True, "harmful": True,
                              "action_verified": True, "recovered": True, "action_id": "action-one"})
        event["required_producers"]["gateway"] = ["gateway"]
        coverage = health() + [dict(health()[0], producer_id="gateway", producer_kind="gateway")]
        for state in ("executed", "verified", "reverted"):
            event["receipts"].append({"receipt_id": state, "producer_id": "gateway", "producer_kind": "gateway",
                                      "kind": "action", "measurements": {"action_id": "action-two", "state": state}})
        facts, quality, _ = build("ai_red", "false", "red", [event], [], coverage, START, END)
        self.assertEqual(facts["objective_ids"], [])
        self.assertFalse(quality["receipts_complete"])
        for row in event["receipts"][-3:]:
            row["measurements"]["action_id"] = "action-one"
        facts, quality, _ = build("ai_red", "false", "red", [event], [], coverage, START, END)
        self.assertEqual(facts["objective_ids"], ["1:target"])
        self.assertTrue(quality["receipts_complete"])

    def test_rehearsal_case_does_not_count_as_official(self):
        event = case(detected=0)
        event["environment"] = "rehearsal"
        facts, quality, _ = build("ai_blue", "recall", "blue", [event], [], health(), START, END)
        self.assertEqual(facts["detection_seconds"], [])
        self.assertFalse(quality["receipts_complete"])

    def test_availability_retains_expected_denominator_and_records_failure(self):
        probes = [{"receipt_id": "one", "producer_kind": "verifier", "target_id": "target", "observed_at": utc(START),
                   "measurements": {"successful": False, "expected": 1, "completed": 1}}]
        facts, _, _ = availability(probes, [], START, START + dt.timedelta(seconds=30), ["target"])
        self.assertEqual(facts, {"expected": 2, "completed": 1, "successful": 0})

    def test_duplicate_probe_slot_is_not_additional_availability(self):
        probes = [{"receipt_id": identity, "producer_kind": "verifier", "target_id": "target", "observed_at": utc(START),
                   "measurements": {"successful": True, "expected": 1, "completed": 1}} for identity in ("one", "two")]
        facts, _, _ = availability(probes, [], START, START + dt.timedelta(seconds=15), ["target"])
        self.assertEqual(facts["completed"], 1)


class SourceCursorTests(unittest.TestCase):
    def test_receipt_uuid_is_scoped_to_producer_and_sequence_conflicts_are_atomic(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = SourceCache(pathlib.Path(directory) / "sources.sqlite3", 7)
            try:
                rows = [{"receipt_id": "same-uuid", "producer_id": producer, "sequence": i,
                         "producer_kind": "verifier", "kind": "probe", "target_id": producer,
                         "observed_at": utc(START), "measurements": {"successful": True, "expected": 1, "completed": 1}}
                        for i, producer in enumerate(("source-one", "source-two"), 1)]
                page = {"schema_version": "scoring-receipts/1.0", "competition": 7, "cases": [],
                        "receipts": rows, "next_cursor": 2, "cases_next_cursor": 0}
                cache.ingest(page)
                _, probes, _ = cache.window(START, END)
                facts, _, _ = availability(probes, [], START, START + dt.timedelta(seconds=15), ["source-one", "source-two"])
                self.assertEqual(facts, {"expected": 2, "completed": 2, "successful": 2})
                with self.assertRaisesRegex(Invalid, "source_sequence_conflict"):
                    cache.ingest(dict(page, receipts=[dict(rows[0], producer_id="source-three")]))
                self.assertEqual(cache.window(START, END)[1], rows)
                self.assertEqual(cache.cursor("next_cursor"), 2)
            finally:
                cache.close()

    def test_late_event_is_discovered_by_receipt_sequence_after_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "sources.sqlite3"
            cache = SourceCache(path, 7)
            first = {"schema_version": "scoring-receipts/1.0", "competition": 7,
                     "cases": [], "receipts": [], "next_cursor": 0, "cases_next_cursor": 0}
            cache.ingest(first)
            cache.close()
            cache = SourceCache(path, 7)
            try:
                probe = {"receipt_id": "late", "sequence": 1, "kind": "probe", "observed_at": utc(START), "measurements": {}}
                cache.ingest(dict(first, receipts=[probe], next_cursor=1))
                _, probes, _ = cache.window(START, END)
                self.assertEqual(probes, [probe])
                with self.assertRaises(Invalid):
                    cache.ingest(dict(first, receipts=[dict(probe, measurements={"changed": True})], next_cursor=1))
                self.assertEqual(cache.cursor("next_cursor"), 1)
            finally:
                cache.close()


def sealed_proof(value):
    def fingerprint(item):
        encoded = json.dumps(item, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
        return hashlib.sha256(encoded).hexdigest()
    result = dict(value)
    result["receipt_id"] = "air_" + fingerprint(result)
    result["integrity_hash"] = "sha256:" + fingerprint(result)
    return result


class SourceProofTests(unittest.TestCase):
    def test_embedded_effect_is_retrievable_and_tampering_prevents_any_retention(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = SourceCache(pathlib.Path(directory) / "sources.sqlite3", 7)
            try:
                effect = sealed_proof({"schema_version": "ai-effect-evidence/1.0", "competition": 7,
                                       "case_id": "case", "target_id": "target", "occurred_at": utc(START), "label": "é"})
                parent = sealed_proof({"schema_version": "ai-receipt/1.0", "competition": 7,
                                       "case_id": "case", "target_id": "target", "payload": {"proof": effect}})
                corrupted = copy.deepcopy(parent)
                corrupted["payload"]["proof"]["label"] = "changed"
                with self.assertRaisesRegex(Invalid, "embedded_proof_integrity"):
                    cache.retain_proof(corrupted)
                self.assertIsNone(cache.proof("ai", parent["receipt_id"]))
                self.assertIsNone(cache.proof("ai", effect["receipt_id"]))
                cache.retain_proof(parent)
                self.assertEqual(cache.proof("ai", effect["receipt_id"]), effect)
                self.assertEqual(cache.proof("ai", parent["receipt_id"]), parent)
            finally:
                cache.close()

    def test_reused_reference_must_validate_against_each_issued_case(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = SourceCache(pathlib.Path(directory) / "sources.sqlite3", 7)
            try:
                proof = sealed_proof({"schema_version": "ai-effect-evidence/1.0", "competition": 7,
                                      "case_id": "case", "target_id": "target", "occurred_at": utc(START)})
                cache.retain_proof(proof)
                first = case()
                first["evidence_refs"] = [{"family": "ai", "id": proof["receipt_id"]}]
                identity = {"targets": [{"target_id": "target"}]}
                resolver = ProofResolver(cache)
                records = resolver.complete([first, first], identity, START, END)
                self.assertEqual(len([row for row in records if row.get("family") == "ai"]), 1)
                with self.assertRaisesRegex(Invalid, "ai_proof_wrong_case"):
                    resolver.complete([first, dict(first, case_id="different-case")], identity, START, END)
            finally:
                cache.close()


class CollectorRecoveryTests(unittest.TestCase):
    def test_oversized_exports_shrink_pages_without_skipping_cursors(self):
        for error in (Failure(413, "http_413"), Invalid("body_too_large")):
            for source in ("platform", "ai"):
                with self.subTest(error=str(error), source=source):
                    sizes = []
                    page = {"has_more": False, "cases_has_more": False}
                    def read(path):
                        query = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)
                        sizes.append(int(query["limit"][0]))
                        if source == "ai":
                            self.assertEqual(urllib.parse.urlsplit(path).path, "/api/v1/scoring/receipts")
                        self.assertEqual(query["after"], ["cursor" if source == "ai" else "3"])
                        if sizes[-1] > 1:
                            raise error
                        return 200, page
                    collector = Collector.__new__(Collector)
                    collector.competition, collector.cache = 7, Mock()
                    collector.ai_prefix = "/api/v1/scoring"
                    collector.cache.cursor.return_value = 3
                    collector.platform = collector.ai_client = Mock(call=read)
                    if source == "platform":
                        self.assertTrue(collector.collect())
                        collector.cache.ingest.assert_called_once_with(page)
                    else:
                        self.assertIs(collector._ai_rows("cursor", 100), page)
                    self.assertEqual(sizes[-1], 1)
                    collector.ai_client = Mock(call=Mock(side_effect=error))
                    with self.assertRaises(type(error)):
                        collector._ai_rows("cursor", 1)
                    collector.ai_client.call.assert_called_once()

    def test_ack_uses_the_same_explicit_facade_or_private_backend_prefix(self):
        for prefix in ("/api/v1/scoring", "/api/v1"):
            collector = Collector.__new__(Collector)
            collector.ai_prefix = prefix
            collector.ai_client = Mock()
            collector.ai_client.call.return_value = (200, {})
            collector._ai_ack("durably-retained-cursor")
            collector.ai_client.call.assert_called_once_with(prefix + "/receipts/ack", {"cursor": "durably-retained-cursor"})

    def test_readonly_check_runs_while_daemon_holds_its_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            token = root / "token"
            token.write_text("isolated-test-token")
            token.chmod(0o600)
            config = {"schema_version": "scoring-collector/1.0", "competition": 7,
                      "platform_url": "https://platform.invalid", "feed_token_file": str(token),
                      "state_dir": str(root), "source_cache_bytes": 1048576,
                      "window_start": utc(START), "window_end": utc(END), "producers": {}, "probes": {}}
            path = root / "config.json"
            path.write_bytes(canonical(config))
            now = dt.datetime.now(dt.timezone.utc)
            response = {"schema_version": "scoring-identity/2.0", "competition": {"id": 7},
                        "historical": True,
                        "captured_at": utc(now - dt.timedelta(seconds=1)), "expires_at": utc(now + dt.timedelta(seconds=119))}
            with (root / "collector.lock").open("a") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                before = set(root.iterdir())
                policy = types.SimpleNamespace(POLICY_VERSION="main-scoring/1.0")
                with patch.dict(sys.modules, {"jengasec_scoring_policy": policy}), patch("scoring_obs.cli.Client") as client:
                    client.return_value.call.return_value = (200, response)
                    self.assertEqual(main(["--config", str(path), "--check"]), 0)
                self.assertEqual(set(root.iterdir()), before)


class NativeHttpTests(unittest.TestCase):
    def test_slow_body_has_a_total_deadline_even_when_each_read_arrives_in_time(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", "100")
                self.end_headers()
                try:
                    for _ in range(100):
                        self.wfile.write(b"x")
                        self.wfile.flush()
                        time.sleep(0.02)
                except OSError:
                    pass

            def log_message(self, *args):
                pass
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            began = time.monotonic()
            self.assertEqual(_get({"ip_address": "127.0.0.1", "port": server.server_port}, "/slow", timeout=0.12), (False, None))
            self.assertLess(time.monotonic() - began, 1)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_actual_ready_server_with_wrong_functional_result_fails(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = b'{"operational":false}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            target = {"ip_address": "127.0.0.1", "port": server.server_port}
            spec = {"health_path": "/healthz", "functional_path": "/functional",
                    "assertions": [{"path": ["operational"], "equals": True}]}
            self.assertFalse(measure(target, spec))
            spec["assertions"][0]["equals"] = False
            self.assertTrue(measure(target, spec))
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_redirect_does_not_forward_feed_credential(self):
        received = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                received.append(self.path)
                self.send_response(302)
                self.send_header("Location", "/capture")
                self.end_headers()

            def log_message(self, *args):
                pass
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = Client(f"http://127.0.0.1:{server.server_port}", {"X-Feed-Token": "test-only"}, loopback_http=True)
            with self.assertRaises(Failure):
                client.call("/redirect")
            self.assertEqual(received, ["/redirect"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == "__main__":
    unittest.main()
