#!/usr/bin/env python3
"""Validate source boundaries, durable delivery, and sanitized collector mappings."""

import copy
import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest

import jsonschema
from referencing import Registry, Resource


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import infrastructure_events as mappings

spec = importlib.util.spec_from_file_location("event_agent", ROOT / "scripts/collect-infrastructure-events.py")
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)
CONFIG = {"resource_id": "test-host", "environment": "live", "services": ["sample.service", "wg-quick@wg0.service"], "network": True, "interface": "wg0"}
SCHEMA = json.loads((ROOT / "contracts/infrastructure-source.schema.json").read_text())
REGISTRY = Registry().with_resource(SCHEMA["$id"], Resource.from_contents(SCHEMA))
VALIDATOR = jsonschema.Draft202012Validator(SCHEMA, registry=REGISTRY, format_checker=jsonschema.FormatChecker())


class ContractTests(unittest.TestCase):
    def test_positive_and_negative_source_fixtures(self):
        root = ROOT / "contracts/fixtures/infrastructure"
        for path in (root / "valid").glob("*.json"):
            with self.subTest(path=path.name):
                VALIDATOR.validate(json.loads(path.read_text()))
        for path in (root / "invalid").glob("*.json"):
            with self.subTest(path=path.name):
                self.assertTrue(list(VALIDATOR.iter_errors(json.loads(path.read_text()))))

    def test_auth_removes_person_command_and_raw_text(self):
        raw = {"__CURSOR": "cursor", "__REALTIME_TIMESTAMP": "1791972000000000", "_COMM": "sshd", "MESSAGE": "Accepted password for person@example.invalid from 192.0.2.10 port 40000 ssh2"}
        result = mappings.map_journal(CONFIG, raw)
        VALIDATOR.validate(result)
        self.assertEqual(result["event_type"], "host.auth_success")
        self.assertEqual(result["attributes"], {"mechanism": "password", "peer_ip": "192.0.2.10"})
        self.assertNotIn("person", mappings.canonical(result))
        self.assertNotIn("MESSAGE", mappings.canonical(result))

    def test_service_template_and_unknown_journal(self):
        raw = {"__CURSOR": "cursor", "__REALTIME_TIMESTAMP": "1791972000000000", "_COMM": "systemd", "UNIT": "wg-quick@wg0.service", "MESSAGE": "Started service with secret argument"}
        result = mappings.map_journal(CONFIG, raw)
        VALIDATOR.validate(result)
        self.assertEqual(result["resource"]["service"], "wg-quick@wg0.service")
        self.assertNotIn("secret", mappings.canonical(result))
        raw["UNIT"] = "unowned.service"
        self.assertIsNone(mappings.map_journal(CONFIG, raw))

    def test_flow_is_observation_and_not_firewall_decision(self):
        result = mappings.map_flow(CONFIG, {"src_addr": "192.0.2.1", "dst_addr": "198.51.100.1", "src_port": 40000, "dst_port": 443, "proto": "TCP", "bytes": 123, "packets": 2, "password": "discard", "payload": "discard"}, "flow-1")
        VALIDATOR.validate(result)
        self.assertNotIn("verdict", result["attributes"])
        self.assertNotIn("discard", mappings.canonical(result))
        self.assertEqual(result["event_type"], "network.flow")

    def test_only_actual_gateway_log_prefix_yields_verdict(self):
        raw = {"__CURSOR": "cursor", "__REALTIME_TIMESTAMP": "1791972000000000", "_TRANSPORT": "kernel", "MESSAGE": "JENGASEC_OBS:refused:default_deny IN=wg0 OUT=eth0 SRC=192.0.2.1 DST=198.51.100.1 PROTO=TCP SPT=40000 DPT=443"}
        result = mappings.map_journal(CONFIG, raw)
        VALIDATOR.validate(result)
        self.assertEqual(result["attributes"]["verdict"], "refused")
        raw["MESSAGE"] = raw["MESSAGE"].replace("IN=wg0", "IN=other0")
        self.assertIsNone(mappings.map_journal(CONFIG, raw))

    def test_ids_canary_is_separate_and_payload_is_removed(self):
        result = mappings.map_ids(CONFIG, {"event_type": "alert", "timestamp": "2026-10-14T09:00:00+00:00", "src_ip": "192.0.2.1", "dest_ip": "198.51.100.1", "proto": "ICMP", "payload": "discard", "http": {"url": "secret"}, "alert": {"signature_id": 9000001, "severity": 3, "action": "allowed", "category": "canary"}}, "eve:1")
        VALIDATOR.validate(result)
        self.assertEqual(result["environment"], "validation")
        self.assertNotIn("discard", mappings.canonical(result))
        self.assertNotIn("secret", mappings.canonical(result))


class DurableQueueTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = pathlib.Path(self.tmp.name) / "events.sqlite3"
        self.queue = agent.Queue(self.path, max_events=2, max_bytes=4096)

    def tearDown(self):
        self.queue.close()
        self.tmp.cleanup()

    def record(self, identity):
        return mappings.event(CONFIG, "host.boot", identity, "2026-10-14T09:00:00Z", {}, {})

    def test_restart_retains_cursor_and_unacknowledged_events(self):
        with self.queue.db:
            self.queue.append(self.record("boot-a"), cursor="journal-a")
        self.queue.close()
        self.queue = agent.Queue(self.path, max_events=2, max_bytes=4096)
        self.assertEqual(self.queue.get("journal_cursor"), "journal-a")
        self.assertEqual(len(self.queue.batch()), 1)
        with self.queue.db:
            self.queue.acknowledge(self.queue.batch())
        self.assertEqual(self.queue.size()[0], 0)
        self.assertEqual(self.queue.get("delivered_total"), "1")

    def test_rollback_keeps_previous_cursor_and_no_partial_event(self):
        with self.assertRaises(RuntimeError):
            with self.queue.db:
                self.queue.append(self.record("boot-a"), cursor="uncommitted")
                raise RuntimeError("interrupted")
        self.assertEqual(self.queue.size()[0], 0)
        self.assertEqual(self.queue.get("journal_cursor", ""), "")

    def test_bounded_queue_has_explicit_loss_and_deduplicates(self):
        with self.queue.db:
            for identity in ("a", "a", "b", "c"):
                self.queue.append(self.record(identity))
        self.assertEqual(self.queue.size()[0], 2)
        self.assertEqual(self.queue.get("dropped_total"), "1")


if __name__ == "__main__":
    unittest.main()
