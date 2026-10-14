#!/usr/bin/env python3
"""Verify collector failure states, bounded output and read-only DB access."""
import importlib.util
import json
from pathlib import Path
import unittest

path = Path(__file__).resolve().parents[2] / "scripts/collect-infrastructure-metrics.py"
spec = importlib.util.spec_from_file_location("collector", path)
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


class CollectorTests(unittest.TestCase):
    def test_freshness_timestamp_preserves_subsecond_clock_value(self):
        now = 1_800_000_123.875
        data = collector.collect({}, now=now)
        stamp = next(float(line.split()[1]) for line in data.splitlines()
                     if line.startswith("jengasec_collection_timestamp_seconds "))
        self.assertLess(abs(now - stamp), 0.001)

    def test_missing_service_is_not_a_healthy_zero(self):
        data = collector.collect({"services": ["required.service"]},
                                 lambda _: "LoadState=not-found\nActiveState=inactive\n", now=1000)
        self.assertIn('jengasec_service_expected{service="required.service"} 1', data)
        self.assertIn('jengasec_service_loaded{service="required.service"} 0', data)
        self.assertIn('jengasec_service_up{service="required.service"} 0', data)
        self.assertIn('jengasec_collection_success{collector="services"} 1', data)

    def test_empty_vpn_is_valid_and_peer_keys_never_leave_collector(self):
        def empty(command):
            if command[0] == "ip":
                return '[{"flags": ["UP"]}]'
            return "wg0\n" if command[-1] == "interfaces" else ""
        data = collector.collect({"wireguard_interface": "wg0"}, empty, now=1000)
        self.assertIn('jengasec_wireguard_peers{interface="wg0"} 0', data)
        self.assertIn('jengasec_collection_success{collector="wireguard"} 1', data)

        def peers(command):
            if command[0] == "ip":
                return '[{"flags": ["UP"]}]'
            if command[-1] == "interfaces":
                return "wg0\n"
            return "NEVER_EXPORT_THIS_KEY 950\n" if command[-1] == "latest-handshakes" else "NEVER_EXPORT_THIS_KEY 200 300\n"
        data = collector.collect({"wireguard_interface": "wg0"}, peers, now=1000)
        self.assertNotIn("NEVER_EXPORT_THIS_KEY", data)
        self.assertIn('jengasec_wireguard_peers_recent{interface="wg0"} 1', data)
        self.assertIn('jengasec_wireguard_receive_bytes_total{interface="wg0"} 200', data)

    def test_failed_vpn_does_not_publish_partial_healthy_values(self):
        def broken(command):
            if command[0] == "ip":
                return '[{"flags": ["UP"]}]'
            if command[-1] == "interfaces":
                return "wg0\n"
            raise RuntimeError("sensitive upstream error")
        data = collector.collect({"wireguard_interface": "wg0"}, broken, now=1000)
        self.assertIn('jengasec_collection_success{collector="wireguard"} 0', data)
        self.assertNotIn("wireguard_interface_up", data)
        self.assertNotIn("sensitive", data)

    def test_database_uses_read_only_monitor_role_and_only_aggregates(self):
        calls = []
        def database(command):
            calls.append(command)
            return json.dumps(dict(max_connections=100, connections=3, active_connections=1,
                                   waiting_locks=0, deadlocks=0, commits=10, rollbacks=2,
                                   database_bytes=123, recovery=False))
        data = collector.collect({"postgresql": True}, database, now=1000)
        self.assertIn("BEGIN READ ONLY;", calls[0][-1])
        self.assertIn("SET LOCAL ROLE pg_monitor;", calls[0][-1])
        self.assertIn("jengasec_postgres_connections 3", data)
        self.assertNotIn("datname", data)
        self.assertNotIn("query", data)

    def test_configuration_rejects_unbounded_or_executable_values(self):
        for config in [{"services": ["a;touch x.service"]},
                       {"wireguard_interface": "wg0;id"}, {"command": "id"},
                       {"postgresql": "yes"}, {"services": ["same.service"] * 40}]:
            with self.subTest(config=config), self.assertRaises(ValueError):
                collector.validate(config)


if __name__ == "__main__":
    unittest.main()
