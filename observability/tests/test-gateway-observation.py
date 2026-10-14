#!/usr/bin/env python3
"""Prove companion logging preserves all original terminal verdict rules."""

import pathlib
import importlib.util
import signal
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "observability/network"))
from nft_verdict_logging import add_verdict_observation

spec = importlib.util.spec_from_file_location("install_hook", ROOT / "scripts/install-firewall-observation.py")
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)

spec = importlib.util.spec_from_file_location("flow_runner", ROOT / "scripts/run-gateway-flow-decoder.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def rules():
    prefix = "add rule inet test_guard forward_guard "
    return [
        "flush chain inet test_guard forward_guard",
        prefix + 'iifname "wg-test" ip saddr { 192.0.2.0/24 } ct state invalid drop',
        prefix + 'iifname "wg-test" ip saddr { 192.0.2.0/24 } ip daddr { 192.0.2.0/24 } drop comment "JengaSec peer isolation"',
        prefix + 'iifname "wg-test" ip saddr { 192.0.2.0/24 } ip daddr { 198.51.100.0/24 } drop comment "JengaSec protected destinations"',
        prefix + 'oifname "wg-test" ip daddr { 192.0.2.0/24 } ct state new drop comment "JengaSec no inbound initiation"',
        prefix + 'oifname "wg-test" ip daddr { 192.0.2.0/24 } ct state established,related accept',
        prefix + 'iifname "wg-test" ip saddr 192.0.2.1/32 ip daddr 203.0.113.1 tcp dport { 443 } ct state { new, established, related } accept comment "JengaSec allow participant 1 target 2"',
        prefix + 'iifname "wg-test" ip saddr { 192.0.2.0/24 } drop comment "JengaSec default deny"',
    ]


class GatewayObservationTests(unittest.TestCase):
    def test_decoder_shutdown_is_clean_and_unexpected_failure_is_visible(self):
        for requested_stop in (False, True):
            with self.subTest(requested_stop=requested_stop):
                handlers = {}
                decoder, forwarder = Mock(), Mock()
                decoder.poll.return_value = -15
                forwarder.poll.return_value = -15
                def wait():
                    if requested_stop:
                        handlers[signal.SIGTERM](signal.SIGTERM, None)
                    return -15
                forwarder.wait.side_effect = lambda **_kwargs: wait()
                with patch.object(runner.subprocess, "Popen", side_effect=[decoder, forwarder]), \
                     patch.object(runner.signal, "signal", side_effect=lambda kind, handler: handlers.update({kind: handler})), \
                     patch.object(sys, "argv", ["decoder", "--goflow2", "/opt/obs/goflow2", "--config", "/etc/obs/config.json"]):
                    self.assertEqual(runner.main(), 0 if requested_stop else -15)

    def test_verdicts_remain_unlimited_and_in_the_original_order(self):
        original = rules()
        result = add_verdict_observation(original, "test_guard")
        self.assertEqual(result[0], original[0])
        self.assertEqual(result[2::2], original[1:])
        self.assertTrue(all(" limit " not in rule for rule in result[2::2]))
        self.assertTrue(all(" log prefix " in rule for rule in result[1::2]))
        self.assertTrue(all("participant" not in rule and "target" not in rule for rule in result[1::2]))

    def test_allow_and_deny_assignments_keep_their_verdict(self):
        original = rules()
        original[-2] = original[-2].replace(' accept comment "JengaSec allow', ' drop comment "JengaSec deny')
        result = add_verdict_observation(original, "test_guard")
        self.assertIn('JENGASEC_OBS:refused:assigned_policy ', result[-4])
        self.assertEqual(result[-3], original[-2])

    def test_unreviewed_generator_changes_fail_closed(self):
        for line in ("flush ruleset", 'add rule inet test_guard forward_guard tcp dport 22 accept comment "unknown"', rules()[1] + "\nflush ruleset"):
            with self.subTest(line=line):
                with self.assertRaises(ValueError):
                    add_verdict_observation([rules()[0], line], "test_guard")
        with self.assertRaises(ValueError):
            add_verdict_observation(rules(), "test_guard", rate=1000)

    def test_source_guard_and_private_rollback_copy(self):
        source = """def apply_firewall(cur):
    # JengaSec default deny; JengaSec peer isolation; JengaSec protected destinations
    lines=[]
    content='\\n'.join(lines)+'\\n'
    run(['nft','-c','-f','-'],content)
    run(['nft','-f','-'],content)
"""
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            worker, reviewed = root / "worker.py", root / "reviewed.py"
            helper = root / "helper.py"
            worker.write_text(source)
            reviewed.write_text(source)
            helper.write_text("def add_verdict_observation(lines, table): return lines\n")
            worker.write_text(source + "# concurrent change\n")
            with self.assertRaisesRegex(ValueError, "reviewed source"):
                installer.install(worker, reviewed, helper, root / "rollback", apply=True)
            worker.write_text(source)
            self.assertEqual(installer.install(worker, reviewed, helper, root / "rollback", apply=True), "installed")
            self.assertEqual((root / "rollback/provision_worker.py.original").read_text(), source)
            self.assertEqual((root / "rollback").stat().st_mode & 0o777, 0o700)
            self.assertEqual(installer.install(worker, reviewed, helper, root / "rollback", apply=True), "unchanged")


if __name__ == "__main__":
    unittest.main()
