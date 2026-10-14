#!/usr/bin/env python3
"""Exercise OBS configuration notifications without Docker, systemd or accounts.

Run with ansible-playbook on PATH, or set OBS_TEST_ANSIBLE. OBS_TEST_SOURCE_ROOT
may select a source checkout; the test copies it before running the role.
"""

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]


class ConfigurationNotificationTests(unittest.TestCase):
    def test_publisher_and_environment_changes_notify_but_identical_runs_do_not(self):
        ansible = os.environ.get("OBS_TEST_ANSIBLE") or shutil.which("ansible-playbook")
        self.assertTrue(ansible, "ansible-playbook is required for the notification regression")
        source = Path(os.environ.get("OBS_TEST_SOURCE_ROOT", ROOT)).resolve()
        with tempfile.TemporaryDirectory(prefix="jengasec-config-notifications-") as temporary:
            base = Path(temporary)
            checkout = base / "source"
            # Freeze the inputs across every same-release run. No source checkout
            # or running service is changed by this test.
            for directory in ("scripts", "contracts", "observability", "ansible/roles/observability"):
                shutil.copytree(source / directory, checkout / directory,
                                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".runtime"))
            play = yaml.safe_load((source / "ansible/observability-rehearsal.yml").read_text())[0]
            play["vars"].update({
                "obs_rehearsal_root": str(base / "runtime"),
                "obs_rehearsal_mode": False,
                "obs_attribution_mode": "disabled",
                "obs_infrastructure_enabled": False,
                "obs_manage_packages": False,
                "obs_manage_systemd": False,
                "obs_manage_storage_ownership": False,
                "obs_validate_runtime": False,
                "obs_validate_network": False,
                "obs_start": False,
                "obs_python_command": sys.executable,
            })
            play["handlers"] = [{
                "name": "Record a requested OBS restart in the isolated test directory",
                "listen": "Restart observability stack",
                "ansible.builtin.command": {
                    "argv": [sys.executable, "-c",
                             "import pathlib,sys; "
                             "pathlib.Path(sys.argv[1]).open('a', encoding='utf-8').write('notified\\n')",
                             "{{ obs_rehearsal_root }}/notifications.txt"],
                },
                "changed_when": True,
            }]
            playbook = checkout / "ansible/config-notifications.yml"
            playbook.write_text(yaml.safe_dump([play], sort_keys=False))
            runtime = base / "runtime"
            runtime.mkdir(mode=0o700)
            notifications = runtime / "notifications.txt"
            values = {"obs_website_feed_url": "https://receiver.example/api/feed", "obs_grafana_port": 3000}

            def run():
                variables = base / "variables.json"
                variables.write_text(json.dumps(values))
                environment = dict(os.environ, ANSIBLE_NOCOLOR="1", ANSIBLE_STDOUT_CALLBACK="default")
                result = subprocess.run(
                    [ansible, "--inventory", "localhost,", "--forks", "1", str(playbook),
                     "--extra-vars", "@" + str(variables)],
                    cwd=checkout, env=environment, text=True, capture_output=True, timeout=180)
                self.assertEqual(result.returncode, 0, (result.stdout + result.stderr)[-6000:])
                recap = re.search(r"localhost\s+:\s+ok=\d+\s+changed=(\d+)\s+unreachable=0\s+failed=0", result.stdout)
                self.assertIsNotNone(recap, result.stdout[-1500:])
                return int(recap.group(1))

            def notification_count():
                return len(notifications.read_text().splitlines()) if notifications.exists() else 0

            def vector():
                return yaml.safe_load((runtime / "state/lookups/vector.yaml").read_text())

            self.assertGreater(run(), 0)
            self.assertIn("website_feed_publisher", vector()["sinks"])
            initial_notifications = notification_count()
            self.assertGreater(initial_notifications, 0)
            fingerprint = (runtime / "opt/current/.source-sha256").read_bytes()

            self.assertEqual(run(), 0, "identical configured deployment must be idempotent")
            self.assertEqual(notification_count(), initial_notifications)

            values["obs_website_feed_url"] = ""
            self.assertGreater(run(), 0, "disabling the publisher must request a restart")
            self.assertNotIn("website_feed_publisher", vector()["sinks"])
            self.assertNotIn("sanitized_website_feed", vector()["transforms"])
            self.assertEqual(notification_count(), initial_notifications + 1)
            self.assertEqual((runtime / "opt/current/.source-sha256").read_bytes(), fingerprint)

            self.assertEqual(run(), 0, "identical disabled deployment must be idempotent")
            self.assertEqual(notification_count(), initial_notifications + 1)

            values["obs_grafana_port"] = 3001
            self.assertGreater(run(), 0, "an environment-only change must request a restart")
            self.assertIn("JENGASEC_GRAFANA_PORT=3001", (runtime / "etc/observability.env").read_text())
            self.assertEqual(notification_count(), initial_notifications + 2)
            self.assertEqual((runtime / "opt/current/.source-sha256").read_bytes(), fingerprint)

            self.assertEqual(run(), 0, "identical environment deployment must be idempotent")
            self.assertEqual(notification_count(), initial_notifications + 2)
            self.assertFalse((runtime / "systemd").exists(), "test must not install host systemd units")


if __name__ == "__main__":
    unittest.main()
