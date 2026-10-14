#!/usr/bin/env python3
"""Run real Ansible opt-out control flow against isolated command fixtures."""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[3]
ROLE = ROOT / "ansible/roles/observability_cluster/tasks"
ANSIBLE = os.environ.get("ANSIBLE_PLAYBOOK", "ansible-playbook")


class OptOutTests(unittest.TestCase):
    def exercise(self, paused=False, race=False):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            state = root / "state.json"
            state.write_text(json.dumps({"paused": paused}))
            (root / "wal-guard.json").write_text("{}")
            timer = root / "guard.timer"
            timer.touch()
            log = root / "operations.jsonl"
            helper = root / "fixture.py"
            helper.write_text('''import json,pathlib,sys
root=pathlib.Path(__file__).parent
state=root/'state.json'
with (root/'operations.jsonl').open('a') as output: output.write(json.dumps(sys.argv[1:])+'\\n')
if sys.argv[1]=='can-start':
    raise SystemExit(1 if json.loads(state.read_text())['paused'] else 0)
if sys.argv[1:]==['systemd','jengasec-observability-wal-guard.service','stopped'] and (root/'race').exists():
    state.write_text('{"paused":true}')
''')
            (root / "guard-observability-wal.py").write_text(helper.read_text())
            if race:
                (root / "race").touch()
            tasks = yaml.safe_load((ROLE / "wal-guard-preflight.yml").read_text())

            def isolate(items):
                for task in items:
                    if "ansible.builtin.stat" in task:
                        task["ansible.builtin.stat"]["path"] = str(
                            timer if task["ansible.builtin.stat"]["path"].endswith(".timer") else state)
                    if "ansible.builtin.systemd_service" in task:
                        unit = task.pop("ansible.builtin.systemd_service")
                        task["ansible.builtin.command"] = {"argv": ["/usr/bin/python3", str(helper),
                            "systemd", unit["name"], unit["state"]]}
                    for key in ("block", "rescue"):
                        if key in task:
                            isolate(task[key])
            isolate(tasks)
            (root / "preflight.yml").write_text(yaml.safe_dump(tasks, sort_keys=False))
            # Use the real main-task condition, which must run even on opt-out.
            include = next(task.copy() for task in yaml.safe_load((ROLE / "main.yml").read_text())
                           if task.get("ansible.builtin.include_tasks") == "wal-guard-preflight.yml")
            include["ansible.builtin.include_tasks"] = str(root / "preflight.yml")
            play = [{"hosts": "localhost", "gather_facts": False, "vars": {
                "obs_cluster_root": str(root), "obs_cluster_apply": True,
                "obs_cluster_wal_guard_enabled": False}, "tasks": [include, {
                    "name": "Represent the downstream collector start",
                    "ansible.builtin.command": {"argv": ["/usr/bin/python3", str(helper), "collector-start"]}}]}]
            (root / "play.yml").write_text(yaml.safe_dump(play, sort_keys=False))
            result = subprocess.run([ANSIBLE, "-i", "localhost,", "-c", "local", str(root / "play.yml")],
                                    capture_output=True, text=True, timeout=45)
            operations = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
            return result.returncode, operations, result.stdout + result.stderr

    def test_disabled_guard_still_rejects_existing_pause_before_any_mutation(self):
        status, operations, output = self.exercise(paused=True)
        self.assertNotEqual(status, 0, output)
        self.assertTrue(operations)
        self.assertTrue(all(row[0] == "can-start" for row in operations), operations)

    def test_safe_opt_out_stops_timer_and_check_before_downstream_start(self):
        status, operations, output = self.exercise()
        self.assertEqual(status, 0, output)
        self.assertEqual([row for row in operations if row[0] == "systemd"], [
            ["systemd", "jengasec-observability-wal-guard.timer", "stopped"],
            ["systemd", "jengasec-observability-wal-guard.service", "stopped"]])
        self.assertEqual(operations[-1], ["collector-start"])

    def test_pause_during_opt_out_restores_guard_and_prevents_collector_start(self):
        status, operations, output = self.exercise(race=True)
        self.assertNotEqual(status, 0, output)
        self.assertNotIn(["collector-start"], operations)
        self.assertIn(["systemd", "jengasec-observability-wal-guard.timer", "started"], operations)


if __name__ == "__main__":
    unittest.main()
