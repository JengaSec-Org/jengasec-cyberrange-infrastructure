#!/usr/bin/env python3
"""Exercise optional node ingress without touching the host firewall or services."""

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]


class NodeIngressTests(unittest.TestCase):
    def test_exact_opt_in_rule_is_idempotent_and_unsafe_inputs_fail_closed(self):
        ansible = os.environ.get("OBS_TEST_ANSIBLE") or shutil.which("ansible-playbook")
        self.assertTrue(ansible, "ansible-playbook is required for the ingress test")
        with tempfile.TemporaryDirectory(prefix="jengasec-node-ufw-") as temporary:
            base = Path(temporary)
            binaries = base / "bin"
            binaries.mkdir()
            state = base / "ufw.json"
            initial = {"active": True, "rules": [["existing-owner-rule"]], "calls": []}
            state.write_text(json.dumps(initial))
            ufw = binaries / "ufw"
            ufw.write_text("#!" + sys.executable + "\n" + textwrap.dedent('''\
                import json, os, pathlib, sys
                path = pathlib.Path(os.environ["OBS_UFW_TEST_STATE"])
                state = json.loads(path.read_text())
                args = sys.argv[1:]
                state["calls"].append(args)
                if args == ["status"]:
                    print("Status: " + ("active" if state["active"] else "inactive"))
                elif args[:1] == ["allow"]:
                    if args in state["rules"]:
                        print("Skipping adding existing rule")
                    else:
                        state["rules"].append(args)
                        print("Rule added")
                else:
                    raise SystemExit("Unexpected UFW mutation: " + repr(args))
                path.write_text(json.dumps(state))
                '''))
            ufw.chmod(0o755)
            ip = binaries / "ip"
            ip.write_text("#!" + sys.executable + "\n" + textwrap.dedent('''\
                import json, sys
                assert sys.argv[1:] == ["-4", "-json", "address", "show", "dev", "obs0"]
                print(json.dumps([{"addr_info": [{"local": "10.42.0.20"}]}]))
                '''))
            ip.chmod(0o755)
            playbook = base / "test.yml"
            playbook.write_text(yaml.safe_dump([{
                "hosts": "localhost", "connection": "local", "gather_facts": False,
                "vars": {"ansible_python_interpreter": sys.executable},
                "environment": {"PATH": str(binaries) + ":" + os.environ["PATH"],
                                "OBS_UFW_TEST_STATE": str(state)},
                "tasks": [{"ansible.builtin.include_role": {
                    "name": "observability_node", "tasks_from": "ufw"}}],
            }], sort_keys=False))
            variables = base / "variables.json"
            environment = dict(os.environ, ANSIBLE_NOCOLOR="1",
                               ANSIBLE_STDOUT_CALLBACK="default",
                               ANSIBLE_ROLES_PATH=str(ROOT / "ansible/roles"))

            def run(values, success=True, check=False):
                variables.write_text(json.dumps(values))
                args = [ansible, "--inventory", "localhost,", "--forks", "1",
                        str(playbook), "--extra-vars", "@" + str(variables)]
                if check:
                    args.append("--check")
                result = subprocess.run(args, env=environment, capture_output=True,
                                        text=True, timeout=45)
                output = result.stdout + result.stderr
                if not success:
                    self.assertNotEqual(result.returncode, 0, output)
                    return
                self.assertEqual(result.returncode, 0, output[-5000:])
                recap = re.search(r"localhost\s+:\s+ok=\d+\s+changed=(\d+).*failed=0", output)
                self.assertIsNotNone(recap, output[-1500:])
                return int(recap.group(1))

            self.assertEqual(run({}), 0)
            self.assertEqual(json.loads(state.read_text()), initial,
                             "Default-off must not inspect or change UFW")
            values = {"obs_node_manage_ufw": True, "obs_node_address": "10.42.0.20",
                      "obs_node_ufw_source_address": "10.42.0.10", "obs_node_ufw_interface": "obs0"}
            self.assertEqual(run(values, check=True), 0)
            self.assertEqual(json.loads(state.read_text())["rules"], initial["rules"])
            self.assertEqual(run(values), 1)
            self.assertEqual(run(values), 0)
            expected = ["allow", "in", "on", "obs0", "proto", "tcp", "from", "10.42.0.10",
                        "to", "10.42.0.20", "port", "9100", "comment", "JengaSec observability"]
            self.assertEqual(json.loads(state.read_text())["rules"], initial["rules"] + [expected])

            for override in ({"obs_node_ufw_source_address": "0.0.0.0/0"},
                             {"obs_node_ufw_source_address": "8.8.8.8"},
                             {"obs_node_address": "10.42.0.21"}):
                with self.subTest(override=override):
                    before = json.loads(state.read_text())
                    run(dict(values, **override), success=False)
                    self.assertEqual(json.loads(state.read_text()), before)

            inactive = json.loads(state.read_text())
            inactive["active"] = False
            state.write_text(json.dumps(inactive))
            run(values, success=False)
            after = json.loads(state.read_text())
            self.assertEqual(after["rules"], inactive["rules"])
            self.assertEqual(after["calls"][len(inactive["calls"]):], [["status"]])
            self.assertFalse(after["active"], "The role must never enable UFW")


if __name__ == "__main__":
    unittest.main()
