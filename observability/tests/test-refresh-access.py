#!/usr/bin/env python3
"""Exercise refresh access controls with real renderers and disposable commands."""

import csv
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


class RefreshAccessTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="obs-refresh-access-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.scripts = self.root / "scripts"
        self.scripts.mkdir()
        for name in ("refresh-observability-state.sh", "sync-observability-lookups.sh",
                     "render-observability-lookups.py", "render-grafana-dashboards.py", "_lib.sh"):
            shutil.copy2(ROOT / "scripts" / name, self.scripts / name)
        self.fixtures = self.root / "fixtures"
        self.fixtures.mkdir()
        for name in ("applications.csv", "ip-allocations.csv", "scope-assignments.csv"):
            shutil.copy2(ROOT / "observability/tests/fixtures/attribution" / name, self.fixtures / name)
        shutil.copy2(ROOT / "observability/tests/fixtures/access/access-principals.csv",
                     self.fixtures / "access-principals.csv")
        self.lookups = self.root / "lookups"
        self.dashboards = self.root / "dashboards"
        self.calls = self.root / "calls.jsonl"
        self.memberships = self.root / "memberships.json"
        self.memberships.write_text('{"existing": ["fixture-viewer"]}\n')
        self.before_memberships = self.memberships.read_bytes()
        self.service = self.root / "service.conf"
        self.service.write_text("[obs_attribution]\n")
        self.service.chmod(0o600)
        self.compose = self.root / "compose.yaml"
        self.compose.touch()
        self.environment = self.root / "observability.env"
        self.environment.touch()
        self.password = self.root / "grafana-password"
        self.password.write_text("fixture-only-password\n")
        self.password.chmod(0o600)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
                        OBS_REFRESH_TEST_ROOT=str(self.root), PYTHONDONTWRITEBYTECODE="1")
        prelude = (f"#!{sys.executable}\nimport json,os,sys\nfrom pathlib import Path\n"
                   "root=Path(os.environ['OBS_REFRESH_TEST_ROOT'])\n"
                   "with (root/'calls.jsonl').open('a') as output:\n"
                   "    output.write(json.dumps([Path(sys.argv[0]).name,*sys.argv[1:]])+'\\n')\n")
        self.command(self.bin / "psql", prelude + """
if os.environ.get('OBS_REFRESH_TEST_DB_FAILURE') == '1':
    raise SystemExit(1)
query=sys.argv[-1]
if 'pg_stat_ssl' in query:
    print('t')
else:
    views={'obs_ip_allocations_v1':'ip-allocations.csv',
           'obs_applications_v1':'applications.csv',
           'obs_scope_assignments_v1':'scope-assignments.csv',
           'obs_access_principals_v1':'access-principals.csv'}
    filename=next(value for key,value in views.items() if key in query)
    print((root/'fixtures'/filename).read_text(),end='')
""")
        self.command(self.bin / "docker", prelude + """
if 'ps' in sys.argv:
    print('running-fixture-container')
""")
        self.command(self.scripts / "provision-grafana-access.py", prelude + """
(root/'memberships.json').write_text('{"converged": true}\\n')
""")

    @staticmethod
    def command(path, content):
        path.write_text(content)
        path.chmod(0o755)

    def run_refresh(self, *extra, grafana=False):
        command = ["bash", str(self.scripts / "refresh-observability-state.sh"),
                   "--service-file", str(self.service), "--lookup-dir", str(self.lookups),
                   "--dashboard-dir", str(self.dashboards), "--compose-file", str(self.compose),
                   "--env-file", str(self.environment)]
        if grafana:
            command += ["--grafana-url", "http://127.0.0.1:3000",
                        "--grafana-admin-password-file", str(self.password)]
        return subprocess.run(command + list(extra), env=self.env, capture_output=True,
                              text=True, timeout=20)

    def recorded(self, command):
        if not self.calls.exists():
            return []
        return [row for row in map(json.loads, self.calls.read_text().splitlines()) if row[0] == command]

    def assert_refreshed(self):
        with (self.lookups / "ip-allocations.csv").open() as handle:
            self.assertEqual(len(list(csv.DictReader(handle))), 4)
        self.assertTrue((self.lookups / "access-principals.csv").is_file())
        self.assertEqual(len(list(self.dashboards.glob("*.json"))), 18)
        dashboard = json.loads((self.dashboards / "jengasec-ent-a-app01.json").read_text())
        self.assertEqual(dashboard["uid"], "jengasec-ent-a-app01")
        self.assertFalse(dashboard["editable"])

    def test_default_and_explicit_true_keep_access_convergence(self):
        password = self.password.read_bytes()
        for arguments in ((), ("--manage-grafana-access", "true")):
            with self.subTest(arguments=arguments):
                result = self.run_refresh(*arguments, grafana=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assert_refreshed()
        self.assertEqual(len(self.recorded("provision-grafana-access.py")), 2)
        self.assertEqual(json.loads(self.memberships.read_text()), {"converged": True})
        self.assertEqual(self.password.read_bytes(), password)

    def test_false_refreshes_data_without_grafana_credentials_or_membership_calls(self):
        self.password.unlink()
        for _ in range(2):
            result = self.run_refresh("--manage-grafana-access", "false")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assert_refreshed()
        self.assertEqual(self.memberships.read_bytes(), self.before_memberships)
        self.assertEqual(self.recorded("provision-grafana-access.py"), [])
        docker = self.recorded("docker")
        self.assertFalse(any("grafana" in call for call in docker))
        self.assertEqual(sum("validate" in call for call in docker), 1)
        self.assertEqual(sum("--force-recreate" in call for call in docker), 1)

    def test_false_does_not_mask_source_failure_or_replace_previous_data(self):
        result = self.run_refresh("--manage-grafana-access", "false")
        self.assertEqual(result.returncode, 0, result.stderr)
        before = {path: path.read_bytes() for folder in (self.lookups, self.dashboards)
                  for path in folder.iterdir() if path.is_file()}
        calls = self.recorded("docker")
        self.env["OBS_REFRESH_TEST_DB_FAILURE"] = "1"
        result = self.run_refresh("--manage-grafana-access", "false")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual({path: path.read_bytes() for path in before}, before)
        self.assertEqual(self.recorded("docker"), calls)
        self.assertEqual(self.recorded("provision-grafana-access.py"), [])
        self.assertEqual(self.memberships.read_bytes(), self.before_memberships)

    def test_invalid_or_missing_setting_stops_before_refresh(self):
        for arguments in (("yes",), ("0",), ("",), ()):
            with self.subTest(arguments=arguments):
                result = self.run_refresh("--manage-grafana-access", *arguments)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("--manage-grafana-access", result.stderr)
                self.assertFalse(self.calls.exists())
                self.assertFalse(self.lookups.exists())
                self.assertEqual(self.memberships.read_bytes(), self.before_memberships)

    def test_default_still_requires_grafana_credentials_before_refresh(self):
        result = self.run_refresh()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--grafana-admin-password-file", result.stderr)
        self.assertFalse(self.calls.exists())
        self.assertFalse(self.lookups.exists())


if __name__ == "__main__":
    unittest.main()
