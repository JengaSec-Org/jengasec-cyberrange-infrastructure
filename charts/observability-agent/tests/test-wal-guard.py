#!/usr/bin/env python3
"""Exercise disk limits and recovery without stopping a real collector."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[3] / "scripts/guard-observability-wal.py"
SPEC = importlib.util.spec_from_file_location("wal_guard", SOURCE)
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.storage = root / "storage"
        self.wal = self.storage / ("pvc_test_" + guard.NAMESPACE + "_" + guard.CLAIM) / "wal"
        self.host = root / "host" / "wal"
        self.state = root / "state"
        self.metrics = root / "metrics.prom"
        for path in (self.wal, self.host, self.state):
            path.mkdir(parents=True)
        self.constants = patch.multiple(guard, STORAGE_ROOT=self.storage, HOST_WAL=self.host,
                                        STATE_ROOT=self.state, METRICS_FILE=self.metrics)
        self.constants.start()
        self.addCleanup(self.constants.stop)
        self.config = {"cluster": "red", "host_enabled": True, "max_wal_bytes": 8192, "min_free_bytes": 16384}
        self.commands = []
        self.active = True
        self.fail_stop = False
        self.fail_start = False
        self.fixture = {
            "namespace": {"metadata": {"labels": {"app.kubernetes.io/component": "observability"}}},
            "deployment": {"spec": {"template": {"spec": {
                "serviceAccountName": "observability-agent",
                "volumes": [{"persistentVolumeClaim": {"claimName": guard.CLAIM}}]}}}},
            "pvc": {"metadata": {"uid": "claim-uid"}, "status": {"phase": "Bound"},
                    "spec": {"volumeName": "pv-test"}},
            "pv": {"metadata": {"uid": "pv-uid"}, "spec": {"hostPath": {"path": str(self.wal.parent)},
                   "claimRef": {"namespace": guard.NAMESPACE, "name": guard.CLAIM, "uid": "claim-uid"}}},
        }

    def command(self, args):
        self.commands.append(args)
        if "get" in args:
            return json.dumps(self.fixture[args[args.index("get") + 1]])
        if args[0] == "systemctl":
            self.assertEqual(args[2], guard.HOST_UNIT)
            if args[1] == "show":
                if "--property=FragmentPath" in args:
                    return "/etc/systemd/system/" + guard.HOST_UNIT
                return "active" if self.active else "inactive"
            if args[1] == "stop":
                if self.fail_stop:
                    raise guard.GuardError("fixture stop failure")
                self.active = False
            if args[1] == "start":
                if self.fail_start:
                    raise guard.GuardError("fixture start failure")
                # ExecCondition must see a cleared latch during explicit resume.
                self.assertTrue(guard.Guard(self.config).can_start("host"))
                self.active = True
            return ""
        if "scale" in args or "wait" in args:
            self.assertEqual(args[args.index("--namespace") + 1], guard.NAMESPACE)
            if "scale" in args:
                self.assertIn("deployment/" + guard.DEPLOYMENT, args)
                if "--replicas=0" in args and self.fail_stop:
                    raise guard.GuardError("fixture stop failure")
                if "--replicas=1" in args and self.fail_start:
                    raise guard.GuardError("fixture start failure")
                if "--replicas=0" in args:
                    state = json.loads((self.state / "state.json").read_text())
                    self.assertTrue(state["targets"]["cluster"]["paused"])
            return ""
        self.fail("Unexpected command")

    def make(self):
        return guard.Guard(self.config, command=self.command, clock=lambda: 1000.25)

    def mutations(self):
        return [c for c in self.commands if "scale" in c or (c[0] == "systemctl" and c[1] in ("start", "stop"))]

    def test_healthy_check_measures_both_wals_without_mutation(self):
        with patch.object(guard, "measure", return_value=(4096, 32768)):
            self.assertTrue(self.make().check())
        self.assertFalse(self.mutations())
        output = self.metrics.read_text()
        self.assertIn('paused{cluster="red",component="cluster-collector"} 0', output)
        self.assertIn('bytes{cluster="red",component="container-log-reader"} 4096', output)
        self.assertNotIn("resource_id", output)
        self.assertNotIn("environment", output)
        self.assertEqual(self.metrics.stat().st_mode & 0o777, 0o644)

    def test_exact_limit_latches_before_stop_and_survives_new_process(self):
        with patch.object(guard, "measure", return_value=(8192, 32768)):
            self.assertTrue(self.make().check())
        self.assertFalse(self.make().can_start("cluster"))
        self.assertFalse(self.make().can_start("host"))
        self.assertEqual((self.state / "state.json").stat().st_mode & 0o777, 0o600)
        with patch.object(guard, "measure", return_value=(4096, 32768)):
            self.assertTrue(self.make().check())
        self.assertFalse(any("--replicas=1" in c or c[:2] == ["systemctl", "start"] for c in self.commands))
        self.assertFalse(self.make().can_start("host"))

    def test_disk_floor_latches_even_with_small_wal(self):
        with patch.object(guard, "measure", return_value=(1, 16383)):
            self.assertTrue(self.make().check())
        self.assertEqual(self.make().state["targets"]["host"]["reason"], "disk_floor")

    def test_equal_disk_floor_does_not_pause(self):
        with patch.object(guard, "measure", return_value=(1, 16384)):
            self.assertTrue(self.make().check())
        self.assertFalse(self.mutations())

    def test_explicit_resume_checks_capacity_and_only_clears_requested_latch(self):
        with patch.object(guard, "measure", return_value=(8192, 32768)):
            self.make().check()
            with self.assertRaises(guard.GuardError):
                self.make().resume("host")
        with patch.object(guard, "measure", return_value=(4096, 16383)):
            with self.assertRaises(guard.GuardError):
                self.make().resume("host")
        with patch.object(guard, "measure", return_value=(4096, 32768)):
            self.assertTrue(self.make().resume("host"))
        self.assertTrue(self.make().can_start("host"))
        self.assertFalse(self.make().can_start("cluster"))
        self.assertTrue(self.active)

    def test_resume_without_recorded_pause_is_rejected(self):
        with self.assertRaises(guard.GuardError):
            self.make().resume("cluster")
        self.assertFalse(self.mutations())

    def test_disabling_host_collection_cannot_bypass_existing_pause(self):
        with patch.object(guard, "measure", return_value=(8192, 32768)):
            self.make().check()
        self.config["host_enabled"] = False
        self.assertFalse(self.make().can_start("host"))
        self.assertFalse(self.make().can_start("cluster"))
        with self.assertRaises(guard.GuardError):
            self.make().resume("host")

    def test_replacement_volume_cannot_clear_a_pause(self):
        with patch.object(guard, "measure", return_value=(8192, 32768)):
            self.make().check()
        self.fixture["pv"]["metadata"]["uid"] = "replacement-volume"
        self.commands.clear()
        with patch.object(guard, "measure", return_value=(4096, 32768)):
            with self.assertRaises(guard.GuardError):
                self.make().resume("cluster")
        self.assertFalse(self.mutations())
        self.assertFalse(self.make().can_start("cluster"))

    def test_failed_stop_is_reported_and_latch_is_retained(self):
        self.fail_stop = True
        with patch.object(guard, "measure", return_value=(8192, 32768)):
            self.assertFalse(self.make().check())
        self.assertFalse(self.make().can_start("host"))
        output = self.metrics.read_text()
        self.assertIn('stop_success{cluster="red",component="container-log-reader"} 0', output)
        self.assertIn('check_success{cluster="red",component="cluster-collector"} 0', output)

    def test_failed_resume_restores_latch(self):
        with patch.object(guard, "measure", return_value=(8192, 32768)):
            self.make().check()
        self.fail_start = True
        with patch.object(guard, "measure", return_value=(4096, 32768)):
            with self.assertRaises(guard.GuardError):
                self.make().resume("host")
        self.assertFalse(self.make().can_start("host"))
        self.assertFalse(self.active)

    def test_wrong_claim_namespace_and_storage_paths_cannot_stop_anything(self):
        self.config["host_enabled"] = False
        cases = [("claimRef", {"namespace": "app01", "name": guard.CLAIM, "uid": "claim-uid"}),
                 ("hostPath", {"path": "/var/lib"}),
                 ("hostPath", {"path": str(self.storage / "unrelated")})]
        original = json.loads(json.dumps(self.fixture["pv"]["spec"]))
        for key, value in cases:
            with self.subTest(key=key, value=value):
                self.fixture["pv"]["spec"] = original | {key: value}
                with patch.object(guard, "measure", return_value=(99999, 1)):
                    self.assertFalse(self.make().check())
                self.assertFalse(self.mutations())

    def test_non_obs_namespace_cannot_be_scaled(self):
        self.config["host_enabled"] = False
        self.fixture["namespace"]["metadata"]["labels"]["app.kubernetes.io/component"] = "application"
        with patch.object(guard, "measure", return_value=(99999, 1)):
            self.assertFalse(self.make().check())
        self.assertFalse(self.mutations())

    def test_measure_counts_allocation_and_rejects_symlinks(self):
        sample = self.host / "segment"
        sample.write_bytes(b"x")
        info = sample.stat()
        used, available = guard.measure(self.host)
        self.assertEqual(used, max(info.st_size, info.st_blocks * 512))
        self.assertGreater(available, 0)
        (self.host / "outside").symlink_to(self.state, target_is_directory=True)
        with self.assertRaises(guard.GuardError):
            guard.measure(self.host)

    def test_symlinked_wal_and_corrupt_state_fail_closed(self):
        self.config["host_enabled"] = False
        self.wal.rmdir()
        self.wal.symlink_to(self.host, target_is_directory=True)
        self.assertFalse(self.make().check())
        self.assertFalse(self.mutations())
        (self.state / "state.json").write_text('{"schema_version":1,"targets":{"host":{"paused":"false"}}}')
        with self.assertRaises(guard.GuardError):
            self.make()

    def test_configuration_cannot_choose_arbitrary_stop_targets(self):
        for invalid in (self.config | {"unit": "k3s.service"}, self.config | {"max_wal_bytes": True},
                        self.config | {"min_free_bytes": 0}, self.config | {"cluster": "anything"}):
            with self.assertRaises(guard.GuardError):
                guard.validate(invalid)


if __name__ == "__main__":
    unittest.main()
