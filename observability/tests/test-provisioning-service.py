#!/usr/bin/env python3
"""Check bounded, fresh source exchange and failure/recovery health metrics."""

import copy
from datetime import timedelta
import errno
import fcntl
import importlib.util
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
from unittest.mock import Mock


ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SERVICE = load("provisioning_service", ROOT / "scripts/provisioning-observability-service.py")
FIXTURES = load("snapshot_fixtures", ROOT / "observability/tests/test-provisioning-snapshot.py")
ADAPTER = SERVICE.ADAPTER
NOW = FIXTURES.NOW


class ProvisioningServiceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.cache = self.root / "cache"
        ADAPTER.refresh(self.source, lambda: FIXTURES.source(True), now=NOW)

    def envelope(self):
        return SERVICE.source_envelope(self.source, now=NOW)

    def rehash(self, envelope):
        envelope["status"]["snapshot_hash"] = ADAPTER.snapshot_hash(ADAPTER.encode(envelope["snapshot"]))

    def test_exchange_preserves_native_bigint_ids_and_original_expiry(self):
        source = self.envelope()
        result = SERVICE.pull_snapshot(self.cache, lambda: source, now=NOW + timedelta(seconds=30))
        self.assertEqual(source["snapshot"], result)
        self.assertEqual(source["status"], json.loads((self.cache / "provisioning-status.json").read_text()))
        self.assertEqual(result["records"]["participants"][0]["participant_id"], "9007199254740993")
        self.assertEqual(ADAPTER.read_current(self.cache, now=NOW + timedelta(seconds=120))[1], "expired")
        self.assertTrue(all(path.stat().st_mode & 0o777 == 0o600 for path in self.cache.iterdir()))

    def test_native_attribution_is_cleared_before_fetch_and_published_after_commit(self):
        SERVICE.pull_snapshot(self.cache, self.envelope, now=NOW)
        published = []
        def publish(update):
            published.append(update)
            if update["state"] == "fresh":
                self.assertEqual(ADAPTER.read_current(self.cache, now=NOW)[1], "fresh")
        def fetch():
            self.assertEqual(published[-1]["state"], "unavailable")
            self.assertEqual(published[-1]["allocations"], [])
            self.assertEqual(ADAPTER.read_current(self.cache, now=NOW)[1], "unavailable")
            return self.envelope()
        result = SERVICE.pull_snapshot(self.cache, fetch, now=NOW, publish=publish)
        update = published[-1]
        self.assertEqual(update["authorization"], "none")
        self.assertEqual(update["mapping_state"], "native_only")
        self.assertEqual(update["snapshot_hash"], ADAPTER.snapshot_hash(ADAPTER.encode(result)))
        self.assertEqual(update["captured_at"], result["captured_at"])
        self.assertEqual(update["expires_at"], result["expires_at"])
        self.assertEqual(update["allocations"], [{"ip_address": "192.0.2.10", "participant_id": "9007199254740993", "team_id": "2", "role": "red_participant"}])
        self.assertEqual(update, json.loads((self.cache / "infrastructure-attribution.json").read_text()))

    def test_invalidation_failure_never_starts_a_pull(self):
        SERVICE.pull_snapshot(self.cache, self.envelope, now=NOW)
        fetch = Mock(side_effect=self.envelope)
        with self.assertRaises(OSError):
            SERVICE.pull_snapshot(self.cache, fetch, now=NOW, publish=Mock(side_effect=OSError("unavailable")))
        fetch.assert_not_called()
        self.assertEqual(ADAPTER.read_current(self.cache, now=NOW)[1], "unavailable")
        self.assertEqual(json.loads((self.cache / "infrastructure-attribution.json").read_text())["allocations"], [])

    def test_failed_fetch_leaves_only_an_unusable_attribution_state(self):
        updates = []
        SERVICE.pull_snapshot(self.cache, self.envelope, now=NOW, publish=updates.append)
        with self.assertRaises(ADAPTER.SnapshotError):
            SERVICE.pull_snapshot(self.cache, lambda: {}, now=NOW, publish=updates.append)
        self.assertEqual([item["state"] for item in updates[-2:]], ["unavailable", "stale"])
        for item in updates[-2:]:
            self.assertEqual(item["allocations"], [])
            self.assertNotIn("participant_id", json.dumps(item))
        self.assertEqual(ADAPTER.read_current(self.cache, now=NOW)[1], "stale")

    def test_attribution_contains_only_active_native_allocations(self):
        snapshot = self.envelope()["snapshot"]
        for state in ("inactive", "revoked", "expired", "unknown"):
            with self.subTest(state=state):
                snapshot["records"]["allocations"][0]["effective_state"] = state
                self.assertEqual(SERVICE.attribution_update(snapshot)["allocations"], [])

    def test_hash_and_native_contract_both_reject_invalid_data(self):
        def extra_field(e):
            e["snapshot"]["records"]["participants"][0]["email"] = "DO_NOT_EXPORT"
        def fabricated_mapping(e):
            e["snapshot"]["mapping_state"] = "canonical"
        def fabricated_authorization(e):
            e["snapshot"]["authorization"] = "allow"
        def wrong_state(e):
            e["snapshot"]["records"]["allocations"][0]["effective_state"] = "revoked"
        def wrong_count(e):
            e["snapshot"]["counts"]["participants"] = 0
        def boolean_count(e):
            e["snapshot"]["counts"]["participants"] = True
        def fractional_count(e):
            e["snapshot"]["counts"]["participants"] = 1.0
        for change in (extra_field, fabricated_mapping, fabricated_authorization, wrong_state,
                       wrong_count, boolean_count, fractional_count):
            envelope = self.envelope()
            change(envelope)
            self.rehash(envelope)
            with self.subTest(change=change), self.assertRaises(ADAPTER.SnapshotError):
                SERVICE.validate_envelope(envelope, now=NOW)
        envelope = self.envelope()
        envelope["status"]["snapshot_hash"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(ADAPTER.SnapshotError, "invalid_publication"):
            SERVICE.validate_envelope(envelope, now=NOW)

    def test_expired_future_and_extended_lifetimes_are_rejected(self):
        envelope = self.envelope()
        for now in (NOW - timedelta(seconds=1), NOW + timedelta(seconds=120)):
            with self.subTest(now=now), self.assertRaises(ADAPTER.SnapshotError):
                SERVICE.validate_envelope(envelope, now=now)
        extended = copy.deepcopy(envelope)
        extended["snapshot"]["expires_at"] = ADAPTER.iso(NOW + timedelta(seconds=3600))
        extended["status"]["expires_at"] = extended["snapshot"]["expires_at"]
        self.rehash(extended)
        with self.assertRaises(ADAPTER.SnapshotError):
            SERVICE.validate_envelope(extended, now=NOW)

    def test_failed_pull_invalidates_old_rows_then_empty_recovery_replaces_them(self):
        SERVICE.pull_snapshot(self.cache, self.envelope, now=NOW)
        before = (self.cache / "provisioning-snapshot.json").read_bytes()
        def failure():
            raise OSError("DO_NOT_EXPORT")
        with self.assertRaises(ADAPTER.SnapshotError):
            SERVICE.pull_snapshot(self.cache, failure, now=NOW + timedelta(seconds=1))
        self.assertEqual((self.cache / "provisioning-snapshot.json").read_bytes(), before)
        self.assertNotIn("DO_NOT_EXPORT", (self.cache / "provisioning-status.json").read_text())
        self.assertEqual(ADAPTER.resolve_address(self.cache, "192.0.2.10", now=NOW)["state"], "stale")
        ADAPTER.refresh(self.source, FIXTURES.source, now=NOW)
        SERVICE.pull_snapshot(self.cache, self.envelope, now=NOW)
        self.assertEqual(ADAPTER.resolve_address(self.cache, "192.0.2.10", now=NOW)["state"], "unknown")
        self.assertEqual(ADAPTER.read_current(self.cache, now=NOW)[0]["counts"]["participants"], 0)

    def test_first_failure_and_interrupted_cache_publication_fail_closed(self):
        with self.assertRaises(ADAPTER.SnapshotError):
            SERVICE.pull_snapshot(self.cache, lambda: {}, now=NOW)
        self.assertFalse((self.cache / "provisioning-snapshot.json").exists())
        SERVICE.pull_snapshot(self.cache, self.envelope, now=NOW)
        with patch.object(ADAPTER, "atomic_write", side_effect=OSError("full")):
            with self.assertRaises(OSError):
                SERVICE.pull_snapshot(self.cache, self.envelope, now=NOW)
        self.assertEqual(ADAPTER.read_current(self.cache, now=NOW)[1], "unavailable")

    def test_fetch_and_status_write_failure_cannot_retain_usable_attribution(self):
        SERVICE.pull_snapshot(self.cache, self.envelope, now=NOW)
        before = (self.cache / "provisioning-snapshot.json").read_bytes()
        updates = []
        atomic_write = ADAPTER.atomic_write
        def write(path, payload, **kwargs):
            if path.name == "provisioning-status.json":
                raise OSError(errno.ENOSPC, "full")
            return atomic_write(path, payload, **kwargs)
        def fetch():
            raise OSError("source unavailable")
        failed_at = NOW + timedelta(seconds=30)
        with patch.object(ADAPTER, "atomic_write", side_effect=write):
            with self.assertRaises(OSError) as failure:
                SERVICE.pull_snapshot(self.cache, fetch, now=failed_at, publish=updates.append)
        self.assertEqual(failure.exception.errno, errno.ENOSPC)
        self.assertEqual((self.cache / "provisioning-snapshot.json").read_bytes(), before)
        self.assertFalse((self.cache / "provisioning-status.json").exists())
        self.assertEqual(ADAPTER.read_current(self.cache, now=failed_at), (None, "unavailable"))
        resolved = ADAPTER.resolve_address(self.cache, "192.0.2.10", now=failed_at)
        self.assertEqual(resolved["state"], "unavailable")
        self.assertNotIn("participant_id", resolved)
        self.assertEqual(resolved["authorization"], "none")
        local = json.loads((self.cache / "infrastructure-attribution.json").read_text())
        self.assertEqual(updates, [local])
        self.assertEqual(local["state"], "unavailable")
        self.assertEqual(local["allocations"], [])
        self.assertEqual(local["authorization"], "none")
        recovered_at = NOW + timedelta(seconds=32)
        empty = FIXTURES.source()
        empty["captured_at"] = ADAPTER.iso(recovered_at)
        ADAPTER.refresh(self.source, lambda: empty, now=recovered_at)
        SERVICE.pull_snapshot(self.cache, lambda: SERVICE.source_envelope(self.source, now=recovered_at),
                              now=recovered_at, publish=updates.append)
        snapshot, state = ADAPTER.read_current(self.cache, now=recovered_at)
        self.assertEqual(state, "fresh")
        self.assertTrue(all(count == 0 for count in snapshot["counts"].values()))
        self.assertEqual(updates[-1]["state"], "fresh")
        self.assertEqual(updates[-1]["allocations"], [])
        self.assertEqual(ADAPTER.resolve_address(self.cache, "192.0.2.10", now=recovered_at)["state"], "unknown")

    def test_overlapping_cache_writers_preserve_previous_commit_marker(self):
        SERVICE.pull_snapshot(self.cache, self.envelope, now=NOW)
        before = (self.cache / "provisioning-status.json").read_bytes()
        with (self.cache / "refresh.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(ADAPTER.SnapshotError, "refresh_already_running"):
                SERVICE.pull_snapshot(self.cache, self.envelope, now=NOW)
        self.assertEqual((self.cache / "provisioning-status.json").read_bytes(), before)

    def test_source_concurrent_publication_cannot_export_mismatched_bytes(self):
        snapshot, _ = ADAPTER.read_current(self.source, now=NOW)
        ADAPTER.refresh(self.source, FIXTURES.source, now=NOW)
        with patch.object(ADAPTER, "read_current", return_value=(snapshot, "fresh")):
            with self.assertRaisesRegex(ADAPTER.SnapshotError, "invalid_publication"):
                SERVICE.source_envelope(self.source, now=NOW)

    def test_metrics_distinguish_fresh_empty_failure_expiry_and_recovery_without_ids(self):
        metrics = self.root / "provisioning.prom"
        def collect(success, now=NOW):
            SERVICE.write_metrics(self.source, metrics, "source", success, time.monotonic(), now=now)
            text = metrics.read_text()
            self.assertEqual(metrics.stat().st_mode & 0o777, 0o644)
            for value in ("9007199254740993", "192.0.2.10", "participant_id", "team_id", "DO_NOT_EXPORT"):
                self.assertNotIn(value, text)
            return text
        healthy = collect(True)
        self.assertIn('snapshot_usable{mode="source"} 1.000000', healthy)
        self.assertIn('snapshot_rows{mode="source",table="participants"} 1', healthy)
        expired = collect(True, NOW + timedelta(seconds=120))
        self.assertIn('snapshot_usable{mode="source"} 0.000000', expired)
        with self.assertRaises(ADAPTER.SnapshotError):
            ADAPTER.refresh(self.source, lambda: {}, now=NOW)
        failed = collect(False)
        self.assertIn('refresh_success{mode="source"} 0.000000', failed)
        self.assertIn('snapshot_usable{mode="source"} 0.000000', failed)
        self.assertIn('snapshot_rows{mode="source",table="participants"} 0', failed)
        ADAPTER.refresh(self.source, FIXTURES.source, now=NOW)
        recovered = collect(True)
        self.assertIn('refresh_success{mode="source"} 1.000000', recovered)
        self.assertIn('snapshot_usable{mode="source"} 1.000000', recovered)
        self.assertIn('snapshot_rows{mode="source",table="participants"} 0', recovered)

    def test_http_client_rejects_redirects_and_unbounded_responses(self):
        config = {"source_address": "source.example", "port": 9444}
        for status, size in ((302, "10"), (200, str(SERVICE.MAX_ENVELOPE + 1)), (200, None)):
            with self.subTest(status=status, size=size), patch.object(SERVICE, "client_context"), \
                    patch.object(SERVICE.http.client, "HTTPSConnection") as connection:
                response = connection.return_value.getresponse.return_value
                response.status = status
                response.getheader.side_effect = lambda header: "application/json" if header == "Content-Type" else size
                with self.assertRaises(ADAPTER.SnapshotError):
                    SERVICE.fetch_https(config)
                response.read.assert_not_called()
                connection.return_value.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
