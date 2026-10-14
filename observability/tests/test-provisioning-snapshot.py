#!/usr/bin/env python3
"""Test native provisioning snapshots, freshness and the read-only boundary."""

import copy
from datetime import datetime, timedelta, timezone
import errno
import fcntl
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import jsonschema


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("provisioning_snapshot", ROOT / "scripts/refresh-provisioning-observability.py")
ADAPTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ADAPTER)
NOW = datetime(2026, 10, 1, 12, tzinfo=timezone.utc)


def source(populated=False):
    earlier = ADAPTER.iso(NOW - timedelta(hours=1))
    result = {"captured_at": ADAPTER.iso(NOW), "read_only": True, "tls": False, "database": "jengasec",
              **{name: [] for name in ADAPTER.TABLES}}
    if populated:
        result["participants"] = [{"participant_id": "9007199254740993", "team_id": "2", "role": "red_participant",
                                   "eligible": True, "status": "active", "created_at": earlier, "updated_at": earlier}]
        result["teams"] = [{"team_id": "2", "category": "ai", "side": "red", "created_at": earlier}]
        result["allocations"] = [{"allocation_id": "3", "participant_id": "9007199254740993", "vpn_address": "192.0.2.10",
                                  "interface_name": "wg0", "status": "active", "allocated_at": earlier, "last_changed_at": earlier}]
        result["targets"] = [{"target_id": "4", "owner_team_id": None, "category": "ai", "namespace": None,
                              "endpoint_ip": "192.0.2.30", "protocol": "tcp", "ports": [443], "enabled": True}]
        result["assignments"] = [{"assignment_id": "5", "red_team_id": "2", "target_id": "4", "starts_at": earlier,
                                  "ends_at": ADAPTER.iso(NOW + timedelta(hours=1))}]
        result["event_windows"] = [{"event_id": "6", "starts_at": earlier, "ends_at": ADAPTER.iso(NOW + timedelta(hours=2))}]
    return result


class ProvisioningTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.output = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        self.validator = jsonschema.Draft202012Validator(
            json.loads((ROOT / "observability/provisioning/snapshot.schema.json").read_text()),
            format_checker=jsonschema.FormatChecker())
        self.status_validator = jsonschema.Draft202012Validator(
            json.loads((ROOT / "observability/provisioning/status.schema.json").read_text()),
            format_checker=jsonschema.FormatChecker())

    def refresh(self, payload=None, now=NOW):
        snapshot = ADAPTER.refresh(self.output, lambda: payload if payload is not None else source(), now=now)
        self.validator.validate(snapshot)
        self.status_validator.validate(json.loads((self.output / "provisioning-status.json").read_text()))
        return snapshot

    def assert_empty_recovery(self):
        now = NOW + timedelta(seconds=32)
        payload = source()
        payload["captured_at"] = ADAPTER.iso(now)
        self.refresh(payload, now=now)
        snapshot, state = ADAPTER.read_current(self.output, now=now)
        self.assertEqual(state, "fresh")
        self.assertEqual(snapshot["counts"], dict.fromkeys(ADAPTER.TABLES, 0))
        self.assertTrue(all(not rows for rows in snapshot["records"].values()))
        result = ADAPTER.resolve_address(self.output, "192.0.2.10", now=now)
        self.assertEqual(result["state"], "unknown")
        self.assertNotIn("participant_id", result)
        self.assertEqual(result["authorization"], "none")

    def test_empty_database_is_valid_and_replaces_prior_rows(self):
        self.refresh(source(True))
        self.assertEqual(ADAPTER.resolve_address(self.output, "192.0.2.10", now=NOW)["state"], "known")
        self.refresh(source())
        snapshot, state = ADAPTER.read_current(self.output, now=NOW)
        self.assertEqual(state, "fresh")
        self.assertTrue(all(value == 0 for value in snapshot["counts"].values()))
        self.assertEqual(ADAPTER.resolve_address(self.output, "192.0.2.10", now=NOW)["state"], "unknown")

    def test_native_ids_are_exact_strings_without_competition_or_access_mapping(self):
        snapshot = self.refresh(source(True))
        result = ADAPTER.resolve_address(self.output, "192.0.2.10", now=NOW)
        self.assertEqual(result["participant_id"], "9007199254740993")
        self.assertEqual(result["identity_source"], "jengasec_provisioning")
        self.assertEqual(result["authorization"], "none")
        self.assertEqual(result["mapping_state"], "native_only")
        self.assertNotIn("JS26-", json.dumps(snapshot))
        self.assertNotIn("access_principals", snapshot)
        self.assertNotIn("verdict", result)
        self.assertNotIn("team_label", result)
        for file in self.output.iterdir():
            self.assertEqual(file.stat().st_mode & 0o777, 0o600)

    def test_revoked_expired_reserved_and_ineligible_never_resolve_as_active(self):
        for field, value, expected in (("participant_status", "revoked", "revoked"),
                                      ("allocation_status", "expired", "expired"),
                                      ("allocation_status", "reserved", "inactive"),
                                      ("eligible", False, "inactive"),
                                      ("participant_role", "unknown", "unknown")):
            payload = source(True)
            if field == "participant_status":
                payload["participants"][0]["status"] = value
            elif field == "allocation_status":
                payload["allocations"][0]["status"] = value
            elif field == "eligible":
                payload["participants"][0]["eligible"] = value
            else:
                payload["participants"][0]["role"] = value
            with self.subTest(field=field):
                snapshot = self.refresh(payload)
                self.assertEqual(snapshot["records"]["allocations"][0]["effective_state"], expected)
                self.assertEqual(ADAPTER.resolve_address(self.output, "192.0.2.10", now=NOW)["state"], "unknown")

    def test_unknown_address_and_assignment_bounds_remain_unknown(self):
        payload = source(True)
        payload["allocations"][0]["vpn_address"] = None
        payload["assignments"][0]["starts_at"] = None
        payload["assignments"][0]["ends_at"] = None
        payload["targets"][0]["endpoint_ip"] = None
        snapshot = self.refresh(payload)
        self.assertEqual(snapshot["records"]["allocations"][0]["effective_state"], "unknown")
        self.assertEqual(snapshot["records"]["assignments"][0]["window_state"], "unknown")
        self.assertIsNone(snapshot["records"]["targets"][0]["endpoint_ip"])

    def test_supported_ip_literals_remain_schema_valid_and_resolvable(self):
        for value, normalized in (("192.0.2.10", "192.0.2.10"),
                                  ("2001:0DB8::0010", "2001:db8::10"),
                                  ("::ffff:192.0.2.10", "::ffff:c000:20a")):
            with self.subTest(value=value):
                payload = source(True)
                payload["allocations"][0]["vpn_address"] = value
                payload["targets"][0]["endpoint_ip"] = value
                snapshot = self.refresh(payload)
                self.assertEqual(snapshot["records"]["allocations"][0]["vpn_address"], normalized)
                self.assertEqual(snapshot["records"]["targets"][0]["endpoint_ip"], normalized)
                result = ADAPTER.resolve_address(self.output, value, now=NOW)
                self.assertEqual(result["state"], "known")
                self.assertEqual(result["authorization"], "none")

    def test_scoped_allocation_addresses_invalidate_prior_attribution(self):
        for value in ("fe80::1%wg0", "fe80::1%2", "fe80::1%DO_NOT_EXPORT"):
            with self.subTest(value=value):
                self.refresh(source(True))
                before = (self.output / "provisioning-snapshot.json").read_bytes()
                payload = source(True)
                payload["allocations"][0]["vpn_address"] = value
                with self.assertRaisesRegex(ADAPTER.SnapshotError, "^invalid_source$"):
                    self.refresh(payload, now=NOW + timedelta(seconds=30))
                self.assertEqual((self.output / "provisioning-snapshot.json").read_bytes(), before)
                status = json.loads((self.output / "provisioning-status.json").read_text())
                self.status_validator.validate(status)
                self.assertFalse(status["usable"])
                self.assertNotIn(value, json.dumps(status))
                result = ADAPTER.resolve_address(self.output, "192.0.2.10", now=NOW + timedelta(seconds=31))
                self.assertEqual(result["state"], "stale")
                self.assertNotIn("participant_id", result)
                self.assert_empty_recovery()

    def test_scoped_target_addresses_remain_unknown_without_scope_data(self):
        for value in ("fe80::1%wg0", "fe80::1%2", "fe80::1%DO_NOT_EXPORT"):
            with self.subTest(value=value):
                payload = source(True)
                payload["targets"][0]["endpoint_ip"] = value
                snapshot = self.refresh(payload)
                self.assertIsNone(snapshot["records"]["targets"][0]["endpoint_ip"])
                self.assertNotIn(value, json.dumps(snapshot))
                self.assertEqual(snapshot["authorization"], "none")

    def test_assignment_expiry_and_disabled_targets_do_not_imply_permission(self):
        payload = source(True)
        payload["assignments"][0]["ends_at"] = ADAPTER.iso(NOW)
        snapshot = self.refresh(payload)
        self.assertEqual(snapshot["records"]["assignments"][0]["window_state"], "expired")
        payload["targets"][0]["enabled"] = False
        snapshot = self.refresh(payload)
        self.assertEqual(snapshot["records"]["assignments"][0]["window_state"], "disabled")
        self.assertEqual(snapshot["authorization"], "none")

    def test_expiry_and_clock_reversal_fail_closed_without_rewriting_snapshot(self):
        self.refresh(source(True))
        before = (self.output / "provisioning-snapshot.json").read_bytes()
        for now in (NOW + timedelta(seconds=120), NOW - timedelta(seconds=1)):
            result = ADAPTER.resolve_address(self.output, "192.0.2.10", now=now)
            self.assertEqual(result["state"], "expired")
            self.assertNotIn("participant_id", result)
        self.assertEqual((self.output / "provisioning-snapshot.json").read_bytes(), before)

    def test_failed_refresh_preserves_bytes_but_immediately_blocks_old_attribution(self):
        self.refresh(source(True))
        before = (self.output / "provisioning-snapshot.json").read_bytes()
        def failure():
            raise ValueError("sensitive connection detail must not escape")
        with self.assertRaises(ADAPTER.SnapshotError):
            ADAPTER.refresh(self.output, failure, now=NOW + timedelta(seconds=30))
        self.assertEqual((self.output / "provisioning-snapshot.json").read_bytes(), before)
        status = json.loads((self.output / "provisioning-status.json").read_text())
        self.status_validator.validate(status)
        self.assertFalse(status["usable"])
        self.assertEqual(status["state"], "refresh_failed")
        self.assertNotIn("sensitive", json.dumps(status))
        result = ADAPTER.resolve_address(self.output, "192.0.2.10", now=NOW + timedelta(seconds=31))
        self.assertEqual(result["state"], "stale")
        self.assertNotIn("participant_id", result)
        self.refresh(source())
        self.assertEqual(ADAPTER.read_current(self.output, now=NOW)[1], "fresh")

    def test_failed_status_write_cannot_keep_prior_attribution_fresh(self):
        def query_failure():
            raise ADAPTER.SnapshotError("database_query_failed")

        for label, fetch in (("query", query_failure), ("validation", lambda: {})):
            with self.subTest(failure=label):
                self.refresh(source(True))
                before = (self.output / "provisioning-snapshot.json").read_bytes()
                with patch.object(ADAPTER, "atomic_write", side_effect=OSError(errno.ENOSPC, "disk full")):
                    with self.assertRaises(OSError):
                        ADAPTER.refresh(self.output, fetch, now=NOW + timedelta(seconds=30))
                self.assertEqual((self.output / "provisioning-snapshot.json").read_bytes(), before)
                self.assertFalse((self.output / "provisioning-status.json").exists())
                result = ADAPTER.resolve_address(self.output, "192.0.2.10", now=NOW + timedelta(seconds=31))
                self.assertEqual(result["state"], "unavailable")
                self.assertNotIn("participant_id", result)
                self.assertEqual(result["authorization"], "none")
                self.assert_empty_recovery()

    def test_timestamp_overflow_invalidates_prior_attribution(self):
        for field, value, reason in (("created_at", "0001-01-01T00:00:00+01:00", "invalid_source"),
                                     ("updated_at", "9999-12-31T23:59:59-01:00", "invalid_source"),
                                     ("captured_at", "9999-12-31T23:59:59Z", "source_clock_or_age")):
            with self.subTest(field=field):
                self.refresh(source(True))
                before = (self.output / "provisioning-snapshot.json").read_bytes()
                payload = source(True)
                if field == "captured_at":
                    payload[field] = value
                else:
                    payload["participants"][0][field] = value
                with self.assertRaisesRegex(ADAPTER.SnapshotError, "^" + reason + "$"):
                    self.refresh(payload, now=NOW + timedelta(seconds=30))
                self.assertEqual((self.output / "provisioning-snapshot.json").read_bytes(), before)
                status = json.loads((self.output / "provisioning-status.json").read_text())
                self.status_validator.validate(status)
                self.assertEqual(status["state"], "refresh_failed")
                self.assertEqual(status["reason"], reason)
                self.assertFalse(status["usable"])
                self.assertNotIn(value, json.dumps(status))
                result = ADAPTER.resolve_address(self.output, "192.0.2.10", now=NOW + timedelta(seconds=31))
                self.assertEqual(result["state"], "stale")
                self.assertNotIn("participant_id", result)
                self.assert_empty_recovery()

    def test_first_failure_publishes_unavailable_status_without_an_empty_success(self):
        with self.assertRaises(ADAPTER.SnapshotError):
            ADAPTER.refresh(self.output, lambda: {}, now=NOW)
        self.assertFalse((self.output / "provisioning-snapshot.json").exists())
        status = json.loads((self.output / "provisioning-status.json").read_text())
        self.status_validator.validate(status)
        self.assertEqual(status["state"], "unavailable")

    def test_interrupted_publication_and_modified_bytes_cannot_be_consumed(self):
        self.refresh(source(True))
        path = self.output / "provisioning-snapshot.json"
        replacement = ADAPTER.build_snapshot(source(), now=NOW)
        ADAPTER.atomic_write(path, ADAPTER.encode(replacement))
        self.assertEqual(ADAPTER.read_current(self.output, now=NOW)[1], "stale")
        self.assertNotIn("participant_id", ADAPTER.resolve_address(self.output, "192.0.2.10", now=NOW))

    def test_publication_failure_keeps_prior_data_unusable(self):
        self.refresh(source(True))
        path = self.output / "provisioning-snapshot.json"
        before = path.read_bytes()
        with patch.object(ADAPTER, "atomic_write", side_effect=OSError("disk unavailable")):
            with self.assertRaises(OSError):
                self.refresh(source())
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(ADAPTER.read_current(self.output, now=NOW)[1], "unavailable")

    def test_an_overlapping_writer_cannot_replace_or_invalidate_a_snapshot(self):
        self.refresh(source(True))
        before = (self.output / "provisioning-status.json").read_bytes()
        with (self.output / "refresh.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(ADAPTER.SnapshotError, "refresh_already_running"):
                self.refresh(source())
        self.assertEqual((self.output / "provisioning-status.json").read_bytes(), before)
        self.assertEqual(ADAPTER.resolve_address(self.output, "192.0.2.10", now=NOW)["state"], "known")

    def test_malformed_sensitive_and_inconsistent_rows_are_rejected(self):
        changes = [
            lambda p: p["participants"][0].update(email="DO_NOT_EXPORT"),
            lambda p: p["participants"][0].update(participant_id=9007199254740993),
            lambda p: p["participants"][0].update(eligible="true"),
            lambda p: p["participants"][0].update(role=[]),
            lambda p: p["participants"][0].update(team_id="999"),
            lambda p: p["allocations"][0].update(vpn_address="192.0.2.0/24"),
            lambda p: p["targets"][0].update(ports=[443, 443]),
            lambda p: p["targets"][0].update(ports=[65536]),
            lambda p: p["assignments"][0].update(ends_at=ADAPTER.iso(NOW - timedelta(days=1))),
            lambda p: p.update(read_only=False),
        ]
        for change in changes:
            payload = source(True)
            change(payload)
            with self.subTest(change=change), self.assertRaises(ADAPTER.SnapshotError):
                self.refresh(payload)
        status = json.loads((self.output / "provisioning-status.json").read_text())
        self.assertFalse(status["usable"])
        self.assertNotIn("DO_NOT_EXPORT", json.dumps(status))

    def test_duplicate_active_addresses_are_rejected(self):
        payload = source(True)
        participant = copy.deepcopy(payload["participants"][0])
        participant["participant_id"] = "7"
        payload["participants"].append(participant)
        allocation = copy.deepcopy(payload["allocations"][0])
        allocation.update(allocation_id="8", participant_id="7")
        payload["allocations"].append(allocation)
        with self.assertRaisesRegex(ADAPTER.SnapshotError, "duplicate_active_address"):
            self.refresh(payload)

    def test_bounded_format_rejects_large_sources_and_unsafe_output_permissions(self):
        payload = source()
        payload["teams"] = [{}] * (ADAPTER.MAX_ROWS + 1)
        with self.assertRaises(ADAPTER.SnapshotError):
            self.refresh(payload)
        with self.assertRaises(ADAPTER.SnapshotError):
            ADAPTER.build_snapshot(source(), now=NOW, max_age=3600)
        self.output.chmod(0o755)
        with self.assertRaisesRegex(ADAPTER.SnapshotError, "private_output_required"):
            self.refresh(source())

    def test_local_sql_drops_to_read_role_and_never_selects_sensitive_fields(self):
        with patch.object(ADAPTER, "bounded_command", return_value=source()) as execute, patch.object(ADAPTER.os, "geteuid", return_value=0):
            ADAPTER.fetch_database(local_peer=True, database="jengasec")
        command, environment, query = execute.call_args.args
        self.assertIn("postgres", command)
        self.assertIn("--host=/var/run/postgresql", command)
        self.assertIn("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY", query)
        self.assertIn("SET LOCAL ROLE pg_read_all_data", query)
        self.assertEqual(environment["PGOPTIONS"], "-c default_transaction_read_only=on")
        self.assertEqual(query.count("LIMIT 10001"), 6)
        for field in ("external_identity", "display_name", "email", "peer_public_key", "audit_events", "event_name", "team_code"):
            self.assertNotIn(field, query)
        self.assertNotRegex(query, r"\b(?:INSERT|UPDATE|DELETE|CREATE|ALTER|GRANT|REVOKE)\b")

    def test_remote_source_requires_verified_tls_and_private_credentials(self):
        path = self.output / "pg-service.conf"
        path.write_text("[obs_provisioning]\nhost=database.example\nsslmode=require\n")
        path.chmod(0o600)
        with self.assertRaisesRegex(ADAPTER.SnapshotError, "tls_required"):
            ADAPTER.fetch_database(local_peer=False, database="jengasec", service_file=path)
        path.write_text("[obs_provisioning]\nhost=database.example\nsslmode=verify-full\n")
        with patch.object(ADAPTER, "bounded_command", return_value=source()) as execute:
            ADAPTER.fetch_database(local_peer=False, database="jengasec", service_file=path)
        self.assertEqual(execute.call_args.args[1]["PGSERVICE"], "obs_provisioning")
        with self.assertRaisesRegex(ADAPTER.SnapshotError, "tls_required"):
            ADAPTER.build_snapshot(source(), now=NOW, transport="tls")

    def test_command_output_is_bounded_and_database_errors_do_not_leak(self):
        with patch.object(ADAPTER, "MAX_BYTES", 1024):
            with self.assertRaisesRegex(ADAPTER.SnapshotError, "source_limit_exceeded"):
                ADAPTER.bounded_command([sys.executable, "-c", "print('x' * 2048)"], {}, "")
        with self.assertRaisesRegex(ADAPTER.SnapshotError, "database_query_failed") as error:
            ADAPTER.bounded_command([sys.executable, "-c", "import sys; print('DO_NOT_EXPORT', file=sys.stderr); sys.exit(1)"], {}, "")
        self.assertNotIn("DO_NOT_EXPORT", str(error.exception))


if __name__ == "__main__":
    unittest.main()
