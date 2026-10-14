#!/usr/bin/env python3
"""Exercise evidence integrity, scope, duplicate delivery and safe empty exports."""

import copy
import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest

import jsonschema

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from infrastructure_events import canonical, digest
spec = importlib.util.spec_from_file_location("infra_export", ROOT / "scripts/export-infrastructure-evidence.py")
export = importlib.util.module_from_spec(spec)
spec.loader.exec_module(export)


def record():
    value = json.loads((ROOT / "contracts/fixtures/infrastructure/valid/flow.json").read_text())
    value.update({"received_ts": "2026-10-14T09:00:01.000000Z", "event_id": "infra_" + digest(value["resource_id"] + "\n" + value["source_event_id"]), "provenance": {"collector": "jengasec-event-agent/1.0", "transport": "https"}})
    value["integrity_hash"] = "sha256:" + digest(canonical(value))
    return value


class InfrastructureEvidenceTests(unittest.TestCase):
    def select(self, records, ids=None):
        return export.select(records, {"test-host"}, export.timestamp("2026-10-14T09:00:00Z"), export.timestamp("2026-10-14T09:05:00Z"), "validation", ids or set())

    def test_hash_and_missing_reference_fail_closed(self):
        value = record()
        self.assertEqual(len(self.select([value])), 1)
        value["attributes"]["bytes"] = 999999
        with self.assertRaises(ValueError):
            self.select([value])
        with self.assertRaises(ValueError):
            self.select([], {record()["event_id"]})

    def test_retry_receipt_time_is_deduplicated_after_both_hashes_verify(self):
        first = record()
        later = copy.deepcopy(first)
        later["received_ts"] = "2026-10-14T09:00:02.000000Z"
        del later["integrity_hash"]
        later["integrity_hash"] = "sha256:" + digest(canonical(later))
        self.assertEqual(self.select([later, first]), [first])
        later["attributes"]["bytes"] = 456
        del later["integrity_hash"]
        later["integrity_hash"] = "sha256:" + digest(canonical(later))
        with self.assertRaises(ValueError):
            self.select([first, later])

    def test_empty_pack_is_valid_private_separate_and_idempotent(self):
        selection = {"resource_ids": ["test-host"], "start_ts": "2026-10-14T09:00:00Z", "end_ts": "2026-10-14T09:05:00Z", "environment": "validation", "event_ids": []}
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "evidence"
            target = export.write_pack(output, "empty-infrastructure", [], selection, "2026-10-14T09:05:01Z")
            manifest = json.loads((target / "manifest.json").read_text())
            schema = json.loads((ROOT / "contracts/infrastructure-evidence.schema.json").read_text())
            jsonschema.Draft202012Validator(schema).validate(manifest)
            self.assertNotIn("finding", manifest)
            self.assertEqual((target / "platform-audit.ndjson").read_bytes(), b"")
            self.assertEqual((target / "competition-events.ndjson").read_bytes(), b"")
            self.assertEqual(target.stat().st_mode & 0o777, 0o700)
            before = (target / "manifest.json").stat().st_mtime_ns
            export.write_pack(output, "empty-infrastructure", [], selection)
            self.assertEqual(before, (target / "manifest.json").stat().st_mtime_ns)

    def test_foreign_resource_and_platform_audit_are_not_infrastructure_evidence(self):
        value = record()
        value["resource_id"] = "foreign-host"
        self.assertEqual(self.select([value]), [])
        value = record()
        value["record_family"] = "platform_audit"
        with self.assertRaisesRegex(ValueError, "schema"):
            self.select([value])


if __name__ == "__main__":
    unittest.main()
