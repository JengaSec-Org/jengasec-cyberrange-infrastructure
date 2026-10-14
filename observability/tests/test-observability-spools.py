#!/usr/bin/env python3
"""Check auxiliary retention, byte caps, active writers and cleanup boundaries."""

import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("spools", ROOT / "scripts/maintain-observability-spools.py")
SPOOLS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SPOOLS)


class SpoolTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.directories = {kind: self.root / kind for kind in SPOOLS.PATTERNS}
        for path in self.directories.values():
            path.mkdir()
        self.now = 1800000000

    def segment(self, name, size=80, age=300, spool="quarantine"):
        path = self.directories[spool] / name
        path.write_bytes(b"x" * size)
        os.utime(path, (self.now - age, self.now - age))
        return path

    def sweep(self, maximum=100, now=None):
        return SPOOLS.sweep(self.directories["quarantine"], "quarantine", maximum, 604800, 120, now or self.now)

    def test_capacity_removes_oldest_closed_segments_and_keeps_unrelated_files(self):
        oldest = self.segment("events-2026-01-01-00-00.jsonl", age=500)
        newest = self.segment("events-2026-01-01-00-01.jsonl")
        unrelated = self.segment("operator-notes.txt", size=1000, age=1000000)
        result = self.sweep()
        self.assertFalse(oldest.exists())
        self.assertTrue(newest.exists())
        self.assertTrue(unrelated.exists())
        self.assertEqual(result["bytes"], 80)
        self.assertEqual(result["removed"]["capacity"], {"files": 1, "bytes": 80})

    def test_active_segments_report_excess_until_they_close(self):
        active = self.segment("events-2026-01-01-00-01.jsonl", size=300, age=20)
        self.assertEqual(self.sweep()["excess_bytes"], 200)
        self.assertTrue(active.exists())
        self.assertEqual(self.sweep(now=self.now + 130)["excess_bytes"], 0)
        self.assertFalse(active.exists())

    def test_retention_applies_even_when_below_capacity_and_accepts_legacy_files(self):
        expired = self.segment("events.jsonl", age=604801)
        result = self.sweep(maximum=1000)
        self.assertFalse(expired.exists())
        self.assertEqual(result["removed"]["retention"]["files"], 1)

    def test_symlinks_cannot_escape_the_configured_directory(self):
        outside = self.root / "important"
        outside.write_text("preserve")
        (self.directories["quarantine"] / "events.jsonl").symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "regular file"):
            self.sweep()
        self.assertEqual(outside.read_text(), "preserve")

    def test_segment_changed_by_a_writer_is_not_removed(self):
        target = self.segment("events.jsonl", size=200)
        original = Path.lstat
        calls = 0
        def changed(path, *args, **kwargs):
            nonlocal calls
            if path == target:
                calls += 1
                if calls == 2:
                    path.write_bytes(b"x" * 300)
            return original(path, *args, **kwargs)
        with patch.object(Path, "lstat", changed):
            result = self.sweep()
        self.assertTrue(target.exists())
        self.assertEqual(result["removed"]["capacity"]["files"], 0)

    def test_private_counters_survive_restart_and_metrics_have_only_bounded_labels(self):
        state, metrics = self.root / "state", self.root / "spool.prom"
        self.segment("events.jsonl", size=200)
        limits = {kind: 100 for kind in self.directories}
        SPOOLS.maintain(self.directories, limits, state, metrics, now=self.now)
        self.segment("events-2026-01-01-00-00.jsonl", size=300)
        SPOOLS.maintain(self.directories, limits, state, metrics, now=self.now)
        counters = json.loads((state / "state.json").read_text())
        self.assertEqual(counters["quarantine"]["capacity"]["bytes"], 500)
        self.assertEqual(state.stat().st_mode & 0o777, 0o700)
        self.assertEqual((state / "state.json").stat().st_mode & 0o777, 0o600)
        self.assertEqual(metrics.stat().st_mode & 0o777, 0o644)
        self.assertIn('removed_bytes_total{spool="quarantine",reason="capacity"} 500', metrics.read_text())
        self.assertNotIn("events.jsonl", metrics.read_text())


if __name__ == "__main__":
    unittest.main()
