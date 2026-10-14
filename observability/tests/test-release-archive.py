#!/usr/bin/env python3
"""Verify source archive integrity, executable modes and private output."""
import hashlib
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/fingerprint-observability-release.py"


class ArchiveTests(unittest.TestCase):
    def test_archive_contains_exact_fingerprinted_source_without_host_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.tar.gz"
            fingerprint = subprocess.check_output([sys.executable, str(SCRIPT), "--archive", str(path)], text=True).strip()
            digest = hashlib.sha256()
            with tarfile.open(path) as archive:
                members = archive.getmembers()
                self.assertEqual([m.name for m in members], sorted(m.name for m in members))
                self.assertIn("scripts/wait-observability-stack.sh", [m.name for m in members])
                for member in members:
                    self.assertFalse(Path(member.name).is_absolute())
                    self.assertNotIn("..", Path(member.name).parts)
                    self.assertTrue(member.isfile())
                    self.assertEqual((member.uid, member.gid, member.uname, member.gname), (0, 0, "", ""))
                    self.assertNotIn("__pycache__", member.name)
                    payload = archive.extractfile(member).read()
                    name = member.name.encode()
                    digest.update(len(name).to_bytes(4, "big"))
                    digest.update(name)
                    digest.update(len(payload).to_bytes(8, "big"))
                    digest.update(payload)
                    if member.name == "scripts/wait-observability-stack.sh":
                        self.assertEqual(member.mode, 0o755)
            self.assertEqual(digest.hexdigest(), fingerprint)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_rejects_output_inside_repository(self):
        result = subprocess.run([sys.executable, str(SCRIPT), "--archive", str(ROOT / "source.tar.gz")],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((ROOT / "source.tar.gz").exists())


if __name__ == "__main__":
    unittest.main()
