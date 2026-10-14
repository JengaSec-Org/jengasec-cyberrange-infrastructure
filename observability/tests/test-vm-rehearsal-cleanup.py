#!/usr/bin/env python3
"""Check the rehearsal EXIT cleanup scope and status without changing sudo policy."""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[2] / "scripts/validate-observability-vm.sh"
SOURCE = SCRIPT.read_text()
CLEANUP = SOURCE[SOURCE.index("cleanup() {"):SOURCE.index("\ntrap cleanup EXIT")]


class CleanupTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(subprocess.check_output(["mktemp", "-d", "/tmp/jengasec-obs-vm.XXXXXX"], text=True).strip())
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(lambda: shutil.rmtree(self.root, ignore_errors=True))
        self.log = Path(self.temp.name) / "sudo-args.json"
        (self.root / "queue").mkdir()
        (self.root / "queue/record").write_text("fixture")

    def execute(self, status=0, fallback=False, sudo_fails=False, path=None):
        # The fixture simulates the first rm permission failure. The hosted
        # rehearsal separately exercises real container-owned files as non-root.
        mock = ""
        if fallback:
            mock += "rm() { return 1; }\n"
        mock += '''sudo() {
  [[ "$1" == -n && "$2" == rm ]] || return 90
  shift 2
  python3 -c 'import json,os,sys;open(os.environ["ARGS_LOG"],"w").write(json.dumps(sys.argv[1:]))' "$@"
'''
        mock += "  return 7\n" if sudo_fails else '  command rm "$@"\n'
        mock += "}\n"
        return subprocess.run(["bash", "-c", "set -euo pipefail\n" + CLEANUP + "\n" + mock
                               + "trap cleanup EXIT\nexit " + str(status)],
                              env=os.environ | {"REHEARSAL_ROOT": str(path or self.root), "ARGS_LOG": str(self.log)},
                              capture_output=True, text=True)

    def test_normal_cleanup_needs_no_privileged_command(self):
        result = self.execute()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.root.exists())
        self.assertFalse(self.log.exists())

    def test_container_owned_cleanup_uses_only_the_exact_rehearsal_root(self):
        result = self.execute(fallback=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(self.log.read_text()), ["-r", "--one-file-system", "--", str(self.root)])
        self.assertFalse(self.root.exists())

    def test_cleanup_does_not_mask_an_original_validation_failure(self):
        result = self.execute(status=73, fallback=True)
        self.assertEqual(result.returncode, 73, result.stderr)
        self.assertFalse(self.root.exists())

    def test_cleanup_failure_still_fails_a_successful_validation(self):
        result = self.execute(fallback=True, sudo_fails=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.root.exists())
        self.assertIn("Could not remove", result.stderr)

    def test_cleanup_failure_preserves_the_original_failure_status(self):
        result = self.execute(status=73, fallback=True, sudo_fails=True)
        self.assertEqual(result.returncode, 73)

    def test_an_unrelated_directory_is_never_removed(self):
        result = self.execute(fallback=True, path=Path(self.temp.name))
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(Path(self.temp.name).is_dir())
        self.assertFalse(self.log.exists())

    def test_a_replaced_root_symlink_is_never_followed(self):
        shutil.rmtree(self.root)
        self.root.symlink_to(self.temp.name, target_is_directory=True)
        self.addCleanup(self.root.unlink)
        result = self.execute(fallback=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.root.is_symlink())
        self.assertTrue(Path(self.temp.name).is_dir())
        self.assertFalse(self.log.exists())


if __name__ == "__main__":
    unittest.main()
