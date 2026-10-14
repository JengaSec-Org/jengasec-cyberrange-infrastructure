#!/usr/bin/env python3
"""Exercise the bounded IDS launcher with owned subprocesses and source files."""

import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import tempfile
import time
import unittest


LAUNCHER = Path(__file__).resolve().parents[2] / "scripts/run-bounded-suricata.py"
CAP = 4096
CHILD = r'''
import errno
import os
from pathlib import Path
import signal
import sys
import time

mode, filename = sys.argv[1:]
path = Path(filename)
if mode in ("normal", "unexpected"):
    path.write_bytes(b"complete record\n")
    raise SystemExit(0 if mode == "normal" else 9)
stopping = False
reopening = False
def stop(*_):
    global stopping
    stopping = True
def reopen(*_):
    global reopening
    reopening = True
signal.signal(signal.SIGINT, stop)
signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGHUP, reopen)
stream = path.open("ab", buffering=0)
stream.write(b"ready\n")
path.with_name("child.pid").write_text(str(os.getpid()))
try:
    if mode == "cap":
        while True:
            try:
                stream.write(b"x" * 1024)
            except OSError as error:
                if error.errno != errno.EFBIG:
                    raise
                break
    while not stopping:
        if reopening:
            stream.close()
            stream = path.open("ab", buffering=0)
            stream.write(b"reopened\n")
            reopening = False
        time.sleep(0.02)
    if mode != "cap":
        stream.write(b"stopped\n")
finally:
    stream.close()
'''


class FileCapTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.eve = self.root / "eve.json"
        self.child = self.root / "child.py"
        self.child.write_text(CHILD)
        self.processes = []

    def tearDown(self):
        for process in self.processes:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
            process.communicate(timeout=5)
        self.directory.cleanup()

    def start(self, mode):
        def limits():
            resource.setrlimit(resource.RLIMIT_FSIZE, (CAP, CAP))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        process = subprocess.Popen(
            [sys.executable, str(LAUNCHER), "--eve-file", str(self.eve), "--",
             sys.executable, str(self.child), mode, str(self.eve)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True, preexec_fn=limits,
        )
        self.processes.append(process)
        return process

    def wait_for(self, predicate, process):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if predicate():
                return
            self.assertIsNone(process.poll(), "launcher exited before child was ready")
            time.sleep(0.02)
        self.fail("child did not reach the expected state")

    def test_cap_stops_child_and_preserves_source(self):
        process = self.start("cap")
        self.assertEqual(process.wait(timeout=5), 75)
        contents = self.eve.read_bytes()
        self.assertEqual(len(contents), CAP)
        self.assertTrue(contents.startswith(b"ready\n"))
        pid_marker = (self.root / "child.pid").read_bytes()
        # An explicit start against the same capped source must not spawn again.
        retry = self.start("normal")
        self.assertEqual(retry.wait(timeout=5), 75)
        self.assertEqual(self.eve.read_bytes(), contents)
        self.assertEqual((self.root / "child.pid").read_bytes(), pid_marker)

    def test_normal_and_unexpected_exit_are_preserved(self):
        for mode, expected in (("normal", 0), ("unexpected", 9)):
            with self.subTest(mode=mode):
                process = self.start(mode)
                _, diagnostic = process.communicate(timeout=5)
                self.assertEqual(process.returncode, expected, diagnostic.decode())
                self.assertEqual(self.eve.read_bytes(), b"complete record\n")

    def test_termination_stops_only_owned_child(self):
        process = self.start("wait")
        marker = self.root / "child.pid"
        self.wait_for(lambda: marker.exists() and marker.stat().st_size > 0, process)
        child_pid = int(marker.read_text())
        process.send_signal(signal.SIGTERM)
        self.assertEqual(process.wait(timeout=5), 0)
        self.assertEqual(self.eve.read_bytes(), b"ready\nstopped\n")
        with self.assertRaises(ProcessLookupError):
            os.kill(child_pid, 0)

    def test_retained_cap_and_hup_rotation_preserve_source(self):
        previous = self.root / "eve.json.1"
        retained = b"retained\n" + b"r" * (CAP - len(b"retained\n"))
        previous.write_bytes(retained)
        process = self.start("wait")
        marker = self.root / "child.pid"
        self.wait_for(lambda: marker.exists() and marker.stat().st_size > 0, process)
        time.sleep(0.75)  # Longer than the launcher's two cap observations.
        self.assertIsNone(process.poll(), "an unopened retained file stopped capture")
        self.assertEqual(previous.read_bytes(), retained)
        evidence = self.root / "retained-evidence.json"
        previous.rename(evidence)
        old_inode = self.eve.stat().st_ino
        self.eve.rename(previous)
        os.killpg(process.pid, signal.SIGHUP)
        self.wait_for(lambda: self.eve.exists() and self.eve.read_bytes() == b"reopened\n", process)
        self.assertNotEqual(self.eve.stat().st_ino, old_inode)
        self.assertIsNone(process.poll(), "HUP killed the launcher")
        self.assertEqual(previous.read_bytes(), b"ready\n")
        self.assertEqual(evidence.read_bytes(), retained)
        process.send_signal(signal.SIGTERM)
        self.assertEqual(process.wait(timeout=5), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
