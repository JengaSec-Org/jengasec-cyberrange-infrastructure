#!/usr/bin/env python3
"""Stop only the passive IDS child when its existing EVE file cap is reached."""

import argparse
import os
import pathlib
import resource
import signal
import stat
import subprocess
import sys
import time

CAP_EXIT_STATUS = 75
POLL_SECONDS = 0.25


def capped_inodes(pid, eve_file, limit):
    """Inspect open files, including an inode renamed by the existing reader."""
    allowed = {str(eve_file), str(eve_file) + ".1"}
    result = set()
    try:
        descriptors = list(pathlib.Path(f"/proc/{pid}/fd").iterdir())
    except FileNotFoundError:
        return result
    for descriptor in descriptors:
        try:
            name = os.readlink(descriptor).removesuffix(" (deleted)")
            if name not in allowed:
                continue
            info = descriptor.stat()
            if stat.S_ISREG(info.st_mode) and info.st_size >= limit:
                result.add((info.st_dev, info.st_ino))
        except FileNotFoundError:
            continue  # The child closed/reopened a log during this inspection.
    return result


def current_file_capped(eve_file, limit):
    try:
        return eve_file.stat().st_size >= limit
    except FileNotFoundError:
        return False


def stop_child(child):
    if child.poll() is None:
        child.send_signal(signal.SIGINT)
        try:
            child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=5)


def supervise(eve_file, command):
    soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
    if soft <= 0 or soft == resource.RLIM_INFINITY or soft != hard:
        raise ValueError("a finite, equal soft and hard file-size limit is required")
    if current_file_capped(eve_file, soft):
        print("IDS EVE file cap reached; preserve and drain source before explicit recovery", file=sys.stderr)
        return CAP_EXIT_STATUS

    stopping = False

    def request_stop(_signum, _frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)
    # The event reader sends HUP to the whole service cgroup after a rename.
    # Suricata handles its own HUP; this launcher must remain alive.
    signal.signal(signal.SIGHUP, lambda _signum, _frame: None)
    # A piped host core handler may bypass LimitCORE=0. Let writes fail with
    # EFBIG, then stop the child explicitly instead of generating SIGXFSZ cores.
    signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
    child = subprocess.Popen(command, restore_signals=False)
    previous = set()
    try:
        while True:
            current = capped_inodes(child.pid, eve_file, soft)
            code = child.poll()
            if stopping:
                stop_child(child)
                return 0
            if code is not None:
                if current or current_file_capped(eve_file, soft):
                    print("IDS EVE file cap reached; explicit recovery required", file=sys.stderr)
                    return CAP_EXIT_STATUS
                return code if code >= 0 else 128 - code
            # Confirm the same open inode twice. A retained .1 file after a
            # successful HUP must not stop a writer that has already reopened.
            if current & previous:
                stop_child(child)
                print("IDS EVE file cap reached; capture stopped; explicit recovery required", file=sys.stderr)
                return CAP_EXIT_STATUS
            previous = current
            time.sleep(POLL_SECONDS)
    finally:
        stop_child(child)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--eve-file", type=pathlib.Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not args.eve_file.is_absolute() or args.eve_file.name != "eve.json" or not command:
        parser.error("an absolute eve.json path and a child command are required")
    return supervise(args.eve_file, command)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"IDS supervision failed: {type(exc).__name__}", file=sys.stderr)
        raise SystemExit(1) from exc
