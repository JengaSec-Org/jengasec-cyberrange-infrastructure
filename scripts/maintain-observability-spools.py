#!/usr/bin/env python3
"""Bound completed auxiliary telemetry segments without truncating open files."""

import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import time


PATTERNS = {
    "quarantine": re.compile(r"events(?:-\d{4}-\d{2}-\d{2}-\d{2}-\d{2})?\.jsonl$"),
    "ai_handoff": re.compile(r"telemetry-\d{4}-\d{2}-\d{2}(?:-\d{2}-\d{2})?\.ndjson$"),
}


def atomic_write(path, payload, mode=0o600):
    descriptor, name = tempfile.mkstemp(prefix=".spool-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, mode)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def sweep(directory, spool, maximum, retention, grace, now):
    if not directory.is_absolute() or directory.is_symlink() or not directory.is_dir():
        raise ValueError("spool must be an existing real directory")
    records = []
    for path in directory.iterdir():
        if not PATTERNS[spool].fullmatch(path.name):
            continue
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("spool segment must be a regular file")
        records.append((info.st_mtime, path, info))
    total = sum(info.st_size for _, _, info in records)
    removed = {reason: {"files": 0, "bytes": 0} for reason in ("retention", "capacity")}
    retained = []
    for modified, path, info in sorted(records):
        reason = "retention" if modified < now - retention else "capacity" if total > maximum else None
        if reason is None or modified > now - grace:
            retained.append(modified)
            continue
        # A writer that touched the segment after inspection takes precedence.
        current = path.lstat()
        if (current.st_ino, current.st_dev, current.st_size, current.st_mtime_ns) != (
                info.st_ino, info.st_dev, info.st_size, info.st_mtime_ns):
            retained.append(current.st_mtime)
            total += current.st_size - info.st_size
            continue
        path.unlink()
        total -= info.st_size
        removed[reason]["files"] += 1
        removed[reason]["bytes"] += info.st_size
    return {"bytes": total, "excess_bytes": max(0, total - maximum),
            "oldest_segment_timestamp_seconds": min(retained, default=now), "removed": removed}


def maintain(directories, limits, state_directory, metrics_file, *, retention=604800, grace=120, now=None):
    now = time.time() if now is None else now
    state_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if state_directory.is_symlink() or state_directory.stat().st_mode & 0o077:
        raise ValueError("private maintenance state required")
    state_file = state_directory / "state.json"
    with (state_directory / "maintenance.lock").open("a") as lock:
        os.chmod(lock.name, 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if state_file.is_symlink() or (state_file.exists() and state_file.stat().st_size > 16384):
            raise ValueError("invalid maintenance state")
        state = json.loads(state_file.read_text()) if state_file.exists() else {}
        if not isinstance(state, dict):
            raise ValueError("invalid maintenance state")
        lines = []
        for spool in PATTERNS:
            result = sweep(directories[spool], spool, limits[spool], retention, grace, now)
            counters = state.setdefault(spool, {reason: {"files": 0, "bytes": 0} for reason in ("retention", "capacity")})
            for field in ("bytes", "excess_bytes", "oldest_segment_timestamp_seconds"):
                lines.append(f'jengasec_auxiliary_spool_{field}{{spool="{spool}"}} {result[field]}')
            for reason, deleted in result["removed"].items():
                for field, value in deleted.items():
                    counters[reason][field] += value
                    lines.append(f'jengasec_auxiliary_spool_removed_{field}_total{{spool="{spool}",reason="{reason}"}} {counters[reason][field]}')
        atomic_write(state_file, (json.dumps(state, sort_keys=True) + "\n").encode())
        lines.append(f"jengasec_auxiliary_spool_last_success_timestamp_seconds {now}")
        atomic_write(metrics_file, ("\n".join(lines) + "\n").encode(), 0o644)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quarantine-dir", type=Path, required=True)
    parser.add_argument("--ai-handoff-dir", type=Path, required=True)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--metrics-file", type=Path, required=True)
    parser.add_argument("--retention-hours", type=int, default=168)
    parser.add_argument("--quarantine-max-bytes", type=int, default=256 * 1024 * 1024)
    parser.add_argument("--ai-handoff-max-bytes", type=int, default=1024 * 1024 * 1024)
    parser.add_argument("--close-grace-seconds", type=int, default=120)
    args = parser.parse_args()
    if (args.retention_hours <= 0 or min(args.quarantine_max_bytes, args.ai_handoff_max_bytes) < 1024 * 1024
            or args.close_grace_seconds < 120 or not args.metrics_file.is_absolute()
            or not args.state_dir.is_absolute()):
        raise ValueError("invalid spool maintenance bounds")
    maintain({"quarantine": args.quarantine_dir, "ai_handoff": args.ai_handoff_dir},
             {"quarantine": args.quarantine_max_bytes, "ai_handoff": args.ai_handoff_max_bytes},
             args.state_dir, args.metrics_file, retention=args.retention_hours * 3600, grace=args.close_grace_seconds)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError):
        raise SystemExit("Auxiliary spool maintenance failed; inspect service health and freshness") from None
