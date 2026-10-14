#!/usr/bin/env python3
"""Collect sanitized host events into a bounded durable HTTPS delivery queue.

Owner: Observability. Configuration and TLS material are private deployment inputs.
The queue commits journal cursors together with events. It never retains raw logs.
"""

import argparse
import fcntl
import json
import os
import pathlib
import re
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

from infrastructure_events import canonical, digest, event, map_flow, map_ids, map_journal


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(request.full_url, code, "redirect refused", headers, fp)


def load_config(path):
    value = json.loads(path.read_text())
    required = {"resource_id", "environment", "services", "endpoint", "tls_ca", "tls_cert", "tls_key", "state_dir", "metrics_file", "network", "interface"}
    if set(value) != required:
        raise ValueError("event agent config fields differ")
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", value["resource_id"]):
        raise ValueError("invalid resource identity")
    if value["environment"] not in {"live", "validation", "rehearsal"}:
        raise ValueError("invalid environment")
    if not isinstance(value["services"], list) or len(value["services"]) > 32:
        raise ValueError("services must be a bounded list")
    if any(not isinstance(s, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}\.service", s) for s in value["services"]):
        raise ValueError("invalid service")
    url = urllib.parse.urlsplit(value["endpoint"])
    if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment or url.path != "/api/v1/infrastructure-events":
        raise ValueError("receiver must use the approved HTTPS path")
    if type(value["network"]) is not bool:
        raise ValueError("network flag must be boolean")
    if value["network"] and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}", value["interface"]):
        raise ValueError("invalid capture interface")
    for key in ("tls_ca", "tls_cert", "tls_key", "state_dir", "metrics_file"):
        if not pathlib.Path(value[key]).is_absolute():
            raise ValueError("event paths must be absolute")
    return value


class Queue:
    """At-least-once queue with explicit, persisted loss counters."""

    def __init__(self, path, max_events=50000, max_bytes=64 * 1024 * 1024):
        self.max_events, self.max_bytes = max_events, max_bytes
        self.db = sqlite3.connect(path, timeout=10)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA journal_size_limit=4194304")
        self.db.execute("PRAGMA max_page_count=32768")
        self.db.execute("PRAGMA auto_vacuum=INCREMENTAL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS events (
              sequence INTEGER PRIMARY KEY,
              identity TEXT UNIQUE NOT NULL,
              payload TEXT NOT NULL,
              bytes INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        """)

    def get(self, key, default="0"):
        row = self.db.execute("SELECT value FROM state WHERE key=?", (key,)).fetchone()
        return row[0] if row else default

    def set(self, key, value):
        self.db.execute("INSERT INTO state VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))

    def increment(self, key, amount=1):
        self.set(key, int(self.get(key)) + amount)

    def size(self):
        return self.db.execute("SELECT count(*), coalesce(sum(bytes),0) FROM events").fetchone()

    def append(self, value, cursor=None):
        payload = canonical(value)
        size = len(payload.encode())
        if size > 16384:
            self.increment("rejected_total")
            self.increment("dropped_total")
            return
        identity = value["resource_id"] + ":" + value["source_event_id"]
        self.db.execute("INSERT OR IGNORE INTO events(identity,payload,bytes) VALUES(?,?,?)", (identity, payload, size))
        count, used = self.size()
        while count > self.max_events or used > self.max_bytes:
            row = self.db.execute("SELECT sequence,bytes FROM events ORDER BY sequence LIMIT 1").fetchone()
            self.db.execute("DELETE FROM events WHERE sequence=?", (row[0],))
            count, used = count - 1, used - row[1]
            self.increment("dropped_total")
        if cursor is not None:
            self.set("journal_cursor", cursor)

    def batch(self):
        return self.db.execute("SELECT sequence,payload FROM events ORDER BY sequence LIMIT 256").fetchall()

    def acknowledge(self, rows):
        self.db.executemany("DELETE FROM events WHERE sequence=?", [(row[0],) for row in rows])
        self.increment("delivered_total", len(rows))
        self.set("last_delivery_timestamp_seconds", int(time.time()))

    def close(self):
        self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        self.db.close()


def collection_loss(config, queue, reason, identity):
    queue.increment("dropped_total")
    queue.append(event(config, "collector.loss", identity, None, {}, {"count": 1, "reason": reason}, severity="medium", outcome="error"))


def collect_journal(config, queue):
    fields = "__CURSOR,__REALTIME_TIMESTAMP,_BOOT_ID,_COMM,_TRANSPORT,_SYSTEMD_UNIT,UNIT,MESSAGE,MESSAGE_ID"
    args = ["journalctl", "--output=json", "--no-pager", "--quiet", "--all", "--output-fields=" + fields]
    cursor = queue.get("journal_cursor", "")
    if cursor:
        args += ["--after-cursor=" + cursor]
    else:
        args += ["--since=-5min"]
    with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}) as process:
        count = 0
        deadline = time.monotonic() + 15
        while count < 1000 and time.monotonic() < deadline:
            line = process.stdout.readline(65537)
            if not line:
                break
            count += 1
            if len(line) > 65536:
                collection_loss(config, queue, "oversized_record", "journal-size:" + str(time.time_ns()))
                while line and not line.endswith(b"\n"):
                    line = process.stdout.readline(65537)
                continue
            try:
                raw = json.loads(line)
                value = map_journal(config, raw)
                if value:
                    queue.append(value)
                if isinstance(raw.get("__CURSOR"), str):
                    queue.set("journal_cursor", raw["__CURSOR"])
                    queue.set("journal_timestamp_seconds", int(raw["__REALTIME_TIMESTAMP"]) // 1_000_000)
            except (ValueError, KeyError, TypeError):
                queue.increment("rejected_total")
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=5)
        queue.set("journal_lag_seconds", max(0, int(time.time()) - int(queue.get("journal_timestamp_seconds"))) if count == 1000 else 0)
        if process.returncode and count == 0:
            if cursor:
                collection_loss(config, queue, "journal_cursor_lost", "cursor-loss:" + digest(cursor))
                queue.set("journal_cursor", "")
            raise RuntimeError("journal collection failed")


def collect_ids(config, queue):
    path = pathlib.Path(config["state_dir"]) / "suricata" / "eve.json"
    if not path.is_file():
        raise RuntimeError("IDS output unavailable")
    with path.open("rb") as stream:
        stat = os.fstat(stream.fileno())
        marker = str(stat.st_dev) + ":" + str(stat.st_ino)
        previous = queue.get("ids_file", "")
        offset = int(queue.get("ids_offset"))
        if previous != marker or stat.st_size < offset:
            if previous and int(queue.get("ids_size")) > offset:
                collection_loss(config, queue, "input_rotated", "ids-rotation:" + previous)
            offset = 0
        stream.seek(offset)
        for _ in range(1000):
            start = stream.tell()
            line = stream.readline(65537)
            if not line or not line.endswith(b"\n"):
                break
            try:
                if len(line) > 65536:
                    raise ValueError("oversized IDS record")
                value = map_ids(config, json.loads(line), marker + ":" + str(start))
                if value:
                    queue.append(value)
            except (ValueError, KeyError, TypeError):
                queue.increment("rejected_total")
            offset = stream.tell()
        queue.set("ids_file", marker)
        queue.set("ids_offset", offset)
        queue.set("ids_size", stat.st_size)


def heartbeat(config, queue, collection_ok=True):
    current = int(time.time())
    if current - int(queue.get("health_timestamp")) < 60:
        return
    count, used = queue.size()
    attrs = {key: int(queue.get(key)) for key in ("dropped_total", "delivered_total", "rejected_total", "collection_errors_total")}
    attrs.update({"queue_events": count, "queue_bytes": used})
    queue.append(event(config, "collector.health", "health:" + str(current // 60), current, {}, attrs, outcome="success" if collection_ok else "error", severity="low" if collection_ok else "medium"))
    queue.set("health_timestamp", current)


def deliver(config, queue):
    rows = queue.batch()
    if not rows:
        return
    ctx = ssl.create_default_context(cafile=config["tls_ca"])
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(config["tls_cert"], config["tls_key"])
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx), NoRedirect())
    payload = ("\n".join(row[1] for row in rows) + "\n").encode()
    request = urllib.request.Request(config["endpoint"], data=payload, headers={"Content-Type": "application/x-ndjson"}, method="POST")
    with opener.open(request, timeout=12) as response:
        if not 200 <= response.status < 300:
            raise RuntimeError("receiver rejected event batch")
        # The receiver acknowledges only after the durable downstream accepts.
        response.read(4096)
    with queue.db:
        queue.acknowledge(rows)


def write_metrics(config, queue, collection_ok):
    count, used = queue.size()
    values = {key: int(queue.get(key)) for key in ("dropped_total", "delivered_total", "rejected_total", "collection_errors_total", "delivery_errors_total", "last_delivery_timestamp_seconds", "last_collect_timestamp_seconds", "journal_lag_seconds", "flow_last_observed_timestamp_seconds")}
    values.update({"queue_events": count, "queue_bytes": used, "collection_success": int(collection_ok)})
    target = pathlib.Path(config["metrics_file"])
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".events-", dir=target.parent)
    try:
        with os.fdopen(fd, "w") as handle:
            for key, value in sorted(values.items()):
                handle.write(f"jengasec_event_agent_{key} {value}\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(name, 0o644)
        os.replace(name, target)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def decode_flows(config, queue):
    """GoFlow2 writes into this pipe; only sanitized records reach disk."""
    index = 0
    while True:
        line = sys.stdin.buffer.readline(65537)
        if not line:
            return
        index += 1
        with queue.db:
            try:
                if len(line) > 65536:
                    while line and not line.endswith(b"\n"):
                        line = sys.stdin.buffer.readline(65537)
                    raise ValueError("oversized flow")
                raw = json.loads(line)
                identity = "flow:" + digest(canonical(raw))
                queue.append(map_flow(config, raw, identity))
                queue.set("flow_last_observed_timestamp_seconds", int(time.time()))
            except (ValueError, KeyError, TypeError):
                queue.increment("rejected_total")
        if index % 256 == 0:
            queue.db.execute("PRAGMA wal_checkpoint(PASSIVE)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=pathlib.Path, required=True)
    parser.add_argument("--decode-flows", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    config = load_config(args.config)
    state = pathlib.Path(config["state_dir"])
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    queue = Queue(state / "events.sqlite3")
    try:
        if args.decode_flows:
            decode_flows(config, queue)
            return 0
        with (state / "collect.lock").open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            collection_ok = True
            with queue.db:
                try:
                    collect_journal(config, queue)
                    if config["network"]:
                        collect_ids(config, queue)
                    queue.set("last_collect_timestamp_seconds", int(time.time()))
                except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
                    collection_ok = False
                    queue.increment("collection_errors_total")
                boot = pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip()
                if boot != queue.get("boot_id", ""):
                    boot_time = next(int(line.split()[1]) for line in pathlib.Path("/proc/stat").read_text().splitlines() if line.startswith("btime "))
                    if time.time() - boot_time <= 300:
                        queue.append(event(config, "host.boot", "boot:" + boot, boot_time, {}, {}, outcome="success"))
                    queue.set("boot_id", boot)
                heartbeat(config, queue, collection_ok)
            try:
                for _ in range(4):
                    deliver(config, queue)
            except (OSError, ValueError, RuntimeError, urllib.error.URLError):
                with queue.db:
                    queue.increment("delivery_errors_total")
            write_metrics(config, queue, collection_ok)
        return 0 if collection_ok else 1
    finally:
        queue.close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, sqlite3.Error) as exc:
        print(f"event collection failed: {type(exc).__name__}", file=sys.stderr)
        raise SystemExit(1) from exc
