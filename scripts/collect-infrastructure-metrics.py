#!/usr/bin/env python3
"""Publish bounded service, VPN and database metrics for node_exporter.

Owner: Observability. Reads local service state and optional local PostgreSQL
statistics. Atomically replaces one OBS-owned Prometheus textfile.
"""

import argparse
import json
import math
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time


POSTGRES_QUERY = """
BEGIN READ ONLY;
SET LOCAL ROLE pg_monitor;
SELECT json_build_object(
  'max_connections', current_setting('max_connections')::int,
  'connections', (SELECT count(*) FROM pg_stat_activity
                  WHERE backend_type = 'client backend' AND pid <> pg_backend_pid()),
  'active_connections', (SELECT count(*) FROM pg_stat_activity
                         WHERE backend_type = 'client backend' AND state = 'active'
                           AND pid <> pg_backend_pid()),
  'waiting_locks', (SELECT count(*) FROM pg_locks WHERE NOT granted),
  'deadlocks', (SELECT coalesce(sum(deadlocks), 0) FROM pg_stat_database),
  'commits', (SELECT coalesce(sum(xact_commit), 0) FROM pg_stat_database),
  'rollbacks', (SELECT coalesce(sum(xact_rollback), 0) FROM pg_stat_database),
  'database_bytes', (SELECT coalesce(sum(pg_database_size(oid)), 0)
                     FROM pg_database WHERE NOT datistemplate),
  'recovery', pg_is_in_recovery()
);
COMMIT;
"""


def run(command):
    result = subprocess.run(command, capture_output=True, text=True, timeout=10,
                            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    if result.returncode:
        raise RuntimeError("collector command failed")
    return result.stdout


def validate(config):
    if set(config) - {"services", "wireguard_interface", "postgresql"}:
        raise ValueError("unknown collector configuration")
    services = config.get("services", [])
    if not isinstance(services, list) or len(services) > 32:
        raise ValueError("invalid service list")
    if any(not isinstance(s, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9@_.:-]{0,100}\.service", s)
           for s in services):
        raise ValueError("invalid service name")
    if len(set(services)) != len(services):
        raise ValueError("duplicate service name")
    interface = config.get("wireguard_interface", "")
    if not isinstance(interface, str) or (interface and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}", interface)):
        raise ValueError("invalid interface name")
    if not isinstance(config.get("postgresql", False), bool):
        raise ValueError("postgresql must be boolean")
    return config


def collect(config, command=run, now=None):
    validate(config)
    now = time.time() if now is None else now
    lines = []

    def emit(name, value, **labels):
        value = float(value)
        if not math.isfinite(value):
            raise ValueError("invalid numeric metric")
        suffix = "{" + ",".join(f"{k}={json.dumps(v)}" for k, v in sorted(labels.items())) + "}" if labels else ""
        lines.append(f"jengasec_{name}{suffix} {value:.17g}")

    def component(name, fn):
        checkpoint = len(lines)
        try:
            fn()
        except (RuntimeError, ValueError, KeyError, TypeError, IndexError, OSError, subprocess.TimeoutExpired):
            del lines[checkpoint:]
            emit("collection_success", 0, collector=name)
        else:
            emit("collection_success", 1, collector=name)

    def services():
        for service in config.get("services", []):
            values = dict(line.split("=", 1) for line in command([
                "systemctl", "show", service, "--property=LoadState,ActiveState"
            ]).splitlines() if "=" in line)
            emit("service_expected", 1, service=service)
            emit("service_loaded", values.get("LoadState") == "loaded", service=service)
            emit("service_up", values.get("LoadState") == "loaded" and values.get("ActiveState") == "active", service=service)

    def wireguard():
        interface = config["wireguard_interface"]
        interfaces = command(["wg", "show", "interfaces"]).split()
        if interface not in interfaces:
            emit("wireguard_interface_up", 0, interface=interface)
            return
        link = json.loads(command(["ip", "-json", "link", "show", "dev", interface]))
        emit("wireguard_interface_up", bool(link) and "UP" in link[0].get("flags", []), interface=interface)
        # Public peer keys are read only to parse command output, never emitted.
        rows = [row.split() for row in command(["wg", "show", interface, "latest-handshakes"]).splitlines()]
        timestamps = [int(row[1]) for row in rows]
        transfers = [row.split() for row in command(["wg", "show", interface, "transfer"]).splitlines()]
        emit("wireguard_peers", len(rows), interface=interface)
        emit("wireguard_peers_recent", sum(stamp > 0 and 0 <= now - stamp <= 180 for stamp in timestamps), interface=interface)
        emit("wireguard_receive_bytes_total", sum(int(row[1]) for row in transfers), interface=interface)
        emit("wireguard_transmit_bytes_total", sum(int(row[2]) for row in transfers), interface=interface)

    def postgres():
        raw = command(["runuser", "-u", "postgres", "--", "psql", "-X", "-q", "-A", "-t",
                       "--set=ON_ERROR_STOP=1", "--dbname=postgres", "--command", POSTGRES_QUERY])
        data = json.loads(raw)
        for key in ["max_connections", "connections", "active_connections", "waiting_locks", "database_bytes"]:
            emit("postgres_" + key, data[key])
        for key in ["deadlocks", "commits", "rollbacks"]:
            emit("postgres_" + key + "_total", data[key])
        emit("postgres_in_recovery", data["recovery"])
        emit("postgres_up", 1)

    component("services", services)
    if config.get("wireguard_interface"):
        component("wireguard", wireguard)
    if config.get("postgresql"):
        component("postgresql", postgres)
    emit("collection_timestamp_seconds", now)
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    config = validate(json.loads(args.config.read_text()))
    payload = collect(config)
    with tempfile.NamedTemporaryFile("w", dir=args.output.parent, prefix=".metrics-", delete=False) as handle:
        temporary = Path(handle.name)
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        temporary.chmod(0o644)
        os.replace(temporary, args.output)
    finally:
        temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
