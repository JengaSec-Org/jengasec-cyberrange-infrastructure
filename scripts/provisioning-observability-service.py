#!/usr/bin/env python3
"""Schedule native observations and exchange fresh snapshots over restricted mTLS."""

import argparse
from datetime import timedelta
import fcntl
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import time


SPEC = importlib.util.spec_from_file_location(
    "provisioning_snapshot", Path(__file__).with_name("refresh-provisioning-observability.py"))
ADAPTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ADAPTER)
MAX_ENVELOPE = ADAPTER.MAX_BYTES + 16384
ROUTE = "/v1/provisioning/snapshot"


def private_directory(path):
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink() or path.stat().st_mode & 0o077:
        raise ADAPTER.SnapshotError("private_output_required")


def validate_envelope(envelope, *, now=None):
    """Validate both the native contract and its source publication marker."""
    now = now or ADAPTER.utc_now()
    if not isinstance(envelope, dict) or set(envelope) != {"status", "snapshot"}:
        raise ADAPTER.SnapshotError("invalid_envelope")
    status, snapshot = envelope["status"], envelope["snapshot"]
    if not isinstance(status, dict) or not isinstance(snapshot, dict):
        raise ADAPTER.SnapshotError("invalid_envelope")
    required_status = {"contract_version", "authorization", "state", "reason", "attempted_at",
                       "last_success_at", "expires_at", "snapshot_hash", "usable"}
    if (set(status) != required_status or status["contract_version"] != "provisioning-status/1.0"
            or status["authorization"] != "none" or status["state"] != "fresh"
            or status["reason"] != "none" or status["usable"] is not True
            or status["snapshot_hash"] != ADAPTER.snapshot_hash(ADAPTER.encode(snapshot))):
        raise ADAPTER.SnapshotError("invalid_publication")
    try:
        captured = ADAPTER.timestamp(snapshot["captured_at"])
        generated = ADAPTER.timestamp(snapshot["generated_at"])
        expires = ADAPTER.timestamp(snapshot["expires_at"])
        attempted = ADAPTER.timestamp(status["attempted_at"])
        lifetime = (expires - captured).total_seconds()
        if (not captured <= generated <= now + timedelta(seconds=5) or not captured <= now < expires
                or not 30 <= lifetime <= 300 or int(lifetime) != lifetime
                or status["expires_at"] != snapshot["expires_at"]
                or status["last_success_at"] != snapshot["generated_at"]
                or attempted > generated or ADAPTER.iso(attempted) != status["attempted_at"]):
            raise ADAPTER.SnapshotError("source_clock_or_age")
        records = snapshot["records"]
        if not isinstance(records, dict) or set(records) != set(ADAPTER.TABLES):
            raise ADAPTER.SnapshotError("invalid_source")
        source = {"captured_at": snapshot["captured_at"], "read_only": snapshot["read_only"],
                  "tls": snapshot["source_transport"] == "tls", "database": "jengasec"}
        for table in ADAPTER.TABLES:
            derived = {"effective_state"} if table == "allocations" else (
                {"window_state"} if table in {"assignments", "event_windows"} else set())
            rows = records[table]
            if not isinstance(rows, list) or len(rows) > ADAPTER.MAX_ROWS:
                raise ADAPTER.SnapshotError("source_limit_exceeded")
            if any(not isinstance(row, dict) or set(row) != ADAPTER.SOURCE_FIELDS[table] | derived for row in rows):
                raise ADAPTER.SnapshotError("invalid_source")
            source[table] = [{key: value for key, value in row.items() if key not in derived} for row in rows]
        rebuilt = ADAPTER.build_snapshot(source, now=generated, max_age=int(lifetime),
                                         transport=snapshot["source_transport"])
        if ADAPTER.encode(rebuilt) != ADAPTER.encode(snapshot):
            raise ADAPTER.SnapshotError("invalid_source")
    except (KeyError, TypeError) as error:
        raise ADAPTER.SnapshotError("invalid_source") from error
    return snapshot


def source_envelope(output, *, now=None):
    snapshot, state = ADAPTER.read_current(output, now=now)
    if snapshot is None:
        raise ADAPTER.SnapshotError("source_" + state)
    # A concurrent publication changes either hash; validate the pair again.
    status = json.loads(ADAPTER.read_bounded(output / "provisioning-status.json"))
    envelope = {"status": status, "snapshot": snapshot}
    validate_envelope(envelope, now=now)
    return envelope


def failed_cache(output, *, now=None):
    previous = None
    payload = None
    try:
        payload = ADAPTER.read_bounded(output / "provisioning-snapshot.json")
        previous = json.loads(payload)
        if not isinstance(previous, dict):
            previous = None
    except (OSError, ValueError):
        pass
    status = {"contract_version": "provisioning-status/1.0", "authorization": "none",
              "state": "refresh_failed" if previous else "unavailable", "reason": "source_unavailable",
              "attempted_at": ADAPTER.iso(now or ADAPTER.utc_now()),
              "last_success_at": previous.get("generated_at") if previous else None,
              "expires_at": previous.get("expires_at") if previous else None,
              "snapshot_hash": ADAPTER.snapshot_hash(payload) if previous else None, "usable": False}
    ADAPTER.atomic_write(output / "provisioning-status.json", ADAPTER.encode(status))


def pull_snapshot(output, fetch, *, now=None):
    private_directory(output)
    with (output / "refresh.lock").open("a") as lock:
        os.chmod(lock.name, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ADAPTER.SnapshotError("refresh_already_running") from error
        try:
            envelope = fetch()
            snapshot = validate_envelope(envelope, now=now)
        except (OSError, ValueError, http.client.HTTPException):
            failed_cache(output, now=now)
            raise ADAPTER.SnapshotError("source_unavailable") from None
        # Keep the original source clock and hash. Polling cannot extend expiry.
        (output / "provisioning-status.json").unlink(missing_ok=True)
        ADAPTER.atomic_write(output / "provisioning-snapshot.json", ADAPTER.encode(snapshot))
        ADAPTER.atomic_write(output / "provisioning-status.json", ADAPTER.encode(envelope["status"]))
        return snapshot


def write_metrics(output, destination, mode, success, started, *, now=None):
    now = now or ADAPTER.utc_now()
    snapshot, state = ADAPTER.read_current(output, now=now)
    try:
        status = json.loads(ADAPTER.read_bounded(output / "provisioning-status.json"))
    except (OSError, ValueError):
        status = {}
    if not isinstance(status, dict):
        status = {}
    def metric_time(value):
        try:
            return ADAPTER.timestamp(value).timestamp()
        except ValueError:
            return 0
    metrics = {
        "refresh_success": int(success), "snapshot_usable": int(state == "fresh"),
        "last_attempt_timestamp_seconds": now.timestamp(),
        "last_success_timestamp_seconds": metric_time(status.get("last_success_at")),
        "snapshot_expires_timestamp_seconds": metric_time(status.get("expires_at")),
        "snapshot_capture_timestamp_seconds": metric_time(snapshot.get("captured_at")) if snapshot else 0,
        "refresh_duration_seconds": max(0, time.monotonic() - started),
    }
    lines = []
    for name, value in metrics.items():
        lines += [f"# TYPE jengasec_provisioning_{name} gauge",
                  f'jengasec_provisioning_{name}{{mode="{mode}"}} {value:.6f}']
    lines.append("# TYPE jengasec_provisioning_snapshot_rows gauge")
    for table in ADAPTER.TABLES:
        count = snapshot["counts"][table] if snapshot else 0
        lines.append(f'jengasec_provisioning_snapshot_rows{{mode="{mode}",table="{table}"}} {count}')
    # These aggregate metrics have no identity values. The exporter needs read access.
    ADAPTER.atomic_write(destination, ("\n".join(lines) + "\n").encode(), mode=0o644)


def client_context(config):
    context = ssl.create_default_context(cafile=config["ca_file"])
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(config["cert_file"], config["key_file"])
    return context


def fetch_https(config):
    connection = http.client.HTTPSConnection(config["source_address"], config["port"],
                                              timeout=10, context=client_context(config))
    try:
        connection.request("GET", ROUTE, headers={"Accept": "application/json"})
        response = connection.getresponse()
        if response.status != 200 or response.getheader("Content-Type") != "application/json":
            raise ADAPTER.SnapshotError("source_unavailable")
        length = response.getheader("Content-Length")
        if length is None or not length.isdecimal() or int(length) > MAX_ENVELOPE:
            raise ADAPTER.SnapshotError("source_limit_exceeded")
        payload = response.read(MAX_ENVELOPE + 1)
        if len(payload) != int(length) or len(payload) > MAX_ENVELOPE:
            raise ADAPTER.SnapshotError("source_limit_exceeded")
        return json.loads(payload)
    finally:
        connection.close()


class SnapshotServer(HTTPServer):
    request_queue_size = 4
    allow_reuse_address = True

    def handle_error(self, *_args):
        # Socket errors must not put client addresses or request data in logs.
        pass

    def __init__(self, config, output):
        self.output = output
        self.allowed_address = str(ipaddress.ip_address(config["allowed_client_address"]))
        self.allowed_certificate = config["allowed_client_certificate_sha256"]
        if not re.fullmatch(r"[a-f0-9]{64}", self.allowed_certificate):
            raise ADAPTER.SnapshotError("invalid_configuration")
        listen = ipaddress.ip_address(config["listen_address"])
        if listen.is_unspecified or not listen.is_private:
            raise ADAPTER.SnapshotError("private_listener_required")
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.verify_mode = ssl.CERT_REQUIRED
        self.context.load_verify_locations(cafile=config["ca_file"])
        self.context.load_cert_chain(config["cert_file"], config["key_file"])
        self.address_family = socket.AF_INET6 if listen.version == 6 else socket.AF_INET
        super().__init__((str(listen), config["port"]), SnapshotHandler)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(5)
        try:
            if str(ipaddress.ip_address(address[0])) != self.allowed_address:
                raise OSError("client denied")
            connection = self.context.wrap_socket(connection, server_side=True)
            peer = hashlib.sha256(connection.getpeercert(binary_form=True)).hexdigest()
            if peer != self.allowed_certificate:
                raise OSError("client denied")
            return connection, address
        except (OSError, ValueError):
            connection.close()
            raise OSError("client denied") from None


class SnapshotHandler(BaseHTTPRequestHandler):
    server_version = "ProvisioningSnapshot"
    sys_version = ""

    def log_message(self, *_args):
        pass

    def respond(self, code, document):
        payload = (json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
        if len(payload) > MAX_ENVELOPE:
            code, payload = 503, b'{"state":"unavailable"}\n'
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)
        self.close_connection = True

    def do_GET(self):
        if self.path != ROUTE:
            self.respond(404, {"state": "unknown_route"})
            return
        try:
            self.respond(200, source_envelope(self.server.output))
        except (OSError, ValueError, KeyError, TypeError):
            self.respond(503, {"state": "unavailable", "authorization": "none"})

    def do_POST(self):
        self.respond(405, {"state": "method_not_allowed"})

    do_PUT = do_PATCH = do_DELETE = do_POST


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("capture", "serve", "pull"))
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--metrics-file", type=Path)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--database", default="jengasec")
    parser.add_argument("--max-age-seconds", default=120, type=int)
    args = parser.parse_args()
    config = json.loads(args.config.read_text()) if args.config else {}
    # systemd credentials contain the existing TLS material, never command-line secrets.
    credentials = os.environ.get("CREDENTIALS_DIRECTORY")
    if credentials:
        config.update({name + "_file": str(Path(credentials) / filename)
                       for name, filename in (("ca", "ca.crt"), ("cert", "tls.crt"), ("key", "tls.key"))})
    if args.mode == "serve":
        with SnapshotServer(config, args.output_dir) as server:
            server.serve_forever(poll_interval=0.5)
        return
    started = time.monotonic()
    success = False
    try:
        if args.mode == "capture":
            ADAPTER.refresh(args.output_dir, lambda: ADAPTER.fetch_database(local_peer=True, database=args.database),
                            database=args.database, max_age=args.max_age_seconds)
        else:
            pull_snapshot(args.output_dir, lambda: fetch_https(config))
        success = True
    finally:
        if args.metrics_file:
            write_metrics(args.output_dir, args.metrics_file, "source" if args.mode == "capture" else "cache", success, started)
    print(json.dumps({"state": "fresh", "authorization": "none"}))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, http.client.HTTPException):
        print("Provisioning observations unavailable; no usable attribution published")
        raise SystemExit(1)
