#!/usr/bin/env python3
"""Synthetic gateway, network, IDS, Kubernetes, and host telemetry."""

import datetime
import hashlib
import json
import os
import socket
import struct
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


SYSLOG_HOST = os.environ.get("JENGASEC_SYSLOG_HOST", "vector")
SYSLOG_UDP_PORT = int(os.environ.get("JENGASEC_SYSLOG_UDP_PORT", "514"))
SYSLOG_TCP_PORT = int(os.environ.get("JENGASEC_SYSLOG_TCP_PORT", "514"))
NETFLOW_HOST = os.environ.get("JENGASEC_NETFLOW_HOST", "goflow2")
NETFLOW_PORT = int(os.environ.get("JENGASEC_NETFLOW_PORT", "2055"))
OTLP_FIXTURE_FILE = os.environ.get(
    "JENGASEC_OTLP_FIXTURE_FILE", "/telemetry/kubernetes.jsonl"
)

COUNTERS = {"emissions": 0, "health": 0, "metrics": 0}
COUNTER_LOCK = threading.Lock()


def now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def increment(name: str) -> None:
    with COUNTER_LOCK:
        COUNTERS[name] += 1


def send_syslog(payload: dict, protocol: str) -> None:
    message = (
        f'<14>1 {payload["ts"]} source-fixture gateway - - - '
        + json.dumps(payload, separators=(",", ":"))
        + "\n"
    ).encode()
    if protocol == "udp":
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.sendto(message, (SYSLOG_HOST, SYSLOG_UDP_PORT))
        return
    with socket.create_connection((SYSLOG_HOST, SYSLOG_TCP_PORT), timeout=5) as client:
        client.sendall(message)


def send_netflow(marker: str) -> int:
    digest = hashlib.sha256(marker.encode()).digest()
    sequence = int.from_bytes(digest[:4], "big")
    source_port = 40000 + int.from_bytes(digest[4:6], "big") % 10000
    unix_seconds = int(time.time())
    header = struct.pack(
        "!HHIIIIBBH",
        5,
        1,
        1000,
        unix_seconds,
        0,
        sequence,
        0,
        0,
        0,
    )
    record = struct.pack(
        "!IIIHHIIIIHHBBBBHHBBH",
        0x0A3C010A,
        0x0A6C000B,
        0,
        1,
        2,
        3,
        300,
        900,
        1000,
        source_port,
        443,
        0,
        2,
        6,
        0,
        0,
        0,
        24,
        24,
        0,
    )
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.sendto(header + record, (NETFLOW_HOST, NETFLOW_PORT))
    return source_port


def base_event(source: str, event: str, marker: str) -> dict:
    return {
        "schema_version": "2.0",
        "ts": now(),
        "source": source,
        "event": event,
        "asset": "gateway",
        "outcome": "success",
        "verdict": "not_applicable",
        "request_id": marker,
        "source_ip": "10.60.1.10",
        "destination_ip": "10.108.0.11",
    }


def emit(marker: str) -> dict:
    ingress_marker = f"{marker}-ingress"
    ingress = base_event("ingress", "ingress_request", ingress_marker)
    ingress.update(
        {
            "asset": "gateway/ingress",
            "verdict": "allowed",
            "src_port": 41001,
            "dst_port": 443,
            "protocol": "TCP",
            "method": "GET",
            "path": "/healthz",
            "status": 200,
            "action": "route_request",
        }
    )
    send_syslog(ingress, "udp")

    firewall_marker = f"{marker}-firewall"
    firewall = base_event("network", "firewall_refused", firewall_marker)
    firewall.update(
        {
            "asset": "gateway/firewall",
            "outcome": "denied",
            "verdict": "refused",
            "src_port": 41002,
            "dst_port": 443,
            "protocol": "TCP",
            "rule_id": "scope-default-deny",
            "destination_ip": "10.108.0.12",
        }
    )
    send_syslog(firewall, "tcp")

    ids_marker = f"{marker}-ids"
    ids = base_event("ids", "suricata_alert", ids_marker)
    ids.update(
        {
            "asset": "gateway/ids",
            "outcome": "failure",
            "verdict": "unknown",
            "src_port": 41003,
            "dst_port": 443,
            "protocol": "TCP",
            "signature_id": "2100498",
            "signature": "Synthetic policy test",
            "category": "Policy",
            "ids_action": "allowed",
        }
    )
    send_syslog(ids, "tcp")

    host_marker = f"{marker}-host"
    host = base_event("host", "host_alert", host_marker)
    host.update(
        {
            "asset": "jengasec-ent-a-app01/node",
            "enterprise": "ENT-A",
            "application": "APP01",
            "namespace": "jengasec-ent-a-app01",
            "source_ip": "10.109.0.50",
            "outcome": "failure",
            "reason": "synthetic_disk_pressure",
        }
    )
    send_syslog(host, "udp")

    application_marker = f"{marker}-application"
    application = {
        "schema_version": "2.0",
        "ts": now(),
        "level": "info",
        "enterprise": "ENT-A",
        "application": "APP01",
        "namespace": "jengasec-ent-a-app01",
        "event": "request_completed",
        "outcome": "success",
        "request_id": application_marker,
        "source_ip": "10.60.1.10",
        "method": "GET",
        "path": "/healthz",
        "status": 200,
        "action": "health_check",
        "detail": {"route": "/healthz"},
    }

    kubernetes_marker = f"{marker}-kubernetes"
    kubernetes = base_event("kubernetes", "kubernetes_event", kubernetes_marker)
    kubernetes.update(
        {
            "asset": "jengasec-ent-a-app01/test-emitter",
            "enterprise": "ENT-A",
            "application": "APP01",
            "namespace": "jengasec-ent-a-app01",
            "source_ip": "10.109.0.50",
            "outcome": "success",
            "reason": "SyntheticReady",
            "kind": "Pod",
        }
    )
    with open(OTLP_FIXTURE_FILE, "a", encoding="utf-8") as fixture_file:
        fixture_file.write(json.dumps(application, separators=(",", ":")) + "\n")
        fixture_file.write(json.dumps(kubernetes, separators=(",", ":")) + "\n")

    source_port = send_netflow(marker)
    increment("emissions")
    return {
        "markers": {
            "ingress": ingress_marker,
            "firewall": firewall_marker,
            "ids": ids_marker,
            "host": host_marker,
            "application": application_marker,
            "kubernetes": kubernetes_marker,
        },
        "netflow_src_port": source_port,
    }


def metrics() -> bytes:
    with COUNTER_LOCK:
        values = dict(COUNTERS)
    lines = [
        "# TYPE jengasec_test_kubernetes_health gauge",
        'jengasec_test_kubernetes_health{enterprise="ENT-A",application="APP01"} 1',
        "# TYPE jengasec_test_source_emissions_total counter",
        f'jengasec_test_source_emissions_total {values["emissions"]}',
        "",
    ]
    return "\n".join(lines).encode()


class Handler(BaseHTTPRequestHandler):
    def send_body(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/healthz":
            increment("health")
            self.send_body(200, "text/plain", b"ok\n")
            return
        if parsed.path == "/metrics":
            increment("metrics")
            self.send_body(200, "text/plain; version=0.0.4", metrics())
            return
        if parsed.path == "/emit":
            marker = urllib.parse.parse_qs(parsed.query).get("marker", [""])[0]
            if not marker or len(marker) > 96:
                self.send_body(400, "text/plain", b"invalid marker\n")
                return
            body = json.dumps(emit(marker), separators=(",", ":")).encode()
            self.send_body(200, "application/json", body)
            return
        self.send_body(404, "text/plain", b"not found\n")

    def log_message(self, _format: str, *_args: object) -> None:
        return


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8081), Handler).serve_forever()
