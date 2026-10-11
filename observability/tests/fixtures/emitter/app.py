#!/usr/bin/env python3
"""Test emitter for the JengaSec observability pipeline."""

from __future__ import annotations

import json
import os
import re
import threading
import time
import uuid
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


ENTERPRISE = os.environ.get("JENGASEC_ENTERPRISE", "ENT-A")
APPLICATION = os.environ.get("JENGASEC_APPLICATION", "APP01")
NAMESPACE = os.environ.get("JENGASEC_NAMESPACE", "jengasec-ent-a-app01")
if re.fullmatch(r"ENT-[AB]", ENTERPRISE) is None:
    raise ValueError("JENGASEC_ENTERPRISE must be ENT-A or ENT-B")
if re.fullmatch(r"APP0[1-9]", APPLICATION) is None:
    raise ValueError("JENGASEC_APPLICATION must be APP01 through APP09")
if NAMESPACE != f"jengasec-{ENTERPRISE.lower()}-{APPLICATION.lower()}":
    raise ValueError("JENGASEC_NAMESPACE does not match the application instance")

START_TIME = time.time()
LOCK = threading.Lock()
COUNTERS = {"events": 0, "health": 0, "metrics": 0, "emit": 0, "rejected": 0}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def increment(name: str) -> None:
    with LOCK:
        COUNTERS[name] += 1


def request_event(request_id: str, source_ip: str, path: str = "/emit") -> dict[str, object]:
    return {
        "schema_version": "2.0",
        "ts": utc_now(),
        "level": "info",
        "enterprise": ENTERPRISE,
        "application": APPLICATION,
        "namespace": NAMESPACE,
        "event": "request_completed",
        "outcome": "success",
        "request_id": request_id,
        "source_ip": source_ip,
        "user_id": "reference-user-1",
        "target_id": "reference-request",
        "method": "GET",
        "path": path,
        "status": 200,
        "action": "emit_reference_event",
        "detail": {"route": path},
    }


def write_event(payload: dict[str, object]) -> None:
    print(json.dumps(payload, separators=(",", ":")), flush=True)
    increment("events")


def render_metrics() -> bytes:
    with LOCK:
        values = COUNTERS.copy()
    lines = [
        "# HELP jengasec_test_emitter_info Static test emitter metadata.",
        "# TYPE jengasec_test_emitter_info gauge",
        f'jengasec_test_emitter_info{{enterprise="{ENTERPRISE}",application="{APPLICATION}"}} 1',
        "# HELP jengasec_test_events_emitted_total Events written to stdout.",
        "# TYPE jengasec_test_events_emitted_total counter",
        f"jengasec_test_events_emitted_total {values['events']}",
        "# HELP jengasec_test_http_requests_total HTTP requests by route.",
        "# TYPE jengasec_test_http_requests_total counter",
        f'jengasec_test_http_requests_total{{route="healthz"}} {values["health"]}',
        f'jengasec_test_http_requests_total{{route="metrics"}} {values["metrics"]}',
        f'jengasec_test_http_requests_total{{route="emit"}} {values["emit"]}',
        f'jengasec_test_http_requests_total{{route="rejected"}} {values["rejected"]}',
        "# HELP process_start_time_seconds Start time of the process since unix epoch.",
        "# TYPE process_start_time_seconds gauge",
        f"process_start_time_seconds {START_TIME:.3f}",
        "",
    ]
    return "\n".join(lines).encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    server_version = "JengaSecReferenceEmitter/2.0"

    def send_bytes(self, status: HTTPStatus, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        parsed = urlparse(self.path)
        if parsed.path == "/healthz":
            increment("health")
            self.send_bytes(HTTPStatus.OK, b'{"status":"ok"}\n', "application/json")
            return
        if parsed.path == "/metrics":
            increment("metrics")
            self.send_bytes(
                HTTPStatus.OK,
                render_metrics(),
                "text/plain; version=0.0.4; charset=utf-8",
            )
            return

        marker = parse_qs(parsed.query).get("marker", [str(uuid.uuid4())])[0][:128]
        marker = marker or str(uuid.uuid4())
        event = request_event(marker, self.client_address[0], parsed.path)
        if parsed.path == "/emit":
            increment("emit")
            write_event(event)
            body = (json.dumps(event, separators=(",", ":")) + "\n").encode()
            self.send_bytes(HTTPStatus.OK, body, "application/json")
            return
        if parsed.path == "/emit-invalid":
            increment("rejected")
            event.pop("outcome")
            write_event(event)
            self.send_bytes(HTTPStatus.ACCEPTED, b'{"emitted":"invalid"}\n', "application/json")
            return
        if parsed.path == "/emit-sensitive":
            increment("rejected")
            event["authorization"] = "Bearer TEST-ONLY-NOT-A-CREDENTIAL"
            write_event(event)
            self.send_bytes(HTTPStatus.ACCEPTED, b'{"emitted":"sensitive"}\n', "application/json")
            return
        self.send_bytes(HTTPStatus.NOT_FOUND, b'{"error":"not_found"}\n', "application/json")

    def log_message(self, _format: str, *_args: object) -> None:
        """Suppress the server's non-JSON access log."""


def main() -> None:
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()


if __name__ == "__main__":
    main()
