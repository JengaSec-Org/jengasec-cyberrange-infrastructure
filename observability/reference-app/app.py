#!/usr/bin/env python3
"""Reference workload for the local JengaSec observability stack."""

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


CELL = os.environ.get("JENGASEC_CELL", "app-01")
if re.fullmatch(r"(app|ai)-[0-9]{2}", CELL) is None:
    raise ValueError("JENGASEC_CELL must match (app|ai)-NN")
START_TIME = time.time()
LOCK = threading.Lock()
COUNTERS = {
    "events": 0,
    "health": 0,
    "metrics": 0,
    "emit": 0,
}


def utc_now() -> str:
    """Return a millisecond-precision RFC 3339 UTC timestamp."""
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def increment(name: str) -> None:
    """Increment a named in-memory counter."""
    with LOCK:
        COUNTERS[name] += 1


def emit_event(
    event: str,
    target: str,
    marker: str,
    source_ip: str = "127.0.0.1",
) -> dict[str, object]:
    """Write one logging-contract-compliant event to stdout."""
    payload: dict[str, object] = {
        "ts": utc_now(),
        "level": "info",
        "cell": CELL,
        "event": event,
        "outcome": "success",
        "request_id": str(uuid.uuid4()),
        "source_ip": source_ip,
        "user": "reference-workload",
        "target": target,
        "severity": "low",
        "detail": {"marker": marker},
    }
    print(json.dumps(payload, separators=(",", ":")), flush=True)
    increment("events")
    return payload


def render_metrics() -> bytes:
    """Render the workload metrics using the Prometheus text format."""
    with LOCK:
        values = COUNTERS.copy()

    lines = [
        "# HELP jengasec_reference_info Static reference workload metadata.",
        "# TYPE jengasec_reference_info gauge",
        f'jengasec_reference_info{{cell="{CELL}"}} 1',
        "# HELP jengasec_reference_events_emitted_total Contract events emitted.",
        "# TYPE jengasec_reference_events_emitted_total counter",
        f"jengasec_reference_events_emitted_total {values['events']}",
        "# HELP jengasec_reference_http_requests_total HTTP requests by route.",
        "# TYPE jengasec_reference_http_requests_total counter",
        f'jengasec_reference_http_requests_total{{route="healthz"}} {values["health"]}',
        f'jengasec_reference_http_requests_total{{route="metrics"}} {values["metrics"]}',
        f'jengasec_reference_http_requests_total{{route="emit"}} {values["emit"]}',
        "# HELP process_start_time_seconds Start time of the process since unix epoch.",
        "# TYPE process_start_time_seconds gauge",
        f"process_start_time_seconds {START_TIME:.3f}",
        "",
    ]
    return "\n".join(lines).encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    """Serve health, metrics, and deterministic event generation endpoints."""

    server_version = "JengaSecReference/1.0"

    def send_bytes(
        self,
        status: HTTPStatus,
        body: bytes,
        content_type: str,
    ) -> None:
        """Send a response with an explicit content length."""
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        """Handle the reference workload's three public endpoints."""
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

        if parsed.path == "/emit":
            increment("emit")
            marker = parse_qs(parsed.query).get("marker", [str(uuid.uuid4())])[0]
            event = emit_event(
                event="reference_smoke",
                target="/emit",
                marker=marker,
                source_ip=self.client_address[0],
            )
            body = (json.dumps(event, separators=(",", ":")) + "\n").encode()
            self.send_bytes(HTTPStatus.OK, body, "application/json")
            return

        self.send_bytes(HTTPStatus.NOT_FOUND, b'{"error":"not_found"}\n', "application/json")

    def log_message(self, _format: str, *_args: object) -> None:
        """Suppress BaseHTTPRequestHandler's non-JSON access log."""


def main() -> None:
    """Start the reference HTTP server after emitting a startup event."""
    emit_event("reference_started", "reference-app", "startup")
    server = ThreadingHTTPServer(("0.0.0.0", 8080), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
