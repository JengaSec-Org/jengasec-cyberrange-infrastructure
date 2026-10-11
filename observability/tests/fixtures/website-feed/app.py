#!/usr/bin/env python3
"""Development-only receiver for sanitized website feed updates."""

import json
import pathlib
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


FIELDS = {
    "schema_version",
    "event_id",
    "ts",
    "enterprise",
    "application",
    "event_type",
    "severity",
    "outcome",
    "verdict",
}
EVENTS = []
LOCK = threading.Lock()
OUTPUT = pathlib.Path("/data/feed.jsonl")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, _format, *_args):
        return

    def response(self, status, document):
        body = json.dumps(document, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/healthz":
            self.response(200, {"status": "ok"})
            return
        if parsed.path == "/events":
            event_id = parse_qs(parsed.query).get("event_id", [None])[0]
            with LOCK:
                events = [item for item in EVENTS if not event_id or item["event_id"] == event_id]
            self.response(200, {"events": events})
            return
        self.response(404, {"error": "not_found"})

    def do_POST(self):
        if urlparse(self.path).path != "/api/feed":
            self.response(404, {"error": "not_found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            event = json.loads(body)
            if set(event) != FIELDS or event["schema_version"] != "1.0":
                raise ValueError("unexpected feed shape")
        except (ValueError, json.JSONDecodeError):
            self.response(400, {"error": "invalid_feed"})
            return
        line = json.dumps(event, separators=(",", ":"), sort_keys=True)
        with LOCK:
            EVENTS.append(event)
            with OUTPUT.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        self.response(202, {"accepted": True})


ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
