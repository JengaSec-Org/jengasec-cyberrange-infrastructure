"""Bounded loopback HTTP service behind the existing authenticated TLS ingress."""

import http.client
import ipaddress
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .authority import CAPABILITIES, UNSUPPORTED
from .common import Rejected, canonical, decode_json, integer, object_fields


class HeaderReader:
    def __init__(self, stream):
        self.stream, self.remaining = stream, 16384

    def readline(self, limit):
        line = self.stream.readline(min(limit, self.remaining + 1))
        self.remaining -= len(line)
        if self.remaining < 0:
            raise http.client.LineTooLong("headers")
        return line


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 16

    def __init__(self, address, gateway):
        if not ipaddress.ip_address(address[0]).is_loopback:
            raise Rejected("listen_requires_loopback", 503)
        self.gateway, self.slots = gateway, threading.BoundedSemaphore(16)
        super().__init__(address, Handler)

    def process_request(self, request, client_address):
        request.settimeout(5)
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        # stdlib's traceback can include request-associated exception text.
        # Bounded error codes and health state are available through the API.
        return


class Handler(BaseHTTPRequestHandler):
    server_version = "JengaSecAI/2.0"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        return  # Never write tokens, payloads or participant paths to access logs.

    def parse_request(self):
        original = self.rfile
        self.rfile = HeaderReader(original)
        try:
            return super().parse_request()
        finally:
            self.rfile = original

    def send_error(self, code, message=None, explain=None):
        self.respond(code, {"error": "http_request_rejected"})

    def respond(self, status, body):
        data = canonical(body)
        self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        if status == 429:
            self.send_header("Retry-After", "5")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def bearer(self):
        values = self.headers.get_all("Authorization", [])
        if len(values) != 1 or not values[0].startswith("Bearer "):
            raise Rejected("unauthorized", 401)
        return values[0][7:]

    def body(self):
        if self.headers.get("Transfer-Encoding") or self.headers.get("Content-Encoding"):
            raise Rejected("unsupported_body_encoding", 400)
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) != 1 or not lengths[0].isdigit():
            raise Rejected("content_length_required", 411)
        length = int(lengths[0])
        if length > 65536:
            raise Rejected("body_too_large", 413)
        if self.headers.get("Content-Type", "").lower() not in ("application/json", "application/json; charset=utf-8"):
            raise Rejected("json_content_type_required", 415)
        raw = self.rfile.read(length)
        if len(raw) != length:
            raise Rejected("incomplete_request")
        return decode_json(raw)

    def route(self):
        if len(self.path) > 4096:
            raise Rejected("request_target_too_long", 414)
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.scheme or parsed.netloc or parsed.fragment or "%" in parsed.path:
            raise Rejected("invalid_request_target")
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True, max_num_fields=8)
        if any(len(values) != 1 for values in query.values()):
            raise Rejected("duplicate_query_parameter")
        return parsed.path, {key: values[0] for key, values in query.items()}

    def handle_api(self, method):
        try:
            gateway = self.server.gateway
            path, query = self.route()
            token = self.bearer()
            principal = gateway.tokens.authenticate(token)
            gateway.rate_limit(principal)
            if method == "GET":
                if self.headers.get("Transfer-Encoding") or self.headers.get("Content-Length") not in (None, "0"):
                    raise Rejected("unexpected_request_body")
                if path == "/api/v1/capabilities":
                    if query:
                        raise Rejected("unknown_query_parameter")
                    self.respond(200, {"schema_version": "ai-api/2.0", "actions": list(CAPABILITIES),
                                       "unsupported": list(UNSUPPORTED), "shadow": False,
                                       "limits": {"active_per_target": 1, "per_minute": 5, "per_hour": 30, "max_ttl_seconds": 60}})
                elif path == "/api/v1/assets":
                    if principal["kind"] == "operator" or query:
                        raise Rejected("competitor_scope_required", 403)
                    self.respond(200, {"assets": gateway.authority.assets(principal, gateway.clock())})
                elif path in ("/api/v1/telemetry/events", "/api/v1/alerts", "/api/v1/telemetry/stream"):
                    if principal["kind"] == "operator" or set(query) - {"since", "cursor", "limit"}:
                        raise Rejected("invalid_telemetry_query")
                    result = gateway.telemetry.read(principal, gateway.clock(), integer(int(query.get("limit", "200")), 1, 1000),
                                                    query.get("cursor"), query.get("since"), path == "/api/v1/alerts")
                    if path.endswith("/stream"):
                        # Bounded SSE batches resume with the same cursor. No
                        # unbounded connection or cross-tenant broadcast state.
                        data = b"".join(b"event: telemetry\ndata: " + canonical(e) + b"\n\n" for e in result["events"])
                        data += b"event: cursor\ndata: " + canonical({"next_cursor": result["next_cursor"], "coverage": result["coverage"]}) + b"\n\n"
                        self.close_connection = True
                        self.send_response(200)
                        self.send_header("Content-Type", "text/event-stream")
                        self.send_header("Content-Length", str(len(data)))
                        self.send_header("Cache-Control", "no-store")
                        self.send_header("Connection", "close")
                        self.end_headers()
                        self.wfile.write(data)
                    else:
                        self.respond(200, result)
                elif path == "/api/v1/receipts":
                    if set(query) - {"after", "limit"}:
                        raise Rejected("unknown_query_parameter")
                    self.respond(200, gateway.receipts(principal, query.get("after"), integer(int(query.get("limit", "200")), 1, 1000)))
                elif path.startswith("/api/v1/actions/"):
                    if query:
                        raise Rejected("unknown_query_parameter")
                    self.respond(200, gateway.action_status(principal, path[len("/api/v1/actions/"):]))
                elif path.startswith("/api/v1/evidence/"):
                    if query:
                        raise Rejected("unknown_query_parameter")
                    self.respond(200, gateway.evidence(principal, path[len("/api/v1/evidence/"):]))
                elif path == "/api/v1/health":
                    if principal["kind"] != "operator" or query:
                        raise Rejected("forbidden", 403)
                    gateway.authority.load(gateway.clock())
                    self.respond(200, {"identity": "fresh", "last_actuator_sync": gateway.store.meta("last_actuator_sync"),
                                       "actuator_error": gateway.store.meta("actuator_error")})
                else:
                    raise Rejected("not_found", 404)
            else:
                if query:
                    raise Rejected("unexpected_query_parameter")
                body = self.body()
                if path in ("/api/v1/decisions", "/api/v1/source-health", "/api/v1/runtime-checks"):
                    kind = {"/api/v1/decisions": "decision", "/api/v1/source-health": "source_health", "/api/v1/runtime-checks": "runtime_check"}[path]
                    receipt, duplicate = gateway.observation(principal, body, kind)
                    self.respond(200 if duplicate else 201, {"receipt": receipt, "duplicate": duplicate})
                elif path.startswith("/api/v1/actions/") and path.endswith("/revert"):
                    object_fields(body, ())
                    self.respond(200, gateway.revert(token, path[len("/api/v1/actions/"):-len("/revert")]))
                elif path.startswith("/api/v1/actions/"):
                    self.respond(202, gateway.action(token, path[len("/api/v1/actions/"):], body))
                elif path == "/api/v1/kill-switch":
                    object_fields(body, ("enabled",))
                    self.respond(200, gateway.kill_switch(principal, body["enabled"]))
                elif path == "/api/v1/receipts/ack":
                    object_fields(body, ("cursor",))
                    self.respond(200, gateway.acknowledge(principal, body["cursor"]))
                else:
                    raise Rejected("not_found", 404)
        except Rejected as error:
            self.respond(error.status, {"error": error.code})
        except (ValueError, TypeError, KeyError):
            self.respond(400, {"error": "invalid_request"})
        except (OSError, TimeoutError):
            self.respond(503, {"error": "service_unavailable"})

    def do_GET(self):
        self.handle_api("GET")

    def do_POST(self):
        self.handle_api("POST")
