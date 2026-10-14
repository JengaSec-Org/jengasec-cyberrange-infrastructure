"""Bounded transport to the fixed private gateway; no scoring or token translation."""

import http.client
import json
import re
import socket
import threading
import time
from dataclasses import dataclass

MAX_BODY = 65536
MAX_RESPONSE = 1024 * 1024
PUBLIC_PREFIX = "/api/v1/scoring"
_READS = {"capabilities", "assets", "alerts", "telemetry/events", "telemetry/stream", "receipts", "health", "kill-switch"}
_WRITES = {"decisions", "source-health", "runtime-checks", "kill-switch", "receipts/ack"}
_ACTION = r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}"


class ProxyFailure(Exception):
    def __init__(self, code, status=503):
        self.code, self.status = code, status
        super().__init__(code)


@dataclass(frozen=True)
class ProxyResponse:
    status: int
    body: bytes
    content_type: str
    retry_after: str | None = None


class _HeaderReader:
    def __init__(self, stream):
        self.stream, self.remaining = stream, 16384

    def readline(self, limit=-1):
        line = self.stream.readline(min(limit if limit >= 0 else 16385, self.remaining + 1))
        self.remaining -= len(line)
        if self.remaining < 0:
            raise http.client.LineTooLong("scoring backend headers")
        return line

    def close(self):
        self.stream.close()


class _Response(http.client.HTTPResponse):
    def begin(self):
        original = self.fp
        self.fp = _HeaderReader(original)
        try:
            super().begin()
        finally:
            self.fp = original


class ScoringProxy:
    def __init__(self, port=9681, timeout=35):
        if type(port) is not int or not 1024 <= port <= 65535 or not 0.1 <= timeout <= 60:
            raise ValueError("invalid_scoring_backend_configuration")
        self.port, self.timeout = port, timeout
        self.slots = threading.BoundedSemaphore(16)

    @staticmethod
    def validate(method, path, authorization, body, query, content_type):
        allowed = (method == "GET" and (path in _READS or re.fullmatch(rf"(?:actions|evidence)/{_ACTION}", path)))
        allowed = allowed or (method == "POST" and (path in _WRITES or re.fullmatch(rf"actions/{_ACTION}(?:/revert)?", path)))
        if not allowed:
            raise ProxyFailure("scoring_route_not_found", 404)
        if not isinstance(authorization, str) or not authorization.startswith("Bearer "):
            raise ProxyFailure("unauthorized", 401)
        token = authorization[7:]
        if not 32 <= len(token) <= 512 or any(not 33 <= ord(c) <= 126 for c in token):
            raise ProxyFailure("unauthorized", 401)
        if len(body) > MAX_BODY:
            raise ProxyFailure("body_too_large", 413)
        if len(query) + len(path) + len(PUBLIC_PREFIX) + 2 > 4096 or any(not 33 <= c <= 126 for c in query):
            raise ProxyFailure("invalid_scoring_request_target", 400)
        if method == "GET" and body:
            raise ProxyFailure("unexpected_request_body", 400)
        if method == "POST" and query:
            raise ProxyFailure("unexpected_query_parameter", 400)
        if method == "POST" and content_type.lower() not in ("application/json", "application/json; charset=utf-8"):
            raise ProxyFailure("json_content_type_required", 415)

    def forward(self, method, path, authorization, body=b"", query=b"", content_type="application/json"):
        self.validate(method, path, authorization, body, query, content_type)
        if not self.slots.acquire(blocking=False):
            raise ProxyFailure("scoring_backend_busy")
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=self.timeout)
        connection.response_class = _Response
        deadline_socket = timer = response = None
        expired = threading.Event()
        started = time.monotonic()
        try:
            connection.connect()
            # Keep an independent descriptor: HTTPConnection may close its own
            # descriptor on Connection: close before the body has been read.
            deadline_socket = connection.sock.dup()

            def expire():
                expired.set()
                try:
                    deadline_socket.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

            remaining = self.timeout - (time.monotonic() - started)
            if remaining <= 0:
                raise ProxyFailure("scoring_backend_unavailable")
            timer = threading.Timer(remaining, expire)
            timer.daemon = True
            timer.start()
            target = "/api/v1/" + path + ("?" + query.decode("ascii") if query else "")
            headers = {"Authorization": authorization, "Connection": "close"}
            if method == "POST":
                headers.update({"Content-Type": content_type, "Content-Length": str(len(body))})
            connection.request(method, target, body=body if method == "POST" else None, headers=headers)
            response = connection.getresponse()
            if 300 <= response.status < 400 or response.status < 200 or response.status > 599:
                raise ProxyFailure("invalid_scoring_backend_response", 502)
            lengths = response.headers.get_all("Content-Length", [])
            if response.headers.get("Transfer-Encoding") or len(lengths) != 1 or not lengths[0].isdigit():
                raise ProxyFailure("invalid_scoring_backend_response", 502)
            length = int(lengths[0])
            if length > MAX_RESPONSE:
                raise ProxyFailure("scoring_response_too_large", 413)
            content_type = response.getheader("Content-Type", "")
            if content_type not in ("application/json", "text/event-stream"):
                raise ProxyFailure("invalid_scoring_backend_response", 502)
            if content_type == "text/event-stream" and (method != "GET" or path != "telemetry/stream" or response.status != 200):
                raise ProxyFailure("invalid_scoring_backend_response", 502)
            data = response.read(MAX_RESPONSE + 1)
            if expired.is_set() or len(data) != length:
                raise ProxyFailure("scoring_backend_unavailable")
            if content_type == "application/json" and not isinstance(json.loads(data), dict):
                raise ProxyFailure("invalid_scoring_backend_response", 502)
            retry = response.getheader("Retry-After")
            return ProxyResponse(response.status, data, content_type,
                                 retry if retry and retry.isdigit() and len(retry) <= 3 else None)
        except (OSError, http.client.HTTPException):
            raise ProxyFailure("scoring_backend_unavailable") from None
        except (ValueError, UnicodeError, RecursionError):
            raise ProxyFailure("invalid_scoring_backend_response", 502) from None
        finally:
            if timer is not None:
                timer.cancel()
            if response is not None:
                response.close()
            connection.close()
            if deadline_socket is not None:
                deadline_socket.close()
            self.slots.release()
