"""Authenticated bounded HTTP; redirects never receive credentials."""

import ipaddress
import urllib.error
import urllib.parse
import urllib.request

from .common import Invalid, canonical, decode


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


class Failure(Exception):
    def __init__(self, code, reason, retry_after=None):
        self.code, self.reason, self.retry_after = code, reason, retry_after
        super().__init__(reason)


def base_url(value, *, loopback_http=False):
    parsed = urllib.parse.urlsplit(value)
    local = False
    try:
        local = ipaddress.ip_address(parsed.hostname or "").is_loopback
    except ValueError:
        pass
    if (not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment
            or parsed.scheme != "https" and not (parsed.scheme == "http" and loopback_http and local)):
        raise Invalid("https_endpoint_required")
    return value.rstrip("/")


class Client:
    def __init__(self, base, headers=None, *, loopback_http=False, timeout=15, response_limit=1048576):
        self.base = base_url(base, loopback_http=loopback_http)
        self.headers = dict(headers or {})
        self.timeout = timeout
        self.response_limit = response_limit
        self.opener = urllib.request.build_opener(NoRedirect())

    def call(self, path, body=None):
        if not path.startswith("/") or path.startswith("//") or "\r" in path or "\n" in path:
            raise Invalid("invalid_endpoint_path")
        headers = dict(self.headers)
        raw = canonical(body) if body is not None else None
        if raw is not None:
            headers["Content-Type"] = "application/json"
            if len(raw) > 1048576:
                raise Invalid("request_too_large")
        request = urllib.request.Request(self.base + path, data=raw, headers=headers)
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                raw = response.read(self.response_limit + 1)
                body = decode(raw, self.response_limit) if raw else {}
                if not isinstance(body, dict):
                    raise Invalid("response_object_required")
                return response.status, body
        except urllib.error.HTTPError as error:
            retry = error.headers.get("Retry-After", "")
            raise Failure(error.code, "http_" + str(error.code), int(retry) if retry.isdigit() else None) from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise Failure(0, "transport_unavailable") from None
