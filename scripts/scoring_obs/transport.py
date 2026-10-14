"""Authenticated bounded HTTP; redirects never receive credentials."""

import contextlib
import ipaddress
import os
import pathlib
import ssl
import stat
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


def client_tls(files):
    """Load only verified private TLS material; never prompt for a key password."""
    if not isinstance(files, dict) or set(files) != {"ca_file", "cert_file", "key_file"}:
        raise Invalid("invalid_client_tls_config")
    try:
        with contextlib.ExitStack() as stack:
            opened, contents = {}, {}
            for name, value in files.items():
                if not isinstance(value, str) or not value or len(value) > 512 or any(char in value for char in "\x00\r\n"):
                    raise Invalid("invalid_tls_file")
                path = pathlib.Path(value)
                if not path.is_absolute() or ".." in path.parts or any(item.is_symlink() for item in (path, *path.parents)):
                    raise Invalid("invalid_tls_file")
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                handle = stack.enter_context(os.fdopen(fd, "rb"))
                info = os.fstat(handle.fileno())
                forbidden = 0o077 if name == "key_file" else 0o022
                if (not stat.S_ISREG(info.st_mode) or info.st_uid not in {0, os.geteuid()}
                        or info.st_mode & forbidden or not 0 < info.st_size <= 65536):
                    raise Invalid("unsafe_tls_file")
                contents[name] = handle.read(65537)
                if not 0 < len(contents[name]) <= 65536:
                    raise Invalid("unsafe_tls_file")
                opened[name] = handle.fileno()
            context = ssl.create_default_context(cadata=contents["ca_file"].decode("ascii"))
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            # Keep the validated descriptors open so a path replacement cannot
            # substitute different credentials between validation and loading.
            context.load_cert_chain("/proc/self/fd/" + str(opened["cert_file"]),
                                    "/proc/self/fd/" + str(opened["key_file"]), password=b"")
            return context
    except Invalid:
        raise
    except (OSError, ValueError, UnicodeError):
        raise Invalid("invalid_tls_material") from None


class Client:
    def __init__(self, base, headers=None, *, loopback_http=False, timeout=15, response_limit=1048576, tls=None):
        self.base = base_url(base, loopback_http=loopback_http)
        self.headers = dict(headers or {})
        self.timeout = timeout
        self.response_limit = response_limit
        if tls is not None and urllib.parse.urlsplit(self.base).scheme != "https":
            raise Invalid("client_tls_requires_https")
        handlers = [NoRedirect()]
        if tls is not None:
            handlers.append(urllib.request.HTTPSHandler(context=client_tls(tls)))
        self.opener = urllib.request.build_opener(*handlers)

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
            with error:
                retry = error.headers.get("Retry-After", "")
                raise Failure(error.code, "http_" + str(error.code), int(retry) if retry.isdigit() else None) from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise Failure(0, "transport_unavailable") from None
