"""Bounded wire types shared by the gateway and its independent actuator."""

import hashlib
import ipaddress
import json
import math
import os
import re
import stat
import subprocess
from datetime import datetime, timezone
from pathlib import Path


class Rejected(Exception):
    def __init__(self, code, status=400):
        self.code, self.status = code, status
        super().__init__(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def digest(value):
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def stamp(now):
    return datetime.fromtimestamp(now, timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def timestamp(value):
    try:
        if not isinstance(value, str) or len(value) > 40:
            raise ValueError()
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.utcoffset() is None or dt.utcoffset().total_seconds() != 0:
            raise ValueError()
        return dt.timestamp()
    except (ValueError, OverflowError, OSError):
        raise Rejected("invalid_timestamp") from None


def object_fields(value, required, optional=()):
    if not isinstance(value, dict) or set(value) - set(required) - set(optional) or set(required) - set(value):
        raise Rejected("invalid_fields")
    return value


def identifier(value, maximum=128):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./:-]{0," + str(maximum - 1) + r"}", value):
        raise Rejected("invalid_identifier")
    return value


def integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise Rejected("invalid_integer")
    return value


def number(value, low, high):
    if type(value) not in (int, float) or not math.isfinite(value) or not low <= value <= high:
        raise Rejected("invalid_number")
    return value


def address(value):
    try:
        if not isinstance(value, str) or "%" in value:
            raise ValueError()
        ip = ipaddress.ip_address(value)
        if ip.version == 6 and ip.ipv4_mapped is not None:
            raise ValueError()
        if ip.is_unspecified or ip.is_multicast or ip.is_link_local or ip.is_loopback:
            raise ValueError()
        return str(ip)
    except ValueError:
        raise Rejected("invalid_address") from None


def evidence_refs(value):
    if not isinstance(value, list) or len(value) > 32:
        raise Rejected("invalid_evidence")
    seen = set()
    for ref in value:
        object_fields(ref, ("family", "id"))
        patterns = {
            "application": r"evt_[a-f0-9]{64}",
            "infrastructure": r"infra_[a-f0-9]{64}",
            "ai": r"air_[a-f0-9]{64}",
            "scenario": r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}",
        }
        pattern = patterns.get(ref["family"])
        if not pattern or not isinstance(ref["id"], str) or not re.fullmatch(pattern, ref["id"]):
            raise Rejected("invalid_evidence")
        key = (ref["family"], ref["id"])
        if key in seen:
            raise Rejected("duplicate_evidence")
        seen.add(key)
    return value


def decode_json(data, maximum=65536):
    if len(data) > maximum:
        raise Rejected("body_too_large", 413)

    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise Rejected("duplicate_json_key")
            out[key] = value
        return out

    def invalid_constant(_):
        raise Rejected("invalid_number")

    try:
        return json.loads(data, object_pairs_hook=pairs, parse_constant=invalid_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise Rejected("invalid_json") from None


def read_json(path, maximum=4 * 1024 * 1024, secret=False):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise Rejected("invalid_config_file", 503)
        if secret and info.st_mode & 0o077:
            raise Rejected("insecure_secret_permissions", 503)
        with os.fdopen(fd, "rb", closefd=False) as handle:
            return decode_json(handle.read(maximum + 1), maximum)
    finally:
        os.close(fd)


def run_bounded(argv, payload=b"", timeout=10, maximum=1024 * 1024):
    """Run fixed argv with bounded pipes, a deadline and no child error leak."""
    import selectors
    import signal
    import time

    if not isinstance(argv, list) or not argv or any(not isinstance(v, str) or not v for v in argv):
        raise Rejected("invalid_adapter_command", 503)
    if not Path(argv[0]).is_absolute():
        raise Rejected("adapter_requires_absolute_path", 503)

    process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True, close_fds=True)
    result, sent, observed = bytearray(), 0, 0
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            for stream, mode in ((process.stdin, selectors.EVENT_WRITE), (process.stdout, selectors.EVENT_READ), (process.stderr, selectors.EVENT_READ)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, mode)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise Rejected("adapter_timeout", 503)
                for key, _ in selector.select(min(remaining, 0.25)):
                    stream = key.fileobj
                    if stream is process.stdin:
                        if sent < len(payload):
                            try:
                                sent += os.write(stream.fileno(), payload[sent:sent + 8192])
                            except BrokenPipeError:
                                raise Rejected("adapter_failed", 503) from None
                        if sent == len(payload):
                            selector.unregister(stream)
                            stream.close()
                    else:
                        chunk = os.read(stream.fileno(), 16384)
                        observed += len(chunk)
                        if observed > maximum:
                            raise Rejected("adapter_output_too_large", 503)
                        if stream is process.stdout:
                            result.extend(chunk)
                        if not chunk:
                            selector.unregister(stream)
                            stream.close()
            process.wait(timeout=max(0.01, deadline - time.monotonic()))
            if process.returncode:
                raise Rejected("adapter_failed", 503)
            return bytes(result)
    except subprocess.TimeoutExpired:
        raise Rejected("adapter_timeout", 503) from None
    finally:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
        for stream in (process.stdin, process.stdout, process.stderr):
            if not stream.closed:
                stream.close()
