"""Read-only functional application measurements and honest clock uncertainty."""

import ctypes
import http.client
import ipaddress
import json
import math
import platform
import socket
import ssl
import threading
import time
import uuid

from .common import Invalid, utc


PROBE_TIMEOUT_SECONDS = 5


def clock_uncertainty_ms():
    """Read Linux NTP state with modes=0; never adjust the clock."""
    if platform.system() != "Linux" or ctypes.sizeof(ctypes.c_long) != 8:
        return 60000

    class Timeval(ctypes.Structure):
        _fields_ = [("seconds", ctypes.c_long), ("microseconds", ctypes.c_long)]

    class Timex(ctypes.Structure):
        _fields_ = [("modes", ctypes.c_uint), ("offset", ctypes.c_long),
                    ("frequency", ctypes.c_long), ("maxerror", ctypes.c_long),
                    ("esterror", ctypes.c_long), ("status", ctypes.c_int),
                    ("constant", ctypes.c_long), ("precision", ctypes.c_long),
                    ("tolerance", ctypes.c_long), ("time", Timeval),
                    ("tick", ctypes.c_long), ("ppsfreq", ctypes.c_long),
                    ("jitter", ctypes.c_long), ("shift", ctypes.c_int),
                    ("stabil", ctypes.c_long), ("jitcnt", ctypes.c_long),
                    ("calcnt", ctypes.c_long), ("errcnt", ctypes.c_long),
                    ("stbcnt", ctypes.c_long), ("tai", ctypes.c_int),
                    ("padding", ctypes.c_int * 11)]
    value = Timex()
    try:
        function = ctypes.CDLL(None, use_errno=True).adjtimex
        function.argtypes, function.restype = [ctypes.POINTER(Timex)], ctypes.c_int
        result = function(ctypes.byref(value))
        if result < 0 or result == 5 or value.status & 0x40:
            return 60000
        offset_us = abs(value.offset) / (1000 if value.status & 0x2000 else 1)
        return min(60000, math.ceil((max(value.maxerror, value.esterror) + offset_us) / 1000))
    except (AttributeError, OSError):
        return 60000


def _path(value):
    if not isinstance(value, str) or not value.startswith("/") or value.startswith("//") or len(value) > 512:
        raise Invalid("invalid_probe_path")
    if "\r" in value or "\n" in value or "#" in value:
        raise Invalid("invalid_probe_path")
    return value


def _get(target, path, *, tls=False, timeout=PROBE_TIMEOUT_SECONDS):
    if timeout <= 0:
        return False, None
    deadline = time.monotonic() + timeout
    address = str(ipaddress.ip_address(target["ip_address"]))
    port = target["port"]
    if type(port) is not int or not 1 <= port <= 65535:
        raise Invalid("invalid_target_port")
    connection = (http.client.HTTPSConnection(address, port, timeout=timeout, context=ssl.create_default_context())
                  if tls else http.client.HTTPConnection(address, port, timeout=timeout))
    timer, expired = None, threading.Event()
    try:
        connection.connect()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False, None
        sock = connection.sock

        def interrupt():
            expired.set()
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()

        # Socket timeouts alone restart after each successful read. Stop the
        # underlying socket at the total deadline even if a peer drips bytes.
        timer = threading.Timer(remaining, interrupt)
        timer.daemon = True
        timer.start()
        connection.request("GET", _path(path), headers={"Accept": "application/json", "User-Agent": "JengaSec-functional-probe/1.0"})
        response = connection.getresponse()
        raw = response.read(65537)
        if len(raw) > 65536 or expired.is_set() or time.monotonic() >= deadline:
            return False, None
        return response.status == 200, raw
    except (OSError, http.client.HTTPException):
        return False, None
    finally:
        if timer is not None:
            timer.cancel()
            timer.join()
        connection.close()


def measure(target, spec, *, request=_get):
    """A ready process alone cannot satisfy the functional assertion."""
    health, functional = _path(spec["health_path"]), _path(spec["functional_path"])
    assertions = spec.get("assertions")
    if health == functional or not isinstance(assertions, list) or not 1 <= len(assertions) <= 16:
        raise Invalid("functional_assertions_required")
    for assertion in assertions:
        if set(assertion) != {"path", "equals"} or not isinstance(assertion["path"], list) or len(assertion["path"]) > 8:
            raise Invalid("invalid_functional_assertion")
        if not all(isinstance(key, str) and 0 < len(key) <= 64 for key in assertion["path"]):
            raise Invalid("invalid_functional_path")
    deadline = time.monotonic() + PROBE_TIMEOUT_SECONDS
    healthy, _ = request(target, health, tls=spec.get("tls", False), timeout=PROBE_TIMEOUT_SECONDS)
    if not healthy:
        return False
    served, raw = request(target, functional, tls=spec.get("tls", False), timeout=deadline - time.monotonic())
    if not served or not healthy:
        return False
    try:
        value = json.loads(raw)
        for assertion in assertions:
            found = value
            for part in assertion["path"]:
                found = found[part]
            if type(found) is not type(assertion["equals"]) or found != assertion["equals"]:
                return False
        return True
    except (ValueError, KeyError, TypeError, UnicodeError):
        return False


def receipt(producer_id, target, success, observed, uncertainty):
    slot = math.floor(observed.timestamp() / 15)
    identity = str(uuid.uuid5(uuid.NAMESPACE_URL, "jengasec-probe:" + producer_id + ":" + target["target_id"] + ":" + str(slot)))
    return {"producer_id": producer_id, "receipt_id": identity, "kind": "probe",
            "target_id": target["target_id"], "observed_at": utc(observed),
            "clock_uncertainty_ms": uncertainty,
            "measurements": {"successful": success, "expected": 1, "completed": 1,
                             "target_digest": target["frozen_digest"]}, "evidence_refs": []}
