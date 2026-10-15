"""A real, source-bound HTTP check for block and recovery verification."""

import hashlib
import http.client
import ipaddress
import os
import socket
import ssl
import time
from pathlib import Path

from .common import Rejected, canonical, digest, object_fields, stamp


class FunctionalProbe:
    """Run on a trusted host/netns that owns both configured source addresses.

    The same immutable request tests the blocked source and an independent
    control source. Only status, bounded content hashes and network outcomes
    are archived. Application responses and request bodies are never retained.
    """

    def __init__(self, config, clock=time.time):
        self.config, self.clock = config, clock

    def request(self, check, source_ip):
        timeout = 1.0
        connection = http.client.HTTPConnection(check["target_ip"], check["port"], timeout=timeout)
        sock = None
        started = time.monotonic()
        try:
            sock = socket.create_connection((check["target_ip"], check["port"]), timeout=timeout,
                                            source_address=(source_ip, 0))
            actual_source = str(ipaddress.ip_address(sock.getsockname()[0]))
            if actual_source != source_ip:
                raise Rejected("probe_source_mismatch", 503)
            if check.get("tls", True):
                context = ssl.create_default_context(cafile=check.get("ca_file"))
                sock = context.wrap_socket(sock, server_hostname=check["host"])
            connection.sock = sock
            connection.request("GET", check["path"], headers={"Host": check["host"], "Connection": "close", "Accept": "application/json"})
            response = connection.getresponse()
            content = response.read(262145)
            if len(content) > 262144:
                raise Rejected("probe_response_too_large", 503)
            content_hash = "sha256:" + hashlib.sha256(content).hexdigest()
            success = response.status == check["expected_status"] and content_hash == check["expected_body_sha256"]
            return {"functional_success": success, "status": response.status, "content_hash": content_hash,
                    "outcome": "response", "source_ip": actual_source,
                    "duration_seconds": round(time.monotonic() - started, 6)}
        except (socket.timeout, TimeoutError, ConnectionError, http.client.HTTPException, OSError):
            return {"functional_success": False, "status": None, "content_hash": None,
                    "outcome": "connection_failed", "source_ip": source_ip,
                    "duration_seconds": round(time.monotonic() - started, 6)}
        finally:
            connection.close()
            if sock is not None:
                sock.close()

    def execute(self, request):
        object_fields(request, ("schema_version", "phase", "action_id", "case_id", "competition", "target_id", "tuple", "frozen_digest"))
        if request["schema_version"] != "ai-effect-probe/1.0" or request["phase"] not in ("before", "after", "recovery"):
            raise Rejected("invalid_probe_request")
        tuple_value = request["tuple"]
        object_fields(tuple_value, ("source_ip", "target_ip", "protocol", "port"))
        checks = [check for check in self.config["checks"]
                  if check["competition"] == request["competition"] and check["target_id"] == request["target_id"]
                  and check["frozen_digest"] == request["frozen_digest"]
                  and all(check[k] == tuple_value[k] for k in tuple_value)]
        if len(checks) != 1:
            raise Rejected("unregistered_effect_probe", 403)
        check = checks[0]
        if check["protocol"] != "tcp" or check["source_ip"] == check["control_source_ip"]:
            raise Rejected("invalid_probe_control", 503)
        path = check["path"]
        if not isinstance(path, str) or not path.startswith("/") or any(v in path for v in ("?", "#", "\r", "\n")):
            raise Rejected("invalid_probe_path", 503)
        host = check["host"]
        if not isinstance(host, str) or any(v in host for v in ("/", "@", "\r", "\n")):
            raise Rejected("invalid_probe_host", 503)
        started = self.clock()
        actual = self.request(check, check["source_ip"])
        control = self.request(check, check["control_source_ip"])
        proof = {"schema_version": "ai-effect-evidence/1.0", "action_id": request["action_id"],
                 "case_id": request["case_id"], "competition": request["competition"], "target_id": request["target_id"],
                 "phase": request["phase"], "occurred_at": stamp(started), "received_at": stamp(self.clock()),
                 "frozen_digest": request["frozen_digest"], "tuple": tuple_value,
                 "functional": actual, "control": control,
                 "assertion": {"expected_status": check["expected_status"], "expected_body_sha256": check["expected_body_sha256"]},
                 "check_hash": digest({k: check[k] for k in ("target_id", "source_ip", "control_source_ip", "target_ip", "port", "protocol", "host", "path", "expected_status", "expected_body_sha256", "frozen_digest")})}
        receipt_id = "air_" + hashlib.sha256(canonical(proof)).hexdigest()
        proof["receipt_id"] = receipt_id
        proof["integrity_hash"] = digest(proof)
        directory = Path(self.config["evidence_directory"])
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if directory.is_symlink() or directory.stat().st_mode & 0o077:
            raise Rejected("insecure_probe_evidence", 503)
        if sum(p.stat().st_size for p in directory.glob("air_*.json")) >= 64 * 1024 * 1024:
            raise Rejected("probe_evidence_full", 503)
        fd = os.open(directory / (receipt_id + ".json"), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(canonical(proof))
            handle.flush()
            os.fsync(handle.fileno())
        dfd = os.open(directory, os.O_DIRECTORY | os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
        return {"schema_version": "ai-effect-probe/1.0", "action_id": request["action_id"],
                "phase": request["phase"], **tuple_value, "functional_success": actual["functional_success"],
                "control_success": control["functional_success"], "evidence_refs": [{"family": "ai", "id": receipt_id}], "proof": proof}
