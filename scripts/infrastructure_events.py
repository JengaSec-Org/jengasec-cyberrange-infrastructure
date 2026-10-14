"""Sanitized infrastructure event mappings shared by collection and export."""

import datetime
import hashlib
import ipaddress
import json
import re


TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,252}$")
EVENT_SOURCES = {
    "host.service_state": "host",
    "host.auth_success": "host",
    "host.auth_failure": "host",
    "host.boot": "host",
    "kubernetes.event": "kubernetes",
    "network.flow": "network",
    "firewall.decision": "firewall",
    "ids.alert": "ids",
    "collector.health": "collector",
    "collector.loss": "collector",
}
PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPV6", 132: "SCTP"}
RULES = {
    "invalid", "peer_isolation", "protected_destination", "inbound_unsolicited",
    "allowed_assignment", "established_return", "default_deny",
}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def utc(value=None):
    if value is None:
        value = datetime.datetime.now(datetime.timezone.utc)
    if isinstance(value, (float, int)):
        value = datetime.datetime.fromtimestamp(value, datetime.timezone.utc)
    if isinstance(value, str):
        value = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if value.tzinfo is None:
        raise ValueError("event time has no timezone")
    return value.astimezone(datetime.timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def event(config, event_type, source_identity, timestamp, resource, attributes,
          severity="low", outcome="unknown", environment=None):
    return {
        "schema_version": "infrastructure/1.0",
        "record_family": "infrastructure_telemetry",
        "environment": environment or config["environment"],
        "source": EVENT_SOURCES[event_type],
        "resource_id": config["resource_id"],
        "event_type": event_type,
        "source_event_id": digest(source_identity),
        "ts": utc(timestamp),
        "severity": severity,
        "outcome": outcome,
        "resource": resource,
        "attributes": attributes,
    }


def protocol(value):
    if isinstance(value, int) or str(value).isdigit():
        return PROTOCOLS.get(int(value), "OTHER")
    value = str(value).upper()
    return value if value in PROTOCOLS.values() else "OTHER"


def network_fields(raw, source="src_ip", destination="dest_ip"):
    result = {"protocol": protocol(raw.get("proto", raw.get("protocol", "OTHER")))}
    for key, original in (("src_ip", source), ("dst_ip", destination)):
        if original in raw:
            result[key] = str(ipaddress.ip_address(raw[original]))
    for key, original in (("src_port", "src_port"), ("dst_port", "dest_port")):
        if original in raw:
            value = int(raw[original])
            if not 0 <= value <= 65535:
                raise ValueError("invalid network port")
            result[key] = value
    return result


def map_flow(config, raw, identity):
    attrs = network_fields(raw, "src_addr", "dst_addr")
    if "dst_port" in raw:
        attrs["dst_port"] = int(raw["dst_port"])
        if not 0 <= attrs["dst_port"] <= 65535:
            raise ValueError("invalid flow destination port")
    for key in ("bytes", "packets"):
        attrs[key] = int(raw[key])
        if not 0 <= attrs[key] <= 9007199254740991:
            raise ValueError("invalid flow count")
    attrs["sampling_rate"] = max(1, int(raw.get("sampling_rate", 1)))
    timestamp = raw.get("time_flow_end_ns", raw.get("time_received_ns"))
    if timestamp:
        timestamp = int(timestamp) / 1_000_000_000
    else:
        timestamp = None
    return event(config, "network.flow", identity, timestamp,
                 {"interface": config["interface"]}, attrs, outcome="success")


def map_ids(config, raw, identity):
    if raw.get("event_type") != "alert":
        return None
    alert = raw["alert"]
    attrs = network_fields(raw)
    signature_id = int(alert["signature_id"])
    attrs.update({"signature_id": signature_id,
                  "signature_revision": int(alert.get("rev", 0)),
                  "ids_action": "blocked" if alert.get("action") == "blocked" else "allowed"})
    category = re.sub(r"[^A-Za-z0-9_.:/-]", "-", str(alert.get("category", "unknown"))).strip("-")[:64]
    attrs["category"] = category if category and TOKEN.fullmatch(category) else "unknown"
    level = int(alert.get("severity", 3))
    # The sole local canary signature proves capture without claiming an attack.
    validation = signature_id == 9000001
    return event(config, "ids.alert", identity, raw["timestamp"],
                 {"interface": config["interface"]}, attrs,
                 severity="high" if level == 1 else "medium" if level == 2 else "low",
                 environment="validation" if validation else None)


def map_journal(config, raw):
    """Read untrusted journal text only in memory; emit allowlisted fields."""
    message = raw.get("MESSAGE", "")
    if not isinstance(message, str):
        return None
    identity = raw.get("__CURSOR")
    timestamp = int(raw["__REALTIME_TIMESTAMP"]) / 1_000_000
    if not isinstance(identity, str):
        return None
    comm = raw.get("_COMM", "")
    unit = raw.get("UNIT", raw.get("_SYSTEMD_UNIT", ""))
    if comm in {"sshd", "sshd-session", "sudo"}:
        success = message.startswith("Accepted ") or (comm == "sudo" and "session opened" in message)
        failure = message.startswith("Failed ") or "authentication failure" in message or "incorrect password" in message
        if not success and not failure:
            return None
        mechanism = "sudo" if comm == "sudo" else "publickey" if "publickey" in message else "password" if "password" in message else "pam"
        attrs = {"mechanism": mechanism}
        match = re.search(r"\bfrom ([0-9a-fA-F:.]+)\b", message)
        if match:
            try:
                attrs["peer_ip"] = str(ipaddress.ip_address(match.group(1)))
            except ValueError:
                pass
        return event(config, "host.auth_success" if success else "host.auth_failure",
                     identity, timestamp, {"service": "sudo" if comm == "sudo" else "ssh.service"},
                     attrs, outcome="success" if success else "failure",
                     severity="low" if success else "medium")
    if comm == "systemd" and unit in config["services"]:
        state, reason = ("unknown", "changed")
        if message.startswith("Started "):
            state, reason = "active", "started"
        elif message.startswith("Stopped ") or "Deactivated successfully" in message:
            state, reason = "inactive", "stopped"
        elif "Failed" in message or "failed" in message:
            state, reason = "failed", "failed"
        elif "Reloaded " in message:
            state, reason = "active", "reloaded"
        else:
            return None
        return event(config, "host.service_state", identity, timestamp, {"service": unit},
                     {"state": state, "reason": reason},
                     outcome="failure" if state == "failed" else "success",
                     severity="high" if state == "failed" else "low")
    if config.get("network") and (comm == "kernel" or raw.get("_TRANSPORT") == "kernel") and "JENGASEC_OBS:" in message:
        prefix = re.search(r"JENGASEC_OBS:(allowed|refused):([a-z_]+)\s", message)
        if not prefix or prefix.group(2) not in RULES:
            return None
        pairs = dict(re.findall(r"\b(IN|OUT|SRC|DST|SPT|DPT|PROTO)=([^ ]*)", message))
        if config["interface"] not in (pairs.get("IN"), pairs.get("OUT")):
            return None
        mapped = {"proto": pairs.get("PROTO", "OTHER")}
        for a, b in (("SRC", "src_ip"), ("DST", "dest_ip"), ("SPT", "src_port"), ("DPT", "dest_port")):
            if pairs.get(a):
                mapped[b] = pairs[a]
        attrs = network_fields(mapped)
        attrs.update({"verdict": prefix.group(1), "rule_id": prefix.group(2)})
        return event(config, "firewall.decision", identity, timestamp,
                     {"interface": config["interface"]}, attrs,
                     severity="medium" if prefix.group(1) == "refused" else "low",
                     outcome="denied" if prefix.group(1) == "refused" else "success")
    return None
