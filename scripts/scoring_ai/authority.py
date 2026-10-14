"""Fail-closed, event-time resolution against the platform's canonical snapshot."""

import hashlib
import hmac
import ipaddress
import re
from dataclasses import dataclass

from .common import Rejected, address, identifier, integer, read_json, timestamp


CAPABILITIES = ("alert", "block-ip", "snapshot-evidence")
UNSUPPORTED = ("revoke-session", "disable-account", "rate-limit", "isolate-workload")


class Tokens:
    """Secrets are hashes in an owner-only file, with explicit producer grants."""

    def __init__(self, path):
        self.path = path

    def authenticate(self, bearer, required=None):
        if not isinstance(bearer, str) or not 32 <= len(bearer) <= 512 or not bearer.isascii():
            raise Rejected("unauthorized", 401)
        value = hashlib.sha256(bearer.encode()).hexdigest()
        config = read_json(self.path, maximum=256 * 1024, secret=True)
        entries = config.get("principals") if isinstance(config, dict) else None
        if not isinstance(entries, list) or not 1 <= len(entries) <= 1000:
            raise Rejected("invalid_token_config", 503)
        matches = []
        for entry in entries:
            if not isinstance(entry, dict) or not re.fullmatch(r"[a-f0-9]{64}", str(entry.get("sha256", ""))):
                raise Rejected("invalid_token_config", 503)
            if hmac.compare_digest(value, entry["sha256"]):
                matches.append(entry)
        if len(matches) != 1:
            raise Rejected("unauthorized", 401)
        principal = matches[0]
        if principal.get("kind") not in ("competitor", "observer", "operator"):
            raise Rejected("invalid_token_config", 503)
        identifier(principal.get("source_id"))
        if principal["kind"] != "operator":
            identifier(principal.get("team"))
            identifier(principal.get("cell_id"))
        if required and principal["kind"] not in required:
            raise Rejected("forbidden", 403)
        return {k: v for k, v in principal.items() if k != "sha256"}


@dataclass(frozen=True)
class Grant:
    competition: int
    team: str
    cell_id: str
    enterprise: str
    target: dict
    scope: dict
    revision: int
    not_after: float
    source_ip: str | None = None

    def context(self):
        return {
            "competition": self.competition,
            "team_id": self.team,
            "target_id": self.target["target_id"],
            "assignment_id": self.scope["scope_id"],
            "assignment_revision": self.revision,
        }


class Authority:
    def __init__(self, path, competition_networks, protected_networks, protected_ports):
        self.path = path
        try:
            self.networks = [ipaddress.ip_network(n, strict=True) for n in competition_networks]
            self.protected = [ipaddress.ip_network(n, strict=True) for n in protected_networks]
        except (ValueError, TypeError):
            raise Rejected("invalid_network_config", 503) from None
        if not self.networks or not self.protected:
            raise Rejected("network_boundaries_required", 503)
        self.ports = {integer(p, 1, 65535) for p in protected_ports}
        self.ports.update((22, 2379, 2380, 6443, 10250, 51820))

    @staticmethod
    def active(row, at):
        start = timestamp(row["valid_from"])
        end = float("inf") if row.get("valid_until") is None else timestamp(row["valid_until"])
        if end <= start:
            raise Rejected("invalid_assignment_interval", 503)
        return start <= at < end

    @staticmethod
    def unique(rows):
        if len(rows) != 1:
            raise Rejected("unresolved_or_ambiguous_identity", 403)
        return rows[0]

    def load(self, now):
        try:
            value = read_json(self.path)
            if value.get("schema_version") != "scoring-identity/2.0":
                raise Rejected("unsupported_identity_version", 503)
            integer(value["revision"], 1, 2**63 - 1)
            captured, expiry = timestamp(value["captured_at"]), timestamp(value["expires_at"])
            if not captured <= now < expiry or expiry - captured > 120:
                raise Rejected("stale_identity", 503)
            comp = value["competition"]
            integer(comp["id"], 1, 2**63 - 1)
            start, end = timestamp(comp["start"]), timestamp(comp["end"])
            if not start <= now < end:
                raise Rejected("outside_competition_window", 403)
            for key in ("teams", "allocations", "targets", "scopes"):
                if not isinstance(value[key], list) or len(value[key]) > 100000:
                    raise Rejected("invalid_identity", 503)
            return value
        except (KeyError, TypeError, AttributeError, OSError):
            raise Rejected("identity_unavailable", 503) from None

    def check_address(self, raw):
        ip = ipaddress.ip_address(address(raw))
        if not any(ip in n for n in self.networks) or any(ip in n for n in self.protected):
            raise Rejected("protected_network", 403)
        return str(ip)

    def team(self, snapshot, principal, at):
        team = self.unique([r for r in snapshot["teams"]
                            if r["team"] == principal["team"] and self.active(r, at)])
        if team["cell_id"] != principal["cell_id"] or team["track"] not in ("ai", "application"):
            raise Rejected("invalid_principal_assignment", 403)
        return team

    def resolve(self, principal, target_id, now, action=None, source_ip=None, at=None):
        at = now if at is None else at
        try:
            snapshot = self.load(now)
            if at > now + 2 or at < timestamp(snapshot["competition"]["start"]):
                raise Rejected("outside_competition_window", 403)
            team = self.team(snapshot, principal, at)
            # Reads and receipts use event-time ownership; mutations also require
            # the same current principal assignment, preventing expired access.
            current = self.team(snapshot, principal, now)
            if current["enterprise"] != team["enterprise"]:
                raise Rejected("assignment_changed", 403)
            target = self.unique([r for r in snapshot["targets"]
                                  if r["target_id"] == target_id and self.active(r, at)])
            if not isinstance(target.get("frozen_digest"), str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", target["frozen_digest"]):
                raise Rejected("unverified_workload", 403)
            if timestamp(target["verified_at"]) > at:
                raise Rejected("unverified_workload", 403)
            self.unique([r for r in snapshot["teams"] if r["team"] == target["team"] and self.active(r, at)])
            ip = self.check_address(target["ip_address"])
            port = integer(target["port"], 1, 65535)
            if port in self.ports or target["protocol"] not in ("tcp", "udp"):
                raise Rejected("protected_service", 403)
            if source_ip is not None:
                source_ip = self.check_address(source_ip)
                if ipaddress.ip_address(source_ip).version != ipaddress.ip_address(ip).version:
                    raise Rejected("address_family_mismatch", 403)
                allocation = self.unique([r for r in snapshot["allocations"]
                                          if r["source_ip"] == source_ip and self.active(r, at)])
                self.unique([r for r in snapshot["teams"] if r["team"] == allocation["team"] and self.active(r, at)])
            else:
                allocation = None
            scopes = [r for r in snapshot["scopes"]
                      if r["team"] == principal["team"] and r["target_id"] == target_id
                      and r.get("active") is True and self.active(r, at)
                      and (action is None or action in r["allowed_actions"])]
            if source_ip is not None:
                scopes = [r for r in scopes if ipaddress.ip_address(source_ip) in ipaddress.ip_network(r["source_cidr"], strict=True)]
            if source_ip is None and action != "block-ip" and scopes:
                # Several disjoint attacker CIDRs can grant access to the same
                # canonical target. Reading that target does not choose an
                # attacker identity or broaden an executable traffic selector.
                by_id = {r["scope_id"]: r for r in scopes}
                if len(by_id) != len(scopes):
                    raise Rejected("unresolved_or_ambiguous_identity", 403)
                scope = dict(sorted(scopes, key=lambda r: r["scope_id"])[0])
                scope["allowed_actions"] = sorted({a for r in scopes for a in r["allowed_actions"]})
            else:
                scope = self.unique(scopes)
            if action and (action not in CAPABILITIES or (action == "block-ip" and team["side"] != "blue")):
                raise Rejected("action_not_permitted", 403)
            rows = [team, current, target, *scopes] + ([allocation] if allocation else [])
            if action and any(not self.active(r, now) for r in rows):
                raise Rejected("assignment_changed", 403)
            expiry = min(timestamp(snapshot["expires_at"]), timestamp(snapshot["competition"]["end"]),
                         *[timestamp(r["valid_until"]) if r.get("valid_until") else float("inf") for r in rows])
            return Grant(snapshot["competition"]["id"], principal["team"], principal["cell_id"], team["enterprise"],
                         {**target, "ip_address": ip}, scope, snapshot["revision"], expiry, source_ip)
        except (KeyError, TypeError, ValueError, AttributeError):
            raise Rejected("invalid_identity", 503) from None

    def assets(self, principal, now):
        snapshot = self.load(now)
        self.team(snapshot, principal, now)
        result = []
        ids = {r["target_id"] for r in snapshot["scopes"] if r.get("team") == principal["team"]}
        for target_id in sorted(ids):
            grant = self.resolve(principal, target_id, now)
            result.append({"target_id": target_id, "enterprise": grant.target["enterprise"],
                           "application": grant.target["application"], "namespace": grant.target["namespace"],
                           "allowed_actions": [a for a in CAPABILITIES if a in grant.scope["allowed_actions"]]})
        return result
