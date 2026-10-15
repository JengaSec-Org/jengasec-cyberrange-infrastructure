"""The existing AI boundary: scoped reads, decisions and verified real actions."""

import hashlib
import os
import re
import threading
import time
from collections import deque
from pathlib import Path

from .actuator import action_request
from .authority import CAPABILITIES, UNSUPPORTED
from .common import (Rejected, canonical, digest, evidence_refs, identifier, integer, number,
                     object_fields, read_json, stamp, timestamp)


class Gateway:
    def __init__(self, tokens, authority, store, telemetry, actuator, evidence_directory, clock=time.time):
        self.tokens, self.authority, self.store, self.telemetry, self.actuator = tokens, authority, store, telemetry, actuator
        self.evidence_directory, self.clock = Path(evidence_directory), clock
        self.request_times, self.rate_lock = {}, threading.Lock()

    def rate_limit(self, principal):
        now = time.monotonic()
        with self.rate_lock:
            recent = self.request_times.setdefault(principal["source_id"], deque())
            while recent and recent[0] <= now - 60:
                recent.popleft()
            if len(recent) >= 120:
                raise Rejected("request_rate_exceeded", 429)
            recent.append(now)

    def receipts(self, principal, after=None, limit=200):
        scope = "receipts:" + (principal.get("team") or "operator")
        position = self.telemetry.cursors.decode(scope, after, 0)
        integer(position, 0, 2**63 - 1)
        result = self.store.receipts(position, integer(limit, 1, 1000), None if principal["kind"] == "operator" else principal["team"])
        result["next_cursor"] = self.telemetry.cursors.encode(scope, result["next_cursor"])
        return result

    def observation(self, principal, body, kind):
        required = ("epoch", "source_sequence", "occurred_at", "target_id", "case_id")
        fields = {
            "decision": ("classification", "incident_id", "rationale_code", "evidence_refs", "action_id", "clock_uncertainty_seconds"),
            "source_health": ("healthy", "gap_count", "clock_uncertainty_seconds"),
            "runtime_check": ("check", "passed", "evidence_refs"),
        }
        if kind not in fields:
            raise Rejected("unsupported_observation")
        object_fields(body, (*required, *fields[kind]))
        identifier(body["epoch"])
        integer(body["source_sequence"], 1, 2**63 - 1)
        identifier(body["target_id"])
        identifier(body["case_id"])
        now, occurred = self.clock(), timestamp(body["occurred_at"])
        if occurred > now + 2 or occurred < now - 120:
            raise Rejected("observation_too_late", 409)
        grant = self.authority.resolve(principal, body["target_id"], now, at=occurred)
        payload = {key: body[key] for key in fields[kind]}
        if kind == "decision":
            if principal["kind"] != "competitor":
                raise Rejected("competitor_source_required", 403)
            if body["classification"] not in ("attack", "legitimate", "abstain"):
                raise Rejected("invalid_classification")
            identifier(body["incident_id"])
            if body["rationale_code"] not in ("signature_match", "model_anomaly", "correlated_activity", "known_legitimate", "insufficient_evidence", "policy_response"):
                raise Rejected("invalid_rationale")
            number(body["clock_uncertainty_seconds"], 0, 86400)
            refs = evidence_refs(body["evidence_refs"])
            # Global infrastructure evidence remains staff-only.
            if any(ref["family"] == "infrastructure" for ref in refs):
                raise Rejected("staff_evidence_not_permitted", 403)
            if body["action_id"] is not None:
                if not re.fullmatch(r"aia_[a-f0-9]{64}", str(body["action_id"])):
                    raise Rejected("invalid_action_reference")
                action = self.actuator.call("status", action_id=body["action_id"])
                if action["team_id"] != principal["team"] or action["case_id"] != body["case_id"]:
                    raise Rejected("action_reference_out_of_scope", 403)
        else:
            if principal["kind"] != "observer":
                raise Rejected("trusted_observer_required", 403)
            if kind == "source_health":
                if type(body["healthy"]) is not bool:
                    raise Rejected("invalid_source_health")
                integer(body["gap_count"], 0, 2**63 - 1)
                number(body["clock_uncertainty_seconds"], 0, 86400)
            else:
                if body["check"] not in ("deterministic", "model", "combined", "fallback", "scope", "budget", "reversal", "kill_switch") or type(body["passed"]) is not bool:
                    raise Rejected("invalid_runtime_check")
                if body["check"] not in principal.get("checks", []):
                    raise Rejected("observer_check_not_permitted", 403)
                if not evidence_refs(body["evidence_refs"]):
                    raise Rejected("runtime_evidence_required")
        return self.store.ingest_sequenced(principal, body, kind, grant.context(), payload, now)

    def _simple_action(self, principal, body, kind):
        object_fields(body, ("key", "case_id", "target_id", "evidence_refs"))
        for field in ("key", "case_id", "target_id"):
            identifier(body[field])
        evidence_refs(body["evidence_refs"])
        if any(ref["family"] == "infrastructure" for ref in body["evidence_refs"]):
            raise Rejected("staff_evidence_not_permitted", 403)
        now = self.clock()
        grant = self.authority.resolve(principal, body["target_id"], now, kind)
        action_id = "aia_" + hashlib.sha256(canonical([grant.competition, principal["team"], kind, body["key"]])).hexdigest()
        with self.store.execution_lock():
            previous = self.store.action(team=principal["team"], key=body["key"], competition=grant.competition)
            if previous:
                if previous["request_hash"] != digest({"type": kind, **body}):
                    raise Rejected("idempotency_conflict", 409)
                return {"action_id": previous["action_id"], "state": previous["state"], "receipts": self.store.action_receipts(previous["action_id"])}
            action = {"action_id": action_id, "competition": grant.competition, "team": principal["team"], "request": body,
                      "action_type": kind, "request_hash": digest({"type": kind, **body}), "created": now, "expires": now, "state": "requested"}
            with self.store.transaction() as db:
                self.store.reserve(action, db)
                self.store.emit("action", grant.context(), body["case_id"],
                                {"action_id": action_id, "action_type": kind, "state": "requested"}, now, db=db)
                self.store.emit("action", grant.context(), body["case_id"],
                                {"action_id": action_id, "action_type": kind, "state": "authorized"}, now, db=db)
            if kind == "snapshot-evidence":
                snapshot = self.telemetry.read(principal, now, limit=1000)
                wanted = {ref["id"] for ref in body["evidence_refs"] if ref["family"] == "application"}
                records = [e for e in snapshot["events"] if e["event_id"] in wanted
                           and e["namespace"] == grant.target["namespace"]]
                if not wanted or {e["event_id"] for e in records} != wanted or snapshot["coverage"]["invalid_records"]:
                    action["state"] = "failed"
                    self.store.update_action(action)
                    self.store.emit("action", grant.context(), body["case_id"],
                                    {"action_id": action_id, "action_type": kind, "state": "failed", "reason_code": "evidence_incomplete"}, now, force=True)
                    return {"action_id": action_id, "state": "failed", "receipts": self.store.action_receipts(action_id)}
                self.evidence_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
                if self.evidence_directory.is_symlink() or self.evidence_directory.stat().st_mode & 0o077:
                    raise Rejected("insecure_evidence_directory", 503)
                data = canonical({"schema_version": "ai-evidence/1.0", **grant.context(), "case_id": body["case_id"], "events": records})
                total = sum(p.stat().st_size for p in self.evidence_directory.glob("*.json"))
                if total + len(data) > 64 * 1024 * 1024:
                    raise Rejected("evidence_archive_full", 503)
                path = self.evidence_directory / (action_id + ".json")
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "wb") as handle:
                    handle.write(data)
                    handle.flush()
                    os.fsync(handle.fileno())
                directory_fd = os.open(self.evidence_directory, os.O_DIRECTORY | os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
                reference = {"family": "ai", "archive_id": action_id, "integrity_hash": "sha256:" + hashlib.sha256(data).hexdigest()}
            else:
                reference = {"evidence_refs": body["evidence_refs"]}
            with self.store.transaction() as db:
                for state in ("executed", "verified"):
                    self.store.emit("action", grant.context(), body["case_id"],
                                    {"action_id": action_id, "action_type": kind, "state": state, **reference}, now, db=db)
                action["state"] = "verified"
                self.store.update_action(action, db)
            return {"action_id": action_id, "state": "verified", "receipts": self.store.action_receipts(action_id)}

    def action(self, bearer, kind, body):
        principal = self.tokens.authenticate(bearer, ("competitor",))
        try:
            if kind in UNSUPPORTED or kind not in CAPABILITIES:
                raise Rejected("unsupported_capability", 422)
            if kind != "block-ip":
                return self._simple_action(principal, body, kind)
            action_request(body)
            self.authority.resolve(principal, body["target_id"], self.clock(), kind, body["source_ip"])
            result = self.actuator.call("execute", token=bearer, request=body)
            self.store.import_receipts(result["receipts"])
            return result
        except Rejected as error:
            if error.status < 500:
                self.rejected_action(principal, kind, body, error.code)
            raise

    def rejected_action(self, principal, kind, body, reason):
        def safe_field(name):
            try:
                return identifier(body.get(name)) if isinstance(body, dict) else None
            except Rejected:
                return None
        now = self.clock()
        competition = None
        try:
            snapshot = self.authority.load(now)
            self.authority.team(snapshot, principal, now)
            competition = snapshot["competition"]["id"]
        except Rejected:
            pass
        context = {"competition": competition, "team_id": principal["team"], "target_id": safe_field("target_id"),
                   "assignment_id": None, "assignment_revision": None}
        # No rejected request body or arbitrary string is copied to the audit.
        self.store.emit("action", context, safe_field("case_id"),
                        {"action_id": None, "action_type": kind if kind in (*CAPABILITIES, *UNSUPPORTED) else "unsupported",
                         "state": "rejected", "reason_code": reason, "producer_source_id": principal["source_id"]}, now)

    def revert(self, bearer, action_id):
        self.tokens.authenticate(bearer, ("competitor", "operator"))
        result = self.actuator.call("revert", token=bearer, action_id=action_id)
        self.store.import_receipts(result["receipts"])
        return result

    def action_status(self, principal, action_id):
        if not isinstance(action_id, str) or not re.fullmatch(r"aia_[a-f0-9]{64}", action_id):
            raise Rejected("action_not_found", 404)
        local = self.store.action(action_id=action_id)
        if local:
            receipts = self.store.action_receipts(action_id)
            result = {"action_id": action_id, "state": local["state"], "team_id": local["team"], "competition": local["competition"],
                      "case_id": local["request"]["case_id"], "receipts_archived": not receipts, "receipts": receipts}
        else:
            result = self.actuator.call("status", action_id=action_id)
        if principal["kind"] != "operator" and result["team_id"] != principal["team"]:
            raise Rejected("action_not_found", 404)
        return result

    def evidence(self, principal, action_id):
        self.action_status(principal, action_id)
        action = self.store.action(action_id=action_id)
        if not action or action.get("action_type") != "snapshot-evidence" or action["state"] != "verified":
            raise Rejected("evidence_not_found", 404)
        return read_json(self.evidence_directory / (action_id + ".json"), maximum=1024 * 1024, secret=True)

    def synchronize(self):
        self.actuator.call("reconcile")
        cursor = int(self.store.meta("actuator_cursor") or "0")
        result = self.actuator.call("receipts", after=cursor, limit=200)
        self.store.import_receipts(result["receipts"])
        self.store.meta("actuator_cursor", result["next_cursor"])
        self.actuator.call("acknowledge", through=result["next_cursor"])
        self.store.meta("last_actuator_sync", stamp(self.clock()))

    def acknowledge(self, principal, cursor):
        if principal["kind"] != "operator":
            raise Rejected("forbidden", 403)
        through = self.telemetry.cursors.decode("receipts:operator", cursor, None)
        self.store.acknowledge(integer(through, 0, 2**63 - 1), self.clock())
        return {"acknowledged": cursor}

    def kill_switch(self, principal, enabled):
        if principal["kind"] != "operator":
            raise Rejected("forbidden", 403)
        if type(enabled) is not bool:
            raise Rejected("invalid_kill_switch")
        result = self.actuator.call("kill-switch", enabled=enabled)
        self.synchronize()
        return result

    def kill_switch_status(self, principal):
        if principal["kind"] != "operator":
            raise Rejected("forbidden", 403)
        return self.actuator.call("kill-switch-status")
