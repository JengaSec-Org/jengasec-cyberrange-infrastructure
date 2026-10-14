"""Drop-only nft leases with independent authorization and effect receipts."""

import hashlib
import math
import re
import time

from .authority import CAPABILITIES, UNSUPPORTED
from .common import (Rejected, canonical, decode_json, digest, evidence_refs, identifier,
                     integer, number, object_fields, run_bounded, stamp, timestamp)


def action_request(body):
    object_fields(body, ("key", "case_id", "target_id", "source_ip", "ttl_seconds"), ("decision_id", "evidence_refs"))
    identifier(body["key"])
    identifier(body["case_id"])
    identifier(body["target_id"])
    integer(body["ttl_seconds"], 10, 60)
    if "decision_id" in body:
        if not re.fullmatch(r"air_[a-f0-9]{64}", str(body["decision_id"])):
            raise Rejected("invalid_decision_reference")
    evidence_refs(body.get("evidence_refs", []))
    return body


class Nft:
    """The provisioning worker owns its guard chain; this table can only drop."""

    def __init__(self, store, executable="/usr/sbin/nft", table="jengasec_ai_actions", runner=run_bounded):
        if not re.fullmatch(r"jengasec_ai_[a-z0-9_]{1,32}", table):
            raise Rejected("invalid_nft_table", 503)
        self.store, self.executable, self.table, self.run = store, executable, table, runner

    def commands(self, text):
        raw = text.encode()
        self.run([self.executable, "-c", "-f", "-"], raw)
        self.run([self.executable, "-f", "-"], raw)

    def tables(self):
        data = decode_json(self.run([self.executable, "-j", "list", "tables"]), 1024 * 1024)
        return [(v["table"]["family"], v["table"]["name"]) for v in data["nftables"] if "table" in v]

    def structure(self):
        data = decode_json(self.run([self.executable, "-j", "list", "table", "inet", self.table]), 1024 * 1024)
        values = []
        for entry in data["nftables"]:
            if "metainfo" in entry:
                continue
            copy = decode_json(canonical(entry))
            for item in copy.values():
                if isinstance(item, dict):
                    for field in ("handle", "elem", "use", "expires"):
                        item.pop(field, None)
            values.append(copy)
        return digest(values)

    def setup(self):
        expected = self.store.meta("nft_structure")
        if ("inet", self.table) in self.tables():
            if not expected or self.structure() != expected:
                raise Rejected("unreviewed_nft_table", 503)
            return
        table = self.table
        self.commands(
            f"add table inet {table}\n"
            f"add set inet {table} blocked4 {{ type ipv4_addr . ipv4_addr . inet_proto . inet_service; flags timeout; timeout 60s; size 1000; }}\n"
            f"add set inet {table} blocked6 {{ type ipv6_addr . ipv6_addr . inet_proto . inet_service; flags timeout; timeout 60s; size 1000; }}\n"
            f"add chain inet {table} guard {{ type filter hook forward priority -10; policy accept; }}\n"
            f"add rule inet {table} guard ip saddr . ip daddr . meta l4proto . th dport @blocked4 drop\n"
            f"add rule inet {table} guard ip6 saddr . ip6 daddr . meta l4proto . th dport @blocked6 drop\n"
        )
        self.store.meta("nft_structure", self.structure())

    @staticmethod
    def key(action):
        data = action["tuple"]
        # Every component was resolved and validated at this executor boundary.
        family = "blocked6" if ":" in data["source_ip"] else "blocked4"
        expression = f"{data['source_ip']} . {data['target_ip']} . {data['protocol']} . {data['port']}"
        return family, expression

    def apply(self, action, now):
        started = time.monotonic()
        remaining = math.floor(action["expires"] - now)
        if not 1 <= remaining <= 60:
            raise Rejected("lease_expired", 409)
        family, key = self.key(action)
        draft = f"add element inet {self.table} {family} {{ {key} timeout {remaining}s }}\n".encode()
        self.run([self.executable, "-c", "-f", "-"], draft, timeout=2)
        # Validation and process startup consume part of the authorization
        # window. Reserve the complete apply deadline so a delayed command
        # cannot leave a kernel lease beyond the canonical assignment expiry.
        remaining = math.floor(action["expires"] - now - (time.monotonic() - started)) - 2
        if remaining < 1:
            raise Rejected("lease_expired", 409)
        content = f"add element inet {self.table} {family} {{ {key} timeout {remaining}s }}\n".encode()
        self.run([self.executable, "-f", "-"], content, timeout=2)

    def contains(self, action):
        data = decode_json(self.run([self.executable, "-j", "list", "set", "inet", self.table, self.key(action)[0]]), 1024 * 1024)
        expected = [action["tuple"]["source_ip"], action["tuple"]["target_ip"], action["tuple"]["protocol"], action["tuple"]["port"]]
        for entry in data["nftables"]:
            for element in entry.get("set", {}).get("elem", []):
                if isinstance(element, dict) and "elem" in element:
                    element = element["elem"]
                if isinstance(element, dict) and "val" in element:
                    element = element["val"]
                if isinstance(element, dict):
                    value = element.get("concat")
                    if isinstance(value, list) and len(value) == 4:
                        value = [*value]
                        value[2] = {6: "tcp", 17: "udp"}.get(value[2], value[2])
                        if value == expected:
                            return True
        return False

    def remove(self, action):
        if self.contains(action):
            family, key = self.key(action)
            self.commands(f"delete element inet {self.table} {family} {{ {key} }}\n")
        if self.contains(action):
            raise Rejected("reversal_failed", 503)


class Verifier:
    """Run an owner-provided functional probe from the assigned traffic source.

    The command is fixed in the actuator's private config. Its JSON response
    contains observations only: no peer-provided URL, command, label or score.
    The actuator decides whether the before/after/recovery relation passed.
    """

    def __init__(self, command, runner=run_bounded):
        self.command, self.run = command, runner

    def check(self, action, phase):
        request = {"schema_version": "ai-effect-probe/1.0", "phase": phase,
                   "action_id": action["action_id"], "case_id": action["request"]["case_id"],
                   "competition": action["context"]["competition"], "target_id": action["request"]["target_id"],
                   "tuple": action["tuple"], "frozen_digest": action["frozen_digest"]}
        result = decode_json(self.run(self.command, canonical(request), timeout=7, maximum=16384), 16384)
        object_fields(result, ("schema_version", "action_id", "phase", "source_ip", "target_ip", "protocol", "port", "functional_success", "control_success", "evidence_refs", "proof"))
        if (result["schema_version"] != "ai-effect-probe/1.0" or result["action_id"] != action["action_id"]
                or result["phase"] != phase or any(result[k] != action["tuple"][k] for k in ("source_ip", "target_ip", "protocol", "port"))):
            raise Rejected("probe_identity_mismatch", 503)
        if type(result["functional_success"]) is not bool or type(result["control_success"]) is not bool:
            raise Rejected("invalid_probe_result", 503)
        if not evidence_refs(result["evidence_refs"]):
            raise Rejected("probe_evidence_required", 503)
        proof = result["proof"]
        object_fields(proof, ("schema_version", "action_id", "case_id", "competition", "target_id", "phase", "occurred_at", "received_at",
                              "frozen_digest", "tuple", "functional", "control", "assertion", "check_hash", "receipt_id", "integrity_hash"))
        object_fields(proof["assertion"], ("expected_status", "expected_body_sha256"))
        integer(proof["assertion"]["expected_status"], 100, 599)
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", str(proof["assertion"]["expected_body_sha256"])):
            raise Rejected("invalid_probe_proof", 503)
        for observation in (proof["functional"], proof["control"]):
            object_fields(observation, ("functional_success", "status", "content_hash", "outcome", "source_ip", "duration_seconds"))
            if type(observation["functional_success"]) is not bool or observation["outcome"] not in ("response", "connection_failed"):
                raise Rejected("invalid_probe_proof", 503)
            number(observation["duration_seconds"], 0, 10)
            if observation["functional_success"] and (observation["status"] != proof["assertion"]["expected_status"]
                                                        or observation["content_hash"] != proof["assertion"]["expected_body_sha256"]):
                raise Rejected("invalid_probe_proof", 503)
        if timestamp(proof["received_at"]) < timestamp(proof["occurred_at"]):
            raise Rejected("invalid_probe_proof", 503)
        copy = dict(proof)
        integrity = copy.pop("integrity_hash", None)
        if integrity != digest(copy):
            raise Rejected("invalid_probe_proof", 503)
        proof_id = copy.pop("receipt_id", None)
        if (proof_id != "air_" + hashlib.sha256(canonical(copy)).hexdigest()
                or proof.get("schema_version") != "ai-effect-evidence/1.0"
                or proof.get("tuple") != action["tuple"] or proof.get("action_id") != action["action_id"]
                or proof.get("case_id") != action["request"]["case_id"] or proof.get("phase") != phase
                or proof.get("frozen_digest") != action["frozen_digest"]
                or proof.get("functional", {}).get("functional_success") is not result["functional_success"]
                or proof.get("control", {}).get("functional_success") is not result["control_success"]
                or {"family": "ai", "id": proof_id} not in result["evidence_refs"]):
            raise Rejected("invalid_probe_proof", 503)
        return {"functional_success": result["functional_success"], "control_success": result["control_success"],
                "evidence_refs": result["evidence_refs"], "proof": proof}


class Actuator:
    def __init__(self, tokens, authority, store, nft, verifier, clock=time.time):
        self.tokens, self.authority, self.store = tokens, authority, store
        self.nft, self.verifier, self.clock = nft, verifier, clock

    def state(self, action, state, reason=None, force=False):
        action["state"] = state
        payload = {"action_id": action["action_id"], "action_type": "block-ip", "state": state,
                   "lease_expires_at": stamp(action["expires"]), "verification": action.get("verification", {}),
                   "decision_id": action["request"].get("decision_id"), "reason_code": reason,
                   "target_tuple": action["tuple"], "frozen_digest": action["frozen_digest"]}
        with self.store.transaction() as db:
            self.store.update_action(action, db)
            self.store.emit("action", action["context"], action["request"]["case_id"], payload, self.clock(), db=db, force=force)

    def response(self, action):
        receipts = self.store.action_receipts(action["action_id"])
        return {"action_id": action["action_id"], "state": action["state"], "lease_expires_at": stamp(action["expires"]),
                "team_id": action["team"], "competition": action["competition"], "case_id": action["request"]["case_id"],
                "receipts_archived": not receipts, "receipts": receipts}

    def execute(self, bearer, body):
        principal = self.tokens.authenticate(bearer, ("competitor",))
        body = action_request(body)
        now = self.clock()
        grant = self.authority.resolve(principal, body["target_id"], now, "block-ip", body["source_ip"])
        with self.store.execution_lock():
            previous = self.store.action(team=principal["team"], key=body["key"], competition=grant.competition)
            if previous:
                if previous["request_hash"] != digest(body):
                    raise Rejected("idempotency_conflict", 409)
                return self.response(previous)
            if self.store.meta("kill_switch") == "on":
                raise Rejected("kill_switch_active", 403)
            self.nft.setup()
            self._reconcile()
            expiry = min(now + body["ttl_seconds"], grant.not_after)
            if expiry - now < 10:
                raise Rejected("insufficient_lease_window", 409)
            action = {"action_id": "aia_" + hashlib.sha256(canonical([grant.competition, principal["team"], body["key"]])).hexdigest(),
                      "competition": grant.competition, "team": principal["team"], "principal": principal, "request": body, "request_hash": digest(body),
                      "created": now, "expires": expiry, "state": "requested", "context": grant.context(),
                      "tuple": {"source_ip": grant.source_ip, "target_ip": grant.target["ip_address"],
                                "protocol": grant.target["protocol"], "port": grant.target["port"]},
                      "frozen_digest": grant.target["frozen_digest"], "verification": {}}
            with self.store.transaction() as db:
                self.store.reserve(action, db)
                self.store.emit("action", action["context"], body["case_id"],
                                {"action_id": action["action_id"], "action_type": "block-ip", "state": "requested",
                                 "evidence_refs": body.get("evidence_refs", []), "decision_id": body.get("decision_id")}, now, db=db)
            applied = False
            try:
                self.state(action, "authorized")
                before = self.verifier.check(action, "before")
                action["verification"]["before"] = before
                if not before["functional_success"] or not before["control_success"]:
                    raise Rejected("baseline_not_healthy", 409)
                # A new snapshot, token revocation or assignment change during
                # the probe must stop execution, even if gateway checks passed.
                fresh = self.authority.resolve(self.tokens.authenticate(bearer, ("competitor",)), body["target_id"],
                                               self.clock(), "block-ip", body["source_ip"])
                if (fresh.target != grant.target or fresh.scope != grant.scope or fresh.not_after < action["expires"]
                        or self.store.meta("kill_switch") == "on"):
                    raise Rejected("assignment_changed", 409)
                # Persist intent before touching the kernel. Recovery of an
                # interrupted authorization always revokes; it never replays.
                applied = True
                self.nft.apply(action, self.clock())
                self.state(action, "executed")
                after = self.verifier.check(action, "after")
                action["verification"]["after"] = after
                if self.store.meta("kill_switch") == "on":
                    raise Rejected("kill_switch_active", 403)
                if after["functional_success"] or not after["control_success"] or not self.nft.contains(action):
                    raise Rejected("effect_not_verified", 409)
                self.state(action, "verified")
            except Exception as error:
                code = error.code if isinstance(error, Rejected) else "actuator_operation_failed"
                if applied:
                    # Reversal happens even if recording the executed state or
                    # the verification receipt failed because the disk filled.
                    self._reverse(action, code)
                else:
                    self.state(action, "failed", code, force=True)
            return self.response(action)

    def _reverse(self, action, reason):
        # Never let a failed audit write prevent removal of a restrictive rule.
        try:
            self.nft.remove(action)
        except Exception:
            action["retry_count"] = action.get("retry_count", 0) + 1
            action["retry_at"] = self.clock() + min(300, 2 ** min(action["retry_count"], 8))
            self.state(action, "revert_failed", "rule_removal_unconfirmed", force=True)
            raise Rejected("rule_removal_unconfirmed", 503) from None
        try:
            recovered = self.verifier.check(action, "recovery")
            action["verification"]["recovered"] = recovered
            if not recovered["functional_success"] or not recovered["control_success"]:
                action["retry_count"] = action.get("retry_count", 0) + 1
                action["retry_at"] = self.clock() + min(300, 2 ** min(action["retry_count"], 8))
                self.state(action, "revert_failed", "recovery_not_verified", force=True)
                return
        except Exception:
            action["retry_count"] = action.get("retry_count", 0) + 1
            action["retry_at"] = self.clock() + min(300, 2 ** min(action["retry_count"], 8))
            self.state(action, "revert_failed", "recovery_not_verified", force=True)
            return
        self.state(action, "reverted", reason, force=True)

    def revert(self, bearer, action_id):
        principal = self.tokens.authenticate(bearer, ("competitor", "operator"))
        with self.store.execution_lock():
            action = self.store.action(action_id=identifier(action_id))
            if not action or (principal["kind"] != "operator" and action["team"] != principal["team"]):
                raise Rejected("action_not_found", 404)
            if action["state"] not in ("reverted", "failed", "rejected"):
                self.nft.setup()
                self._reverse(action, "requested_reversal")
            return self.response(action)

    def _reconcile(self):
        for action in self.store.pending_actions():
            if action.get("retry_at", 0) > self.clock():
                continue
            reason = None
            if self.store.meta("kill_switch") == "on":
                reason = "kill_switch"
            elif action["expires"] <= self.clock():
                reason = "lease_expired"
            elif action["state"] != "verified":
                reason = "interrupted_execution"
            else:
                try:
                    grant = self.authority.resolve(action["principal"], action["request"]["target_id"], self.clock(),
                                                   "block-ip", action["request"]["source_ip"])
                    if (grant.target["ip_address"] != action["tuple"]["target_ip"]
                            or grant.target["port"] != action["tuple"]["port"]
                            or grant.target["frozen_digest"] != action["frozen_digest"]
                            or grant.scope["scope_id"] != action["context"]["assignment_id"]):
                        reason = "assignment_changed"
                    elif not self.nft.contains(action):
                        reason = "firewall_rebuilt_or_lease_expired"
                except Rejected:
                    reason = "authority_unavailable"
            if reason:
                self._reverse(action, reason)

    def dispatch(self, request):
        object_fields(request, ("operation", "token"), ("request", "action_id", "enabled", "after", "limit", "through"))
        operation = request["operation"]
        if operation == "execute":
            return self.execute(request["token"], request.get("request"))
        if operation == "revert":
            return self.revert(request["token"], request.get("action_id"))
        principal = self.tokens.authenticate(request["token"], ("operator",))
        if operation == "kill-switch-status":
            with self.store.execution_lock():
                return {"kill_switch": self.store.meta("kill_switch") == "on",
                        "unresolved_actions": len(self.store.pending_actions())}
        if operation in ("reconcile", "kill-switch"):
            if operation == "kill-switch":
                if type(request.get("enabled")) is not bool:
                    raise Rejected("invalid_kill_switch")
                if request["enabled"]:
                    # A probe holding the execution lock must not prevent the
                    # operator from stopping this or subsequent executions.
                    self.store.meta("kill_switch", "on")
            with self.store.execution_lock():
                if operation == "kill-switch":
                    # Setting the durable switch succeeds before revocation.
                    # Failure to persist a disable request cannot re-enable it.
                    self.store.meta("kill_switch", "on" if request["enabled"] else "off")
                self.nft.setup()
                self._reconcile()
                active = self.store.pending_actions()
                return {"kill_switch": self.store.meta("kill_switch") == "on", "unresolved_actions": len(active)}
        if operation == "receipts":
            return self.store.receipts(integer(request.get("after", 0), 0, 2**63 - 1), integer(request.get("limit", 200), 1, 1000))
        if operation == "acknowledge":
            self.store.acknowledge(integer(request.get("through"), 0, 2**63 - 1), self.clock())
            return {"acknowledged": request["through"]}
        if operation == "status":
            action = self.store.action(action_id=identifier(request.get("action_id")))
            if not action:
                raise Rejected("action_not_found", 404)
            return self.response(action)
        raise Rejected("unsupported_actuator_operation")


class RemoteActuator:
    """A fixed SSH/forced-command transport; cell credentials stay on stdin."""

    def __init__(self, command, operator_token, runner=run_bounded):
        self.command, self.operator_token, self.run = command, operator_token, runner

    def call(self, operation, token=None, **kwargs):
        request = {"operation": operation, "token": token or self.operator_token, **kwargs}
        result = decode_json(self.run(self.command, canonical(request), timeout=30, maximum=1024 * 1024), 1024 * 1024)
        if not isinstance(result, dict):
            raise Rejected("invalid_actuator_reply", 503)
        if "error" in result:
            raise Rejected(identifier(result["error"]), integer(result.get("status", 503), 400, 599))
        return result
