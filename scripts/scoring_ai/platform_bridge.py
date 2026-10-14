"""Translate retained AI observations into the website's producer receipt API.

The injected reader takes (opaque_cursor_or_none, limit) and returns the AI
gateway's receipts/next_cursor object. retain_proof(receipt) must durably retain
the complete original before returning. The delivery outbox supplies
enqueue_receipt(payload), cursor(name, value=None) and transaction(). Credentials
belong to the caller's per-producer HTTP clients, never to this bridge or queue.
"""

import hashlib
import math
import uuid

from .common import Rejected, canonical, digest, evidence_refs, identifier, integer, number, object_fields, timestamp


OUTPUT_ROLE = {"decision": "competitor", "action": "gateway", "runtime_check": "verifier", "source_health": "verifier"}
STATES = {"requested": "requested", "authorized": "authorized", "executed": "executed", "verified": "verified",
          "failed": "failed", "rejected": "blocked", "reverted": "reverted", "revert_failed": "failed"}


def receipt_uuid(receipt_id, kind):
    """Stable transport identity, including when an acknowledged item is retried."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "jengasec:ai-receipt:" + receipt_id + ":" + kind))


def validate_receipt(value, competition):
    fields = ("schema_version", "receipt_id", "source_id", "sequence", "kind", "occurred_at", "received_at",
              "competition", "team_id", "target_id", "assignment_id", "assignment_revision", "case_id", "payload", "integrity_hash")
    object_fields(value, fields)
    if value["schema_version"] != "ai-receipt/1.0" or value["kind"] not in OUTPUT_ROLE:
        raise Rejected("unsupported_ai_receipt", 503)
    integer(value["sequence"], 1, 2**63 - 1)
    identifier(value["source_id"])
    identifier(value["team_id"])
    if value["competition"] != competition and value["competition"] is not None:
        raise Rejected("ai_receipt_competition_mismatch", 503)
    timestamp(value["occurred_at"])
    timestamp(value["received_at"])
    if value["target_id"] is not None:
        identifier(value["target_id"])
    if value["assignment_id"] is not None:
        identifier(value["assignment_id"])
        integer(value["assignment_revision"], 1, 2**63 - 1)
    if not isinstance(value["payload"], dict):
        raise Rejected("invalid_ai_receipt_payload", 503)
    copy = dict(value)
    integrity = copy.pop("integrity_hash")
    if integrity != digest(copy):
        raise Rejected("invalid_ai_receipt_integrity", 503)
    receipt_id = copy.pop("receipt_id")
    if receipt_id != "air_" + hashlib.sha256(canonical(copy)).hexdigest():
        raise Rejected("invalid_ai_receipt_integrity", 503)
    return value


class PlatformBridge:
    """A bounded, restart-safe handoff; it does not calculate or award points.

    producer_map is a list of {team, source_id, kind, producer_id,
    clock_uncertainty_ms}. kind is the website producer kind: competitor,
    gateway or verifier. source_id is producer_source_id for sequenced cell
    records and the original receipt source_id for actuator records.
    Source-health gap_count is cumulative within its registered producer epoch.
    Its interval reports receipt-source coverage, not inferred application health.
    """

    def __init__(self, read_rows, outbox, competition, producer_map, retain_proof, *, cursor_name="ai-platform", acknowledge=None):
        self.read_rows, self.outbox, self.retain_proof = read_rows, outbox, retain_proof
        self.acknowledge = acknowledge
        self.competition = integer(competition, 1, 2**63 - 1)
        self.cursor_name = identifier(cursor_name) + ":" + str(competition)
        self.producers = {}
        if not isinstance(producer_map, list) or not callable(retain_proof) or not callable(read_rows):
            raise Rejected("invalid_ai_bridge_config", 503)
        for row in producer_map:
            object_fields(row, ("team", "source_id", "kind", "producer_id", "clock_uncertainty_ms"))
            key = (identifier(row["team"]), identifier(row["source_id"]), row["kind"])
            if row["kind"] not in ("competitor", "gateway", "verifier") or key in self.producers:
                raise Rejected("ambiguous_ai_producer_mapping", 503)
            try:
                if str(uuid.UUID(row["producer_id"])) != row["producer_id"]:
                    raise ValueError()
            except (ValueError, TypeError, AttributeError):
                raise Rejected("invalid_platform_producer_id", 503) from None
            integer(row["clock_uncertainty_ms"], 0, 3600000)
            self.producers[key] = dict(row)

    def mapping(self, receipt):
        body = receipt["payload"]
        role = OUTPUT_ROLE[receipt["kind"]]
        if receipt["kind"] == "decision" and body.get("producer_kind") != "competitor":
            raise Rejected("invalid_competitor_receipt_origin", 503)
        if receipt["kind"] in ("runtime_check", "source_health") and body.get("producer_kind") != "observer":
            raise Rejected("invalid_observer_receipt_origin", 503)
        source = body.get("producer_source_id", receipt["source_id"])
        row = self.producers.get((receipt["team_id"], source, role))
        if row is None:
            raise Rejected("unmapped_ai_producer", 503)
        return row

    @staticmethod
    def audit_reason(receipt):
        if receipt["competition"] is None:
            return "competition_unresolved"
        if receipt["kind"] == "source_health":
            return None
        try:
            if str(uuid.UUID(receipt["case_id"])) != receipt["case_id"]:
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            return "case_not_platform_issued"
        if receipt["assignment_id"] is None or receipt["target_id"] is None:
            return "assignment_unresolved"
        if receipt["kind"] == "action" and receipt["payload"].get("action_type") not in ("alert", "block-ip", "snapshot-evidence", "revert"):
            return "unsupported_action"
        return None

    def payload(self, receipt, producer, kind, measurements, references=None):
        uncertainty = producer["clock_uncertainty_ms"]
        measured = receipt["payload"].get("clock_uncertainty_seconds")
        if measured is not None:
            number(measured, 0, 3600)
            uncertainty = max(uncertainty, math.ceil(measured * 1000))
        refs = [{"family": "ai", "id": receipt["receipt_id"]}]
        for ref in references or []:
            if ref not in refs:
                refs.append(ref)
        value = {"producer_id": producer["producer_id"], "receipt_id": receipt_uuid(receipt["receipt_id"], kind),
                 "kind": kind, "observed_at": receipt["occurred_at"], "clock_uncertainty_ms": uncertainty,
                 "target_id": receipt["target_id"], "measurements": measurements, "evidence_refs": refs}
        if kind != "source_health":
            try:
                case = str(uuid.UUID(receipt["case_id"]))
            except (ValueError, TypeError, AttributeError):
                raise Rejected("ai_case_not_platform_issued", 503) from None
            if case != receipt["case_id"]:
                raise Rejected("ai_case_not_platform_issued", 503)
            value["case_id"] = case
        return value

    def source_gap_key(self, receipt):
        source = identifier(receipt["payload"].get("producer_source_id"))
        return self.cursor_name + ":source:" + receipt["team_id"] + ":" + source

    def track_source(self, receipt, staged):
        body = receipt["payload"]
        if "source_sequence" not in body:
            return
        key = self.source_gap_key(receipt)
        sequence = integer(body["source_sequence"], 1, 2**63 - 1)
        gaps = integer(body.get("sequence_gap"), 0, 1000000)
        epoch = identifier(body.get("epoch"))
        previous = staged.get(key, self.outbox.cursor(key))
        if previous and previous["epoch"] == epoch:
            if sequence < previous["sequence"] or (sequence == previous["sequence"] and previous["receipt_id"] != receipt["receipt_id"]):
                raise Rejected("conflicting_ai_source_sequence", 503)
            if sequence == previous["sequence"]:
                return
            gaps += previous["gaps"]
        staged[key] = {"epoch": epoch, "sequence": sequence, "gaps": gaps, "receipt_id": receipt["receipt_id"]}

    def normalize(self, receipt, health):
        producer = self.mapping(receipt)
        body, kind = receipt["payload"], receipt["kind"]
        if kind == "decision":
            if body.get("classification") not in ("attack", "legitimate", "abstain"):
                raise Rejected("invalid_ai_classification", 503)
            incident = identifier(body.get("incident_id"))
            refs = evidence_refs(body.get("evidence_refs"))
            if any(ref["family"] == "infrastructure" for ref in refs):
                raise Rejected("competitor_staff_reference", 503)
            action = body.get("action_id")
            if action is not None:
                identifier(action)
            results = [self.payload(receipt, producer, "decision",
                        {"decision_id": receipt["receipt_id"], "action_ids": [action] if action else [],
                         "correlation_ids": [incident], "rationale_reference": receipt["receipt_id"]}, refs)]
            if body["classification"] != "abstain":
                results.append(self.payload(receipt, producer, "detection", {"classification": body["classification"], "incident_id": incident}, refs))
            return results
        if kind == "action":
            if body.get("state") not in STATES or body.get("action_type") not in ("alert", "block-ip", "snapshot-evidence", "revert"):
                raise Rejected("unsupported_ai_action_receipt", 503)
            action_id = body.get("action_id") or "blocked:" + receipt["receipt_id"]
            identifier(action_id)
            # Effect and safety are separate trusted scenario assertions. Even
            # a verified block is not automatically a harmful induced action.
            return [self.payload(receipt, producer, "action",
                                 {"action_id": action_id, "action_type": body["action_type"], "state": STATES[body["state"]]})]
        if kind == "runtime_check":
            if body.get("check") not in ("deterministic", "model", "combined", "fallback", "scope", "budget", "reversal", "kill_switch") or type(body.get("passed")) is not bool:
                raise Rejected("invalid_ai_runtime_check", 503)
            refs = evidence_refs(body.get("evidence_refs"))
            if not refs:
                raise Rejected("ai_runtime_evidence_missing", 503)
            return [self.payload(receipt, producer, "outcome", {"runtime_checks": {body["check"]: body["passed"]}}, refs)]
        epoch = identifier(body.get("epoch"))
        sequence = integer(body.get("source_sequence"), 1, 2**63 - 1)
        gaps = integer(body.get("gap_count"), 0, 1000000)
        sequence_gap = integer(body.get("sequence_gap"), 0, 1000000)
        if type(body.get("healthy")) is not bool:
            raise Rejected("invalid_ai_source_health", 503)
        target_id = identifier(receipt["target_id"])
        key = self.cursor_name + ":health:" + producer["producer_id"] + ":" + target_id
        previous = health.get(key, self.outbox.cursor(key))
        source_key = self.source_gap_key(receipt)
        source = health.get(source_key, self.outbox.cursor(source_key))
        source_gaps = source["gaps"] if source and source["epoch"] == epoch else sequence_gap
        current = {"epoch": epoch, "sequence": sequence, "gaps": gaps, "healthy": body["healthy"],
                   "occurred_at": receipt["occurred_at"], "receipt_id": receipt["receipt_id"], "source_gaps": source_gaps}
        health[key] = current
        if previous is None or previous["epoch"] != epoch:
            return []  # No invented coverage before the first actual receipt.
        if (sequence <= previous["sequence"] or gaps < previous["gaps"]
                or not 0 < timestamp(receipt["occurred_at"]) - timestamp(previous["occurred_at"]) <= 3600):
            raise Rejected("invalid_ai_health_interval", 503)
        expected = sequence - previous["sequence"]
        known_lost = max(gaps - previous["gaps"], source_gaps - previous.get("source_gaps", 0), sequence_gap)
        integer(expected, 1, 1000000)
        expected = max(expected, known_lost)
        complete = body["healthy"] and previous["healthy"] and known_lost == 0
        values = {"start": previous["occurred_at"], "end": receipt["occurred_at"], "expected": expected,
                  "completed": expected if complete else 0, "lost": known_lost}
        return [self.payload(receipt, producer, "source_health", values,
                             [{"family": "ai", "id": previous["receipt_id"]}])]

    def step(self, *, limit=100):
        integer(limit, 1, 1000)
        previous_cursor = self.outbox.cursor(self.cursor_name)
        page = self.read_rows(previous_cursor, limit)
        object_fields(page, ("receipts", "next_cursor"))
        if (not isinstance(page["receipts"], list) or len(page["receipts"]) > limit
                or not isinstance(page["next_cursor"], str) or not 1 <= len(page["next_cursor"]) <= 2048):
            raise Rejected("invalid_ai_receipt_page", 503)
        if page["receipts"] and page["next_cursor"] == previous_cursor:
            raise Rejected("ai_receipt_cursor_stalled", 503)
        health, prepared, retained, audits, held = {}, [], 0, [], []
        for row in page["receipts"]:
            validate_receipt(row, self.competition)
            self.retain_proof(row)
            retained += 1
            self.track_source(row, health)
            reason = self.audit_reason(row)
            if reason:
                audits.append({"receipt_id": row["receipt_id"], "reason": reason})
                continue
            try:
                prepared.extend(self.normalize(row, health))
            except Rejected as error:
                held.append({"receipt_id": row["receipt_id"], "reason": error.code})
        # enqueue_receipt owns its transaction. A later enqueue failure leaves
        # the source cursor unchanged; deterministic IDs make retry harmless.
        for payload in prepared:
            self.outbox.enqueue_receipt(payload)
        if not held:
            with self.outbox.transaction():
                for key, value in health.items():
                    self.outbox.cursor(key, value)
                self.outbox.cursor(self.cursor_name, page["next_cursor"])
        if not held and self.acknowledge is not None:
            self.acknowledge(page["next_cursor"])
        return {"retained": retained, "enqueued": len(prepared), "next_cursor": page["next_cursor"] if not held else previous_cursor,
                "more_possible": not held and len(page["receipts"]) == limit,
                "cursor_advanced": not held, "audited": len(audits), "audit_reasons": audits,
                "held": len(held), "held_reasons": held}
