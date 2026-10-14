"""Resolve typed proof through the existing OBS exporters and private cache."""

import importlib.util
import pathlib
import re
import urllib.parse

from .common import Invalid, canonical, decode, digest, timestamp


ROOT = pathlib.Path(__file__).resolve().parents[2]
PREFIX = {"application": "evt_", "infrastructure": "infra_", "ai": "ai_",
          "metrics": "metric_", "scenario": "case_"}


def _module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class ProofResolver:
    def __init__(self, cache, *, loki=None, infrastructure_resources=()):
        self.cache, self.loki = cache, loki
        self.resources = set(infrastructure_resources)
        self.application = self.infrastructure = None

    def _fetch(self, family, identifier, start, end, targets):
        if self.loki is None:
            raise Invalid("referenced_telemetry_unavailable")
        if family == "application":
            namespaces = sorted({target["namespace"] for target in targets})
            if not namespaces:
                raise Invalid("referenced_target_unresolved")
            selector = "{namespace=~" + canonical("|".join(re.escape(value) for value in namespaces)).decode() + "}"
        else:
            selector = '{record_family="infrastructure_telemetry",environment="competition"}'
        query = selector + ' | json | event_id=' + canonical(identifier).decode()
        parameters = {"query": query, "start": int(start.timestamp() * 1000000000),
                      "end": int(end.timestamp() * 1000000000) - 1, "direction": "forward", "limit": 100}
        status, response = self.loki.call("/loki/api/v1/query_range?" + urllib.parse.urlencode(parameters))
        if status != 200 or response.get("status") != "success":
            raise Invalid("referenced_telemetry_unavailable")
        records = [decode(line.encode(), 65536) for stream in response.get("data", {}).get("result", [])
                   for _, line in stream.get("values", [])]
        if len(records) >= 100 or not records:
            raise Invalid("referenced_telemetry_missing_or_unbounded")
        selected = self._validate(family, identifier, records, start, end, targets)
        self.cache.retain_proof(selected, family=family, identifier=identifier)
        return selected

    def _validate(self, family, identifier, records, start, end, targets):
        if family == "application":
            if self.application is None:
                self.application = _module("scoring_application_export", "export-observability-evidence.py")
            blocked = self.application.forbidden_keys(ROOT / "contracts/telemetry-event-catalogue.yaml")
            scoped = [target for target in targets if any(record.get("namespace") == target["namespace"] for record in records)]
            if not scoped or len({(row["enterprise"], row["application"], row["namespace"]) for row in scoped}) != 1:
                raise Invalid("application_proof_wrong_target")
            selector = {key: scoped[0][key] for key in ("enterprise", "application", "namespace")}
            selector.update(telemetry_event_ids=[identifier], correlation_ids=[])
            try:
                result = self.application.select_telemetry(records, selector, start, end, blocked)
            except self.application.EvidenceError:
                raise Invalid("application_proof_invalid") from None
        else:
            if self.infrastructure is None:
                self.infrastructure = _module("scoring_infrastructure_export", "export-infrastructure-evidence.py")
            try:
                result = self.infrastructure.select(records, self.resources, start, end, "competition", {identifier})
            except ValueError:
                raise Invalid("infrastructure_proof_invalid") from None
        if len(result) != 1 or not start <= timestamp(result[0]["ts"]) < end:
            raise Invalid("proof_outside_measurement_window")
        return result[0]

    def complete(self, records, identity, start, end):
        """Include original referenced records, retaining each native ID/family.

        A native AI receipt gets a typed archive wrapper; its air_ identifier,
        original envelope and integrity hash remain unchanged inside it.
        """
        result, visited, archived = list(records), set(), set()

        def visit(value, context=None, depth=0):
            if depth > 20:
                raise Invalid("proof_reference_depth")
            if isinstance(value, list):
                for item in value:
                    visit(item, context, depth + 1)
                return
            if not isinstance(value, dict):
                return
            if all(key in value for key in ("case_id", "starts_at", "deadline_at", "target_id")):
                context = value
            for ref in value.get("evidence_refs", []):
                family, identifier = ref["family"], ref["id"]
                if family not in PREFIX or not isinstance(identifier, str):
                    raise Invalid("invalid_proof_reference")
                key = (family, identifier)
                scope = (context["case_id"], context["starts_at"], context["deadline_at"], context["target_id"]) if context else None
                visit_key = (key, scope)
                if visit_key in visited:
                    continue
                if len(visited) >= 4096:
                    raise Invalid("proof_reference_limit")
                visited.add(visit_key)
                begins = max(start, timestamp(context["starts_at"])) if context else start
                ends = min(end, timestamp(context["deadline_at"])) if context else end
                targets = [row for row in identity["targets"] if context is None or row["target_id"] == context["target_id"]]
                proof = self.cache.proof(family, identifier)
                if family in {"application", "infrastructure"}:
                    if not re.fullmatch(PREFIX[family] + "[a-f0-9]{64}", identifier):
                        raise Invalid("invalid_telemetry_reference")
                    proof = (self._validate(family, identifier, [proof], begins, ends, targets)
                             if proof is not None else self._fetch(family, identifier, begins, ends, targets))
                elif proof is None:
                    raise Invalid("referenced_source_proof_unavailable")
                elif family == "ai" and context is not None:
                    if (proof.get("competition") != self.cache.competition
                            or proof.get("target_id") != context["target_id"]
                            or proof.get("case_id") != context["case_id"]
                            or not begins <= timestamp(proof.get("occurred_at")) < ends):
                        raise Invalid("ai_proof_wrong_case")
                archive_id = identifier if identifier.startswith(PREFIX[family]) else PREFIX[family] + digest(proof)
                if key not in archived:
                    result.append({"family": family, "id": archive_id, "native_id": identifier, "record": proof})
                    archived.add(key)
                visit(proof, context, depth + 1)
            for key, item in value.items():
                if key != "evidence_refs":
                    visit(item, context, depth + 1)

        visit(records)
        # Identity, source registrations and approved exclusions are part of
        # the exact private proof, not only a list of unexplained revision IDs.
        authority = {key: identity[key] for key in ("schema_version", "competition", "revision", "captured_at",
                     "teams", "targets", "allocations", "scopes", "producers", "exclusions") if key in identity}
        result.append({"family": "scenario", "id": "case_" + digest(authority), "identity": authority})
        return result
