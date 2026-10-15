"""Publish immutable evidence before sending versioned score decisions."""

from .common import Invalid, canonical, digest
from .transport import Failure


def evidence_records(records):
    for row in records:
        if row.get("family") in {"application", "infrastructure", "ai", "scenario", "metrics"} and "id" in row:
            yield row
            continue
        if row.get("kind") == "probe":
            prefix, record_family = "metric_", "metrics"
        elif "case_id" in row or row.get("kind") == "source_health":
            prefix, record_family = "case_", "scenario"
        else:
            prefix, record_family = "ai_", "ai"
        yield {"family": record_family, "id": prefix + digest(row), "receipt": row}


def archive(client, competition, team, snapshot, records, queries=()):
    """Archive every source receipt in bounded chunks with one input snapshot."""
    header = {"schema_version": "scoring-evidence/1.0", "competition": competition,
              "team": team, "family": "mixed", "snapshot": snapshot, "queries": list(queries)}
    chunks, chunk, size = [], [], len(canonical(header))
    for record in evidence_records(records):
        length = len(canonical(record)) + 1
        if length > 500000:
            raise Invalid("evidence_record_too_large")
        if (size + length > 750000 or len(chunk) >= 1000) and chunk:
            chunks.append(chunk)
            chunk, size = [], len(canonical(header))
        chunk.append(record)
        size += length
    if chunk:
        chunks.append(chunk)
    if not chunks:
        raise Invalid("no_source_evidence")
    if len(chunks) > 128:
        raise Invalid("evidence_archive_limit")
    references = []
    for chunk in chunks:
        body = dict(header, records=chunk)
        status, reply = client.call("/api/scoring/evidence/", body)
        if status not in {200, 201} or reply.get("input_sha256") != digest(snapshot) or reply.get("sha256") != digest(body):
            raise Invalid("archive_receipt_mismatch")
        references.append({"id": reply["id"], "sha256": reply["sha256"]})
    return references


def deliver(outbox, platform, *, loki=None, producer=None, now=None):
    """Acknowledge each row only when the receiver confirms its exact revision."""
    count = 0
    for item in outbox.due(now=now):
        try:
            if item["kind"] == "observation":
                if loki is None:
                    raise Failure(0, "loki_not_configured")
                status, _ = loki.call("/loki/api/v1/push", item["payload"])
                if status != 204:
                    raise Invalid("unexpected_loki_response")
                outbox.finish(item["id"], "accepted")
                count += 1
                continue
            if item["kind"] == "receipt":
                if producer is None:
                    raise Failure(0, "producer_not_configured")
                client = producer.get(item["payload"]["producer_id"]) if isinstance(producer, dict) else producer
                if client is None:
                    raise Failure(0, "producer_not_configured")
                status, response = client.call("/api/scoring/receipts/", item["payload"])
                if status not in {200, 201} or response.get("receipt_id") != item["payload"]["receipt_id"]:
                    raise Invalid("unexpected_producer_response")
                outbox.finish(item["id"], "accepted")
                count += 1
                continue
            status, response = platform.call("/api/feed/", item["payload"])
            if status not in {200, 202}:
                raise Invalid("unexpected_feed_response")
            results = response.get("outcomes")
            if not isinstance(results, list) or len(results) != 1:
                raise Invalid("missing_row_outcome")
            result, sent = results[0], item["payload"]["scores"][0]
            if not isinstance(result, dict) or result.get("index") != 0:
                raise Invalid("row_outcome_mismatch")
            # Per-row successful outcomes must identify what was acknowledged.
            outcome = result.get("status")
            if outcome in {"accepted", "duplicate"}:
                if result.get("key") != sent["key"] or result.get("revision") != sent["revision"]:
                    raise Invalid("revision_receipt_mismatch")
                outbox.finish(item["id"], outcome)
                count += 1
            elif outcome in {"rejected", "pending", "override_hold"}:
                # Receiver text is not copied into logs or local labels.
                outbox.fail(item["id"], "row_rejected", permanent=result.get("retryable") is not True, now=now)
            else:
                raise Invalid("unknown_row_outcome")
        except Failure as failure:
            permanent = failure.code in {400, 405, 409, 413, 422}
            outbox.fail(item["id"], failure.reason, permanent=permanent, now=now, retry_after=failure.retry_after)
            if failure.code == 0 or failure.code in {401, 403, 429} or failure.code >= 500:
                break  # One unavailable destination must not stall measurement.
        except (Invalid, KeyError, TypeError, ValueError):
            outbox.fail(item["id"], "invalid_receiver_response", now=now)
    return count
