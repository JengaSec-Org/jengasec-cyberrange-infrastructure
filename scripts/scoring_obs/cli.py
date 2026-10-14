"""Run authenticated measurement and score delivery on existing OBS capacity."""

import argparse
import concurrent.futures
import datetime as dt
import fcntl
import math
import os
import pathlib
import sqlite3
import sys
import threading
import time
import urllib.parse

from .cache import SourceCache
from .common import Invalid, atomic, canonical, decode, digest, private_directory, secret, timestamp, utc
from .evidence import ProofResolver
from .facts import build
from .outbox import Full, Outbox
from .probes import clock_uncertainty_ms, measure, receipt
from .publisher import archive, deliver
from .transport import Client, Failure


CRITERIA = {
    "application_blue": ("availability", "detected", "response", "unfound"),
    "ai_blue": ("precision", "recall", "correlation", "decisions", "safety"),
    "ai_red": ("missed", "false", "breadth"),
}


def load_config(path):
    import jsonschema

    config = decode(pathlib.Path(path).read_bytes(), 65536)
    schema = decode((pathlib.Path(__file__).resolve().parents[2] / "contracts/scoring-collector.schema.json").read_bytes())
    try:
        jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(config)
    except jsonschema.ValidationError:
        raise Invalid("invalid_collector_config") from None
    if config.get("schema_version") != "scoring-collector/1.0":
        raise Invalid("collector_config_version")
    if type(config.get("competition")) is not int or config["competition"] <= 0:
        raise Invalid("invalid_competition")
    if timestamp(config["window_start"]) >= timestamp(config["window_end"]):
        raise Invalid("invalid_competition_window")
    if type(config.get("source_cache_bytes")) is not int or config["source_cache_bytes"] < 1048576:
        raise Invalid("explicit_source_cache_budget_required")
    return config


class Collector:
    def __init__(self, config):
        self.config = config
        self.state = private_directory(config["state_dir"])
        self.start, self.end = timestamp(config["window_start"]), timestamp(config["window_end"])
        self.competition = config["competition"]
        self.platform = Client(config["platform_url"], {"X-Feed-Token": secret(config["feed_token_file"])},
                               loopback_http=config.get("allow_loopback_http", False), timeout=5)
        self.outbox = Outbox(self.state / "delivery.sqlite3")
        self.cache = SourceCache(self.state / "sources.sqlite3", self.competition, max_bytes=config["source_cache_bytes"])
        self.producers = {}
        for entry in config.get("producers", {}).values():
            self.producers[entry["id"]] = Client(config["platform_url"], {"Authorization": "Bearer " + secret(entry["token_file"])},
                                                 loopback_http=config.get("allow_loopback_http", False), timeout=5)
        self.loki = None
        if config.get("loki_url"):
            headers = {"X-Scope-OrgID": "staff"}
            if config.get("loki_headers_file"):
                source = pathlib.Path(config["loki_headers_file"])
                if source.stat().st_mode & 0o077 or source.is_symlink():
                    raise Invalid("loki_credentials_not_private")
                headers.update(decode(source.read_bytes(), 8192))
            self.loki = Client(config["loki_url"], headers, loopback_http=True)
        self.proof = ProofResolver(self.cache, loki=self.loki,
                                   infrastructure_resources=config.get("infrastructure_resources", []))
        self.ai_bridge = self.ai_client = None
        if config.get("ai_gateway"):
            from scoring_ai.platform_bridge import PlatformBridge
            ai = config["ai_gateway"]
            self.ai_prefix = ai.get("api_prefix", "/api/v1/scoring")
            self.ai_client = Client(ai["url"], {"Authorization": "Bearer " + secret(ai["operator_token_file"])},
                                    loopback_http=config.get("allow_loopback_http", False), timeout=5)
            if any(row["producer_id"] not in self.producers for row in ai["producer_map"]):
                raise Invalid("ai_producer_credentials_missing")
            self.ai_bridge = PlatformBridge(self._ai_rows, self.outbox, self.competition,
                                            ai["producer_map"], self.cache.retain_proof, acknowledge=self._ai_ack)

    def _ai_ack(self, cursor):
        status, _ = self.ai_client.call(self.ai_prefix + "/receipts/ack", {"cursor": cursor})
        if status != 200:
            raise Invalid("ai_acknowledgement_failed")

    def _ai_rows(self, cursor, limit):
        while True:
            parameters = {"limit": limit}
            if cursor:
                parameters["after"] = cursor
            try:
                status, page = self.ai_client.call(self.ai_prefix + "/receipts?" + urllib.parse.urlencode(parameters))
            except (Failure, Invalid) as error:
                large = (isinstance(error, Failure) and error.code == 413) or (isinstance(error, Invalid) and str(error) == "body_too_large")
                if large and limit > 1:
                    limit = max(1, limit // 2)
                    continue
                raise
            if status != 200:
                raise Invalid("ai_source_unavailable")
            return page

    def close(self):
        self.outbox.close()
        self.cache.close()

    def identity(self, *, historical_end=None, now=None):
        now = now or dt.datetime.now(dt.timezone.utc)
        parameters = {"competition": self.competition}
        if historical_end is not None:
            parameters.update(start=utc(self.start), end=utc(historical_end))
        snapshot_path = self.state / "identity.json"
        try:
            status, snapshot = self.platform.call("/api/scoring/identity/?" + urllib.parse.urlencode(parameters))
            if (status != 200 or snapshot.get("schema_version") != "scoring-identity/2.0"
                    or snapshot.get("competition", {}).get("id") != self.competition
                    or snapshot.get("historical") is not (historical_end is not None)
                    or not timestamp(snapshot["captured_at"]) <= now < timestamp(snapshot["expires_at"])
                    or (timestamp(snapshot["expires_at"]) - timestamp(snapshot["captured_at"])).total_seconds() > 120):
                raise Invalid("unusable_identity_snapshot")
            if historical_end is None:
                atomic(snapshot_path, canonical(snapshot))
            return snapshot
        except (Failure, Invalid, KeyError, TypeError):
            # Actions must not keep using a prior authority after refresh fails.
            if historical_end is None:
                snapshot_path.unlink(missing_ok=True)
            raise

    def collect(self):
        limit = 1000
        for _ in range(100):
            parameters = {"competition": self.competition, "after": self.cache.cursor("next_cursor"),
                          "cases_after": self.cache.cursor("cases_next_cursor"), "limit": limit}
            try:
                _, page = self.platform.call("/api/scoring/receipts/?" + urllib.parse.urlencode(parameters))
            except (Failure, Invalid) as error:
                large = (isinstance(error, Failure) and error.code == 413) or (isinstance(error, Invalid) and str(error) == "body_too_large")
                if large and limit > 1:
                    limit = max(1, limit // 2)
                    continue
                raise
            self.cache.ingest(page)
            if not page["has_more"] and not page["cases_has_more"]:
                return True
        return False

    def _readiness(self, team, criterion, end, status, reason):
        self.platform.call("/api/scoring/readiness/", {
            "competition": self.competition, "team": team, "criterion": criterion,
            "policy_version": "main-scoring/1.0", "window": {"start": utc(self.start), "end": utc(end)},
            "status": status, "reason_code": reason})

    def score(self, *, now=None):
        from jengasec_scoring_policy import calculate

        now = now or dt.datetime.now(dt.timezone.utc)
        watermark = now - dt.timedelta(seconds=120)
        end = min(self.end, dt.datetime.fromtimestamp(math.floor(watermark.timestamp() / 60) * 60, dt.timezone.utc))
        if watermark >= self.end:
            end = self.end
        if end <= self.start:
            return {"state": "collecting"}
        snapshot = self.identity(historical_end=end, now=now)
        if not self.collect():
            return {"state": "catching_up"}
        cases, probes, health = self.cache.window(self.start, end)
        readiness = {}
        teams = {row["team"]: row for row in snapshot["teams"]}
        for team, item in teams.items():
            side = item["track"] + "_" + item["side"]
            if side not in CRITERIA:
                continue
            targets = [row for row in snapshot["targets"] if row["team"] == team]
            assigned = {row["target_id"] for row in snapshot.get("scopes", []) if row.get("team") == team}
            relevant_cases = [case for case in cases if team in {case.get("actor_team"), case.get("defender_team", case.get("target_team"))}]
            assigned.update(case["target_id"] for case in relevant_cases)
            revisions = sorted({row["revision"] for section in ("teams", "targets", "scopes", "allocations")
                                for row in snapshot.get(section, []) if row.get("team") == team or row.get("target_id") in assigned}
                               | {case["assignment_revision"] for case in relevant_cases
                                  if "assignment_revision" in case and timestamp(case["deadline_at"]) <= end})
            if not revisions:
                continue
            for criterion in CRITERIA[side]:
                key = team + ":" + criterion
                try:
                    facts, quality, records = build(side, criterion, team, cases, probes, health, self.start, end,
                                                    target_ids=[row["target_id"] for row in targets],
                                                    exclusions=snapshot.get("exclusions", []), target_intervals=targets)
                    result = calculate(side, criterion, facts, quality, policy_version="main-scoring/1.0")
                    if result.status != "ready":
                        readiness[key] = "insufficient_data"
                        self._readiness(team, criterion, end, "insufficient_data", "measurement_incomplete")
                        continue
                    archived = {"policy_version": "main-scoring/1.0", "side": side, "criterion": criterion,
                                "window": {"start": utc(self.start), "end": utc(end)}, "facts": facts,
                                "quality": quality, "assignment_revisions": revisions}
                    semantic = digest({key: value for key, value in archived.items() if key != "window"}
                                      | {"final_window": end == self.end})
                    cursor_key = "score_input:" + key
                    if self.outbox.cursor(cursor_key) == semantic:
                        readiness[key] = "unchanged"
                        continue
                    records = self.proof.complete(records, snapshot, self.start, end)
                    references = archive(self.platform, self.competition, team, archived, records,
                                         ["scoring-receipts/1.0; immutable server sequence; UTC half-open window"])
                    row = {"team": team, "stage": "main", "criterion": criterion, "key": "main:" + criterion,
                           "policy_version": archived["policy_version"], "window": archived["window"],
                           "facts": facts, "quality": quality, "assignment_revisions": revisions,
                           "evidence": references, "marks": str(result.marks)}
                    self.outbox.enqueue_score(self.competition, row)
                    self.outbox.cursor(cursor_key, semantic)
                    readiness[key] = "queued"
                except Full:
                    raise
                except (Invalid, Failure, ValueError, KeyError):
                    readiness[key] = "publication_failed"
                    self._readiness(team, criterion, end, "publication_failed", "source_or_archive_unavailable")
        return {"state": "running", "criteria": readiness}

    def probe(self, *, now=None):
        now = now or dt.datetime.now(dt.timezone.utc)
        if not self.start <= now < self.end:
            return
        snapshot = self.identity(now=now)
        uncertainty = clock_uncertainty_ms()
        if uncertainty > 2000:
            raise Invalid("observer_clock_untrusted")
        targets = {row["target_id"]: row for row in snapshot["targets"]
                   if timestamp(row["valid_from"]) <= now
                   and (not row.get("valid_until") or now < timestamp(row["valid_until"]))}
        work = []
        for target_id, spec in self.config.get("probes", {}).items():
            target = targets.get(target_id)
            if target is None:
                continue
            producer = self.config.get("producers", {}).get(target["team"])
            if spec.get("producer"):
                producer = self.config.get("producers", {}).get(spec["producer"])
            if producer is None:
                continue
            slot_key = "probe:" + target_id
            slot = math.floor(now.timestamp() / 15)
            if (self.outbox.cursor(slot_key) or -1) >= slot:
                continue
            work.append((target, spec, producer["id"], slot_key, slot))
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(32, max(1, len(work)))) as pool:
            futures = [(entry, pool.submit(measure, entry[0], entry[1])) for entry in work]
            for (target, spec, producer, slot_key, slot), future in futures:
                success = future.result()
                observation = receipt(producer, target, success, now, uncertainty)
                payload = None
                if self.loki:
                    line = dict(observation, schema_version="scoring-observation/1.0", competition=self.competition,
                                team=target["team"], namespace=target["namespace"])
                    payload = {"streams": [{"stream": {"record_family": "competition_measurement",
                                "source": "functional_probe", "namespace": target["namespace"]},
                                "values": [[str(int(now.timestamp() * 1000000000)), canonical(line).decode()]]}]}
                self.outbox.enqueue_probe(observation, slot_key, slot, payload)

    def cycle(self, *, do_score=True):
        delivered = deliver(self.outbox, self.platform, loki=self.loki, producer=self.producers)
        ai_state = None
        if self.ai_bridge is not None:
            from scoring_ai.common import Rejected
            try:
                ai_state = self.ai_bridge.step()
            except (Rejected, Invalid, Failure):
                ai_state = {"state": "held", "reason": "ai_source_unavailable"}
            delivered += deliver(self.outbox, self.platform, loki=self.loki, producer=self.producers)
        result = self.score() if do_score else {"state": "probing"}
        delivered += deliver(self.outbox, self.platform, loki=self.loki, producer=self.producers)
        result.update(delivered=delivered, outbox=self.outbox.stats())
        if ai_state is not None:
            result["ai"] = ai_state
        atomic(self.state / "status.json", canonical(result))
        return result

    def metrics(self):
        stats = self.outbox.stats()
        lines = ["# TYPE jengasec_scoring_pending_rows gauge",
                 "jengasec_scoring_pending_rows " + str(stats["rows"]),
                 "# TYPE jengasec_scoring_pending_bytes gauge",
                 "jengasec_scoring_pending_bytes " + str(stats["bytes"]),
                 "# TYPE jengasec_scoring_rejected_rows gauge",
                 "jengasec_scoring_rejected_rows " + str(stats["rejected"]),
                 "# TYPE jengasec_scoring_backpressure gauge",
                 "jengasec_scoring_backpressure " + str(int(stats["warning"]))]
        if self.config.get("metrics_file"):
            atomic(self.config["metrics_file"], ("\n".join(lines) + "\n").encode(), 0o644)


def _probe_worker(config, stop):
    # Measurement has its own database connection and schedule. A delayed
    # website/archive request must not prevent the next functional check.
    collector = Collector(config)
    try:
        while not stop.is_set():
            began = time.monotonic()
            try:
                collector.probe()
                status = {"state": "running", "checked_at": utc(dt.datetime.now(dt.timezone.utc))}
            except (Invalid, Failure, OSError, sqlite3.DatabaseError, ValueError, KeyError):
                status = {"state": "held", "reason": "probe_source_unavailable"}
            try:
                atomic(collector.state / "probes.json", canonical(status))
            except OSError:
                pass  # The missing heartbeat remains visible to operations.
            stop.wait(max(0, 15 - (time.monotonic() - began)))
    finally:
        collector.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    config = load_config(args.config)
    if args.check:
        from jengasec_scoring_policy import POLICY_VERSION
        if POLICY_VERSION != "main-scoring/1.0":
            raise Invalid("policy_version_mismatch")
        client = Client(config["platform_url"], {"X-Feed-Token": secret(config["feed_token_file"])},
                        loopback_http=config.get("allow_loopback_http", False), timeout=5)
        now = dt.datetime.now(dt.timezone.utc)
        start, end = timestamp(config["window_start"]), timestamp(config["window_end"])
        parameters = {"competition": config["competition"]}
        if not start <= now < end:
            parameters.update(start=utc(start), end=utc(min(end, start + dt.timedelta(seconds=1))))
        status, snapshot = client.call("/api/scoring/identity/?" + urllib.parse.urlencode(parameters))
        if (status != 200 or snapshot.get("schema_version") != "scoring-identity/2.0"
                or snapshot.get("competition", {}).get("id") != config["competition"]
                or snapshot.get("historical") is not ("start" in parameters)
                or not timestamp(snapshot["captured_at"]) <= now < timestamp(snapshot["expires_at"])
                or (timestamp(snapshot["expires_at"]) - timestamp(snapshot["captured_at"])).total_seconds() > 120):
            raise Invalid("unusable_identity_snapshot")
        return 0
    state = private_directory(config["state_dir"])
    lock = open(state / "collector.lock", "a")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise Invalid("collector_already_running") from None
    collector = Collector(config)
    stop, worker = threading.Event(), None
    try:
        if not args.once:
            worker = threading.Thread(target=_probe_worker, args=(config, stop), daemon=True)
            worker.start()
        next_score = 0
        while True:
            began = time.monotonic()
            try:
                if args.once:
                    collector.probe()
                score_due = began >= next_score
                result = collector.cycle(do_score=score_due)
                if score_due:
                    next_score = began + 60
                collector.metrics()
                print(canonical(result).decode(), flush=True)
            except (Invalid, Failure, OSError, sqlite3.DatabaseError, ValueError, KeyError):
                result = {"state": "held", "reason": "source_or_delivery_unavailable", "outbox": collector.outbox.stats()}
                atomic(collector.state / "status.json", canonical(result))
                collector.metrics()
                print(canonical(result).decode(), flush=True)
                if args.once:
                    return 1
            if args.once:
                return 0
            time.sleep(max(0, 15 - (time.monotonic() - began)))
    finally:
        stop.set()
        if worker:
            worker.join(timeout=12)
        collector.close()
        lock.close()


if __name__ == "__main__":
    sys.exit(main())
