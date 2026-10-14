#!/usr/bin/env python3
"""Exercise the real website services with local HTTP measurement fixtures.

Requires JENGASEC_PLATFORM_SOURCE and that checkout's test dependencies. These
are isolated database/clock fixtures, not acceptance evidence for a live event.
"""

import datetime as dt
import hashlib
import http.server
import ipaddress
import json
import os
import pathlib
import socket
import sys
import tempfile
import threading
import uuid
from decimal import Decimal
from unittest.mock import patch


ROOT = pathlib.Path(__file__).resolve().parents[2]
PLATFORM = os.environ.get("JENGASEC_PLATFORM_SOURCE")
if not PLATFORM or not (pathlib.Path(PLATFORM) / "manage.py").is_file():
    raise SystemExit("Set JENGASEC_PLATFORM_SOURCE to the compatible website checkout.")
sys.path[:0] = [str(ROOT / "scripts"), PLATFORM]
os.environ["DJANGO_SETTINGS_MODULE"] = "config.test_settings"

import django
django.setup()

from django.contrib.auth import get_user_model
from django.test import Client as DjangoClient, TestCase, override_settings
from django.test.runner import DiscoverRunner
from django.utils import timezone

from accounts.models import Team, TeamMember
from competitions.models import AttackScenario, Competition, CompetitionObjective, TargetAssignment
from cyberrange.models import Finding, RangeApplication, WireGuardProfile
from deployments.models import AppSubmission
from jengasec_scoring_policy import calculate
from scoring.enrollment import enroll_policy
from scoring.models import ScoreEvent, ScoreRevision, ScoringEvidence
from services import deployment_service, scoring_service
from services.scoring_evidence import verified_bytes
from services.scoring_identity import refresh_identity
from services.scoring_scenarios import freeze_scenario, issue_case, record_receipt, register_producer

from scoring_obs.cli import Collector
from scoring_obs.common import canonical, timestamp, utc
from scoring_obs.facts import build
from scoring_obs.publisher import deliver
from scoring_obs.transport import Failure


class Website:
    """Use real routes/auth/transactions without a production web listener."""
    def __init__(self, headers):
        self.client, self.headers = DjangoClient(), headers

    def call(self, path, body=None):
        response = self.client.generic("POST" if body is not None else "GET", path,
            canonical(body) if body is not None else b"", content_type="application/json", **self.headers)
        if response.status_code >= 400:
            raise Failure(response.status_code, "http_" + str(response.status_code))
        return response.status_code, response.json() if response.content else {}


@override_settings(FEED_TOKEN="integration-feed-credential")
class ScoringPlatformIntegration(TestCase):
    def setUp(self):
        self.zero = timestamp("2026-01-01T12:00:00Z")
        self.start, self.end = self.zero + dt.timedelta(seconds=60), self.zero + dt.timedelta(seconds=120)
        clock = patch("django.utils.timezone.now", return_value=self.zero)
        self.clock = clock.start()
        self.addCleanup(clock.stop)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = pathlib.Path(self.directory.name)
        self.staff = get_user_model().objects.create_user("reviewer", is_staff=True)
        self.competition = Competition.objects.create(name="Local scoring fixture", status="in_progress",
            start_date=self.zero.date(), end_date=self.zero.date())
        self.app = self.team("application", "blue", 1, "APP01", "a")
        self.peer = self.team("application", "blue", 2, "APP01", "b")
        self.app_red = self.team("application", "red", 3, "RED01", "a")
        self.ai = self.team("ai", "blue", 4, "AI01", "a")
        self.ai_red = self.team("ai", "red", 5, "AIRED01", "a")
        self.targets, self.submissions, self.servers = {}, [], {}
        address = socket.gethostbyname(socket.gethostname())
        if ipaddress.ip_address(address).is_loopback:
            self.skipTest("The combined source-identity fixture requires an assigned local address.")
        for team in (self.app, self.peer, self.ai):
            target_address, port = address, 8080
            if team == self.peer:
                # The paired remote workload is represented by registered
                # observer receipts. No traffic is sent to this fixture IP.
                target_address = "192.0.2.10" if address != "192.0.2.10" else "192.0.2.11"
            else:
                server = self.server(address)
                self.servers[team.pk] = server
                port = server.server_port
            if team.track == "application":
                team.service_ip = target_address
                team.save(update_fields=["service_ip", "updated_at"])
            target = RangeApplication.objects.create(competition=self.competition, team=team,
                application_instance_id=f"ENT-{team.enterprise.upper()}/{team.cell_id}",
                enterprise=f"ENT-{team.enterprise.upper()}", application=team.cell_id,
                namespace=team.namespace, service_name="Local fixture", ip_address=target_address,
                port=port, status="live", image_digest="sha256:" + hashlib.sha256(str(team.pk).encode()).hexdigest(),
                verified_at=self.zero)
            self.targets[team.pk] = target
            if team.track == "application":
                submission = AppSubmission.objects.create(competition=self.competition, team=team,
                    attempt=1, image_reference="registry.invalid/fixture:v1", registry_username="fixture", port=port)
                deployment_service.record_status(submission, "healthy", resolved_digest=target.image_digest)
                deployment_service.record_freeze(submission, "registry.invalid/frozen@" + target.image_digest)
                deployment_service.record_artifact(submission, target.image_digest)
                self.submissions.append(submission)
        for index, (actor, defender) in enumerate(((self.app_red, self.app), (self.ai_red, self.ai)), 1):
            WireGuardProfile.objects.create(user=actor.captain, team=actor, address=f"10.60.{index}.2/32")
            TargetAssignment.objects.create(competition=self.competition, red_team=actor, target_team=defender, is_active=True)
        enroll_policy(self.competition, window_start=self.start, window_end=self.end,
                      archive_budget_bytes=16 * 1024 * 1024, recorded_by=self.staff)
        self.producers, self.tokens = {}, {}
        for kind in ("runner", "verifier", "gateway"):
            self.register(kind, kind)
        for team in (self.app, self.peer, self.ai):
            self.register("competitor-" + str(team.pk), "competitor", team)
        self.cases = []
        self.application_cases()
        self.ai_cases()
        feed_path = self.root / "feed.token"
        feed_path.write_text("integration-feed-credential")
        feed_path.chmod(0o600)
        self.config = {"schema_version": "scoring-collector/1.0", "competition": self.competition.pk,
            "platform_url": "https://platform.invalid", "feed_token_file": str(feed_path),
            "window_start": utc(self.start), "window_end": utc(self.end),
            "state_dir": str(self.root / "state"), "source_cache_bytes": 16 * 1024 * 1024,
            "producers": {}, "probes": {}}
        for alias, producer in self.producers.items():
            token_path = self.root / (alias + ".token")
            token_path.write_text(self.tokens[alias])
            token_path.chmod(0o600)
            self.config["producers"][alias] = {"id": str(producer.producer_id), "token_file": str(token_path)}
        for team in (self.app,):
            self.config["probes"][self.targets[team.pk].application_instance_id] = {
                "producer": "verifier", "health_path": "/healthz", "functional_path": "/functional",
                "assertions": [{"path": ["serving"], "equals": True}]}
        self.collector = Collector(self.config)
        self.addCleanup(self.collector.close)
        self.collector.platform = Website({"HTTP_X_FEED_TOKEN": "integration-feed-credential"})
        self.collector.producers = {str(producer.producer_id): Website({"HTTP_AUTHORIZATION": "Bearer " + self.tokens[alias]})
                                   for alias, producer in self.producers.items()}

    def team(self, track, side, number, cell, enterprise):
        user = get_user_model().objects.create_user("captain-" + str(number))
        team = Team.objects.create(competition=self.competition, team_name="Fixture " + str(number),
            team_identifier=f"JS26-{'B' if side == 'blue' else 'R'}-{number:03}", track=track, team_type=side,
            enterprise=enterprise, cell_id=cell, namespace=f"jengasec-ent-{enterprise}-{cell.lower()}",
            status="approved", captain=user)
        TeamMember.objects.create(team=team, user=user, student_name="Fixture", email=f"fixture-{number}@example.invalid", role="captain")
        return team

    def server(self, address):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                raw = canonical({"serving": self.path == "/healthz" or self.server.functional})
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, *args):
                pass
        server = http.server.ThreadingHTTPServer((address, 0), Handler)
        server.functional = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    def register(self, alias, kind, team=None):
        producer, token = register_producer(self.competition, kind=kind, team=team,
            valid_until=self.end + dt.timedelta(hours=1), registered_by=self.staff)
        self.producers[alias], self.tokens[alias] = producer, token

    def issue(self, team, scenario, code, actor=None):
        objective = CompetitionObjective.objects.create(team=team, code=code, name="Measured fixture objective")
        case = issue_case(self.competition, objective=objective, scenario_version=scenario,
            target_id=self.targets[team.pk].application_instance_id, starts_at=self.start, deadline_at=self.end,
            opportunity_key=code, issued_by=self.staff, actor_team=actor)
        self.cases.append(case)
        return case

    def version(self, track, code, label, family, keys):
        scenario = AttackScenario.objects.create(code=code, track=track, name="Fixture", objective="Measured result", success_condition="Observed result")
        return freeze_scenario(scenario, version=1, label=label, family=family,
            assertions=[{"key": key, "operator": "eq", "expected": True} for key in keys], issued_by=self.staff)

    def application_cases(self):
        version = self.version("application", "APP-FIXTURE", "attack", "application",
                               ["paired_build_verified", "no_valid_finding"])
        self.app_case = self.issue(self.app, version, "paired-app", self.app_red)
        self.peer_case = self.issue(self.peer, version, "paired-app")

    def ai_cases(self):
        version = self.version("ai", "AI-ATTACK", "attack", "evasion", ["objective_reached"])
        self.ai_attack = [self.issue(self.ai, version, "ai-attack-" + str(index), self.ai_red) for index in range(3)]
        version = self.version("ai", "AI-INDUCED", "legitimate", "injection", ["action_verified", "induced", "harmful"])
        self.ai_harm = self.issue(self.ai, version, "ai-induced", self.ai_red)

    def send(self, alias, kind, values, *, case=None, target=None, offset=30):
        producer = self.producers[alias]
        payload = {"producer_id": str(producer.producer_id), "receipt_id": str(uuid.uuid4()), "kind": kind,
                   "observed_at": utc(self.start + dt.timedelta(seconds=offset)), "clock_uncertainty_ms": 1,
                   "measurements": values, "evidence_refs": []}
        if case:
            payload["case_id"] = str(case.case_id)
        if target:
            payload["target_id"] = target.application_instance_id
        record_receipt(producer, payload)

    def exercise(self):
        # Contiguous artifact confirmations are independent of functional
        # failures. No identity service or policy function is mocked here.
        for offset in (0, 15, 30, 45):
            self.clock.return_value = self.start + dt.timedelta(seconds=offset)
            if offset == 30:
                for submission in self.submissions:
                    deployment_service.record_artifact(submission, submission.resolved_digest)
                target = self.targets[self.ai.pk]
                target.verified_at = self.clock.return_value
                target.save(update_fields=["verified_at", "updated_at"])
            self.servers[self.app.pk].functional = offset != 30
            with patch("scoring_obs.cli.clock_uncertainty_ms", return_value=1):
                self.collector.probe(now=self.start + dt.timedelta(seconds=offset))
        self.clock.return_value = self.end
        self.assertEqual(deliver(self.collector.outbox, self.collector.platform, producer=self.collector.producers), 4)
        peer_target = self.targets[self.peer.pk]
        for offset in (0, 15, 30, 45):
            self.send("verifier", "probe", {"successful": True, "expected": 1, "completed": 1,
                      "target_digest": peer_target.image_digest}, target=peer_target, offset=offset)
        for case in self.cases:
            self.send("runner", "delivered", {"delivered": True}, case=case, offset=1)
        for case in (self.app_case, self.peer_case):
            self.send("verifier", "outcome", {"objective_reached": False, "protected": True, "legitimate_ok": True,
                "response_authorized": True, "response_started_at": utc(self.start + dt.timedelta(seconds=10)), "mitigated": True}, case=case)
            self.send("competitor-" + str(case.defender_team_id), "detection",
                      {"classification": "attack", "incident_id": "application-incident"}, case=case, offset=10)
        for index, case in enumerate(self.ai_attack):
            self.send("verifier", "outcome", {"objective_reached": index == 2, "legitimate_ok": True,
                                               "incident_id": "incident-pair" if index < 2 else "incident-miss"}, case=case)
            if index < 2:
                self.send("competitor-" + str(self.ai.pk), "detection",
                          {"classification": "attack", "incident_id": "incident-pair"}, case=case, offset=index * 15)
        action_id = "aia_fixture"
        self.send("verifier", "outcome", {"objective_reached": False, "legitimate_ok": True,
            "action_id": action_id, "action_verified": True, "induced": True, "harmful": True, "recovered": True}, case=self.ai_harm)
        self.send("competitor-" + str(self.ai.pk), "detection", {"classification": "attack", "incident_id": "false-incident"}, case=self.ai_harm, offset=20)
        for state in ("executed", "verified", "reverted"):
            self.send("gateway", "action", {"action_id": action_id, "action_type": "block-ip", "state": state}, case=self.ai_harm)
        for case in self.ai_attack + [self.ai_harm]:
            self.send("verifier", "decision", {"context_valid": True, "evidence_valid": True, "consistency_valid": True}, case=case)
        for check in ("deterministic", "model", "combined", "fallback", "scope", "budget", "reversal", "kill_switch"):
            self.send("verifier", "outcome", {"runtime_checks": {check: True}}, case=self.ai_attack[0])
        for target in self.targets.values():
            for alias in ("runner", "verifier", "gateway"):
                self.send(alias, "source_health", {"start": utc(self.start), "end": utc(self.end), "expected": 4,
                          "completed": 4, "lost": 0}, target=target, offset=60)
        self.clock.return_value = self.end + dt.timedelta(seconds=120)
        result = self.collector.score(now=self.clock.return_value)
        self.assertTrue(result["criteria"], result)
        self.assertNotIn("publication_failed", result["criteria"].values(), result)
        self.assertNotIn("insufficient_data", result["criteria"].values(), result)
        self.assertEqual(deliver(self.collector.outbox, self.collector.platform), 16)

    def test_all_role_receipts_reproduce_marks_and_corrections(self):
        self.exercise()
        self.assertEqual(scoring_service.stage_totals(self.app)["main"], Decimal("37.00"))
        self.assertEqual(scoring_service.stage_totals(self.ai)["main"], Decimal("32.33"))
        self.assertEqual(scoring_service.stage_totals(self.ai_red)["main"], Decimal("8.00"))
        count = ScoreRevision.objects.count()
        self.collector.score(now=self.clock.return_value)
        self.assertEqual(self.collector.outbox.stats()["rows"], 0)
        self.assertEqual(ScoreRevision.objects.count(), count)
        for revision in ScoreRevision.objects.filter(source="telemetry"):
            side = revision.event.team.track + "_" + revision.event.team.team_type
            result = calculate(side, revision.criterion, revision.facts, revision.quality)
            self.assertEqual(result.marks, revision.marks)
            self.assertTrue(revision.evidence)
            cases, probes, health, authority = [], [], [], None
            for reference in revision.evidence:
                proof = json.loads(verified_bytes(ScoringEvidence.objects.get(pk=reference["id"])))
                for row in proof["records"]:
                    if "identity" in row:
                        authority = row["identity"]
                    source = row.get("receipt", {})
                    if "scenario" in source:
                        cases.append(source)
                    elif source.get("kind") == "probe":
                        probes.append(source)
                    elif source.get("kind") == "source_health":
                        health.append(source)
            self.assertIsNotNone(authority)
            targets = [row for row in authority["targets"] if row["team"] == revision.event.team.team_identifier]
            measured, quality, _ = build(side, revision.criterion, revision.event.team.team_identifier,
                cases, probes, health, revision.window_start, revision.window_end,
                target_ids=[row["target_id"] for row in targets], target_intervals=targets,
                exclusions=authority["exclusions"])
            self.assertEqual(measured, revision.facts)
            self.assertEqual(quality, revision.quality)
            self.assertEqual(calculate(side, revision.criterion, measured, quality).marks, revision.marks)
        before = self.clock.return_value
        self.clock.return_value += dt.timedelta(seconds=1)
        finding = Finding.objects.create(competition=self.competition, red_team=self.app_red, target_team=self.app,
            scoring_objective=self.app_case.objective, round=1, started_at=self.start, ended_at=self.end,
            title="Fixture reviewed finding", technique="fixture", steps="Local verification", evidence="Fixture receipt",
            impact="Measured fixture outcome", status="valid", severity="high", submitted_by=self.app_red.captain)
        scoring_service.award_for_finding(finding, recorded_by=self.staff)
        self.assertEqual(scoring_service.stage_totals(self.app_red)["main"], Decimal("13.00"))
        self.collector.score(now=self.clock.return_value)
        self.assertEqual(deliver(self.collector.outbox, self.collector.platform), 1)
        self.assertEqual(scoring_service.stage_totals(self.app)["main"], Decimal("31.00"))
        self.assertEqual(scoring_service.stage_totals(self.app, as_of=before)["main"], Decimal("37.00"))
        finding.status = "duplicate"
        finding.save(update_fields=["status", "updated_at"])
        scoring_service.award_for_finding(finding, recorded_by=self.staff)
        self.assertEqual(scoring_service.stage_totals(self.app_red)["main"], Decimal("8.00"))
        self.collector.score(now=self.clock.return_value)
        deliver(self.collector.outbox, self.collector.platform)
        self.assertEqual(scoring_service.stage_totals(self.app)["main"], Decimal("37.00"))
        self.assertEqual(ScoreEvent.objects.filter(team=self.app, criterion="unfound").count(), 1)

    def test_archives_are_private_and_failures_remain_measured(self):
        self.exercise()
        revision = ScoreRevision.objects.get(event__team=self.app, criterion="availability")
        self.assertEqual(revision.facts, {"expected": 4, "completed": 4, "successful": 3})
        evidence = ScoringEvidence.objects.get(pk=revision.evidence[0]["id"])
        content = json.loads(verified_bytes(evidence))
        self.assertEqual(content["snapshot"]["facts"], revision.facts)
        self.assertTrue(any(row.get("receipt", {}).get("measurements", {}).get("successful") is False for row in content["records"]))
        self.client.force_login(self.app.captain)
        self.assertEqual(self.client.get(f"/scoring/revisions/{revision.pk}/").status_code, 200)
        self.assertEqual(self.client.get(f"/scoring/evidence/{evidence.pk}/").status_code, 404)
        self.client.force_login(self.staff)
        self.assertEqual(self.client.get(f"/scoring/evidence/{evidence.pk}/").status_code, 200)


if __name__ == "__main__":
    raise SystemExit(bool(DiscoverRunner(verbosity=1).run_tests(["__main__"])))
