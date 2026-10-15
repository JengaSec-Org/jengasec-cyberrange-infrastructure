#!/usr/bin/env python3
"""Verify staff-only provisioning, query contracts and optional native queries.

Owner: Observability. Native queries are read-only and emit no test events.
"""

import argparse
import copy
import importlib.util
import json
from pathlib import Path
import re
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("infrastructure_grafana", ROOT / "scripts/provision-infrastructure-grafana.py")
PROVISION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROVISION)
DIRECTORY = ROOT / "observability/grafana/dashboards"
RULES_FILE = ROOT / "observability/grafana/alerting/infrastructure-rules.json"


def panels(dashboard):
    for panel in dashboard["panels"]:
        yield panel
        yield from panels({"panels": panel.get("panels", [])})


class FakeGrafana(PROVISION.Grafana):
    def __init__(self):
        self.org_id = None
        self.calls = []
        self.org = {"id": 2, "name": "JengaSec Staff"}
        self.sources = {
            uid: {"id": i, "orgId": 2, "uid": uid, "name": uid.title(), "type": uid,
                  "url": "http://" + uid + ":9090", "access": "proxy", "version": 1,
                  "readOnly": False, "isDefault": uid == "prometheus",
                  "jsonData": {"httpHeaderName1": "X-Scope-OrgID", "maxLines": 1000,
                               "derivedFields": [{"name": "Existing custom field", "matcherRegex": "custom"}]},
                  "secureJsonFields": {"httpHeaderValue1": True}}
            for i, uid in enumerate(("prometheus", "loki"), 1)
        }
        self.folders = []
        self.dashboards = {}
        self.rules = []
        self.contacts = []
        self.policy = {"receiver": "empty", "group_by": ["grafana_folder", "alertname"],
                       "routes": [{"receiver": "other-owner", "object_matchers": [["owner", "=", "other"]]}]}
        self.supports_payload = True
        self.preferences = {"homeDashboardUID": "", "theme": "dark", "timezone": "utc"}

    def request(self, method, path, *, expected=(200,), **kwargs):
        self.calls.append((method, path, self.org_id, copy.deepcopy(kwargs.get("json"))))
        data = kwargs.get("json")
        if method != "GET" and self.org_id != 2:
            raise AssertionError("Mutation escaped the verified staff organization")
        if path == "/api/health":
            return {"database": "ok"}
        if path == "/api/org/preferences":
            if method == "PUT":
                self.preferences = copy.deepcopy(data)
            return copy.deepcopy(self.preferences)
        if path.startswith("/api/orgs/name/"):
            return copy.deepcopy(self.org)
        if path.endswith("/health"):
            return {"status": "OK"}
        if path.startswith("/api/datasources/uid/"):
            uid = path.rsplit("/", 1)[-1]
            if method == "PUT":
                if "secureJsonData" in data:
                    raise AssertionError("Tenant credentials must not be rewritten")
                self.sources[uid].update(copy.deepcopy(data))
                self.sources[uid]["version"] += 1
            return copy.deepcopy(self.sources[uid])
        if path == "/api/folders":
            if method == "POST":
                self.folders.append(copy.deepcopy(data))
                return copy.deepcopy(data)
            return copy.deepcopy(self.folders)
        if path == "/api/dashboards/db":
            if data["folderUid"] != PROVISION.FOLDER_UID:
                raise AssertionError("Dashboard escaped the managed folder")
            self.dashboards[data["dashboard"]["uid"]] = copy.deepcopy(data)
            return {"status": "success"}
        if path == "/api/alert-notifiers":
            return [{"type": "webhook", "options": [{"propertyName": "payload"}] if self.supports_payload else []}]
        if path == "/api/v1/provisioning/alert-rules":
            return copy.deepcopy(self.rules)
        if path == "/api/v1/provisioning/policies":
            if method == "PUT":
                self.policy = copy.deepcopy(data)
            return copy.deepcopy(self.policy)
        if path.startswith("/api/v1/provisioning/contact-points"):
            if method == "GET":
                return copy.deepcopy(self.contacts)
            self.contacts = [item for item in self.contacts if item["uid"] != data["uid"]]
            self.contacts.append(copy.deepcopy(data))
            return {}
        if path.startswith("/api/v1/provisioning/folder/"):
            self.rules = copy.deepcopy(data["rules"])
            return copy.deepcopy(data)
        raise AssertionError((method, path))


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.dashboards = PROVISION.load_dashboards(DIRECTORY)
        self.definition = PROVISION.load_rules(RULES_FILE)

    def test_views_keep_navigation_context_and_intuitive_defaults(self):
        self.assertEqual(len(self.dashboards), 7)
        for dashboard in self.dashboards:
            self.assertEqual(dashboard["refresh"], "30s")
            self.assertEqual(dashboard["time"], {"from": "now-1h", "to": "now"})
            self.assertEqual({link["url"] for link in dashboard["links"]},
                             {"/d/" + uid for uid in PROVISION.DASHBOARDS})
            self.assertTrue(all(link["includeVars"] and link["keepTime"] for link in dashboard["links"]))
            environment = next(item for item in dashboard["templating"]["list"] if item["name"] == "environment")
            self.assertEqual(environment["current"]["value"], ["live"])
            identifiers = [panel["id"] for panel in panels(dashboard)]
            self.assertEqual(len(identifiers), len(set(identifiers)))
            for panel in panels(dashboard):
                for target in panel.get("targets", []):
                    self.assertNotRegex(target["expr"], r"\b(?:count|sum)\s*\(\s*\{\s*\}")

    def test_application_requests_keep_source_and_event_boundary(self):
        dashboard = next(item for item in self.dashboards if item["uid"] == "jengasec-observability")
        request_panel = next(panel for panel in panels(dashboard) if panel["id"] == 3)
        expression = request_panel["targets"][0]["expr"]
        for clause in ('source="application"', 'raw_event="request_completed"', 'event_type="http_request"'):
            self.assertIn(clause, expression)
        self.assertIn('unclassified', expression)
        self.assertIn('${environment:regex}', expression)
        self.assertIn('${team:doublequote}', expression)
        self.assertIn('${participant:doublequote}', expression)

    def test_investigation_does_not_mix_families_or_interpret_ids_as_regex(self):
        dashboard = next(item for item in self.dashboards if item["uid"] == "jengasec-investigation")
        logs = [panel for panel in panels(dashboard) if panel["type"] == "logs"]
        self.assertEqual(len(logs), 2)
        infrastructure, application = [panel["targets"][0]["expr"] for panel in logs]
        self.assertIn('record_family="infrastructure_telemetry"', infrastructure)
        self.assertNotIn('app0[1-9]', infrastructure)
        self.assertIn('namespace=~"jengasec-ent-(a|b)-app0[1-9]"', application)
        for expression in (infrastructure, application):
            self.assertIn('event_id=${event_id:doublequote}', expression)
            self.assertIn('request_id=${correlation:doublequote}', expression)
            self.assertNotIn('${event_id:regex}', expression)
            self.assertNotIn('${correlation:regex}', expression)

    def test_missing_hosts_and_inactive_peers_are_not_reported_healthy(self):
        overview = next(item for item in self.dashboards if item["uid"] == "jengasec-overview")
        targets = [panel for panel in overview["panels"] if any('up{job="jengasec-node"' in item["expr"] for item in panel.get("targets", []))]
        self.assertEqual(len(targets), 6)
        for panel in targets:
            self.assertIn('or on() vector(-1)', panel["targets"][0]["expr"])
            self.assertEqual(panel["fieldConfig"]["defaults"]["mappings"][0]["options"]["-1"]["text"], "Missing")
        self.assertFalse(any('wireguard_peers' in rule["query"] for rule in self.definition["rules"]))
        restart = next(rule for rule in self.definition["rules"] if rule["uid"] == "jengasec-container-restarts")
        self.assertIn('clamp_min(delta(k8s_container_restarts{', restart["query"])
        self.assertNotIn('_total', restart["query"])

    def test_alerts_use_recent_increases_and_sustained_failures(self):
        for rule in self.definition["rules"]:
            self.assertNotIn('$', rule["query"])
            self.assertIn('environment="live"', rule["query"])
            if '_total' in rule["query"]:
                self.assertRegex(rule["query"], r'\b(increase|rate)\(')
            native = PROVISION.native_rule(rule, 2)
            self.assertEqual(native["orgID"], 2)
            self.assertEqual(native["execErrState"], "Error")
            self.assertEqual(native["keepFiringFor"], "1m")
            dashboard = next(item for item in self.dashboards if item["uid"] == rule["dashboard_uid"])
            self.assertIn(rule["panel_id"], [panel["id"] for panel in panels(dashboard)])

    def test_provisioning_preserves_access_secrets_other_routes_and_converges(self):
        fake = FakeGrafana()
        fake.sources["loki"]["jsonData"]["derivedFields"].append({
            "name": "Event evidence", "matcherType": "label", "matcherRegex": "^event_id$",
            "url": "/d/jengasec-investigation?var-event_id=${__value.raw}",
        })
        original_source = copy.deepcopy(fake.sources["loki"])
        foreign_route = copy.deepcopy(fake.policy["routes"][0])
        for _ in range(2):
            PROVISION.apply(fake, self.dashboards, self.definition, "validation-topic-no-identities")
        self.assertEqual(len(fake.dashboards), 7)
        self.assertEqual(len(fake.folders), 1)
        self.assertEqual(len(fake.contacts), 1)
        self.assertEqual(len(fake.policy["routes"]), 2)
        self.assertEqual(fake.policy["routes"][1], foreign_route)
        self.assertEqual(len(fake.rules), len(self.definition["rules"]))
        for key in original_source.keys() - {"jsonData", "version"}:
            self.assertEqual(fake.sources["loki"][key], original_source[key])
        self.assertEqual(fake.sources["loki"]["jsonData"]["httpHeaderName1"], "X-Scope-OrgID")
        fields = fake.sources["loki"]["jsonData"]["derivedFields"]
        self.assertIn({"name": "Existing custom field", "matcherRegex": "custom"}, fields)
        self.assertTrue(all('/d/jengasec-investigation?' in field["url"] for field in fields if "url" in field))
        links = {field["name"]: field for field in fields if "url" in field}
        self.assertEqual(set(links), {"event_id", "request_id", "trace_id"})
        for name, link in links.items():
            self.assertEqual(link["matcherType"], "label")
            self.assertEqual(link["matcherRegex"], "^" + name + "$")
            self.assertIn("${__value.raw:percentencode}", link["url"])
            self.assertIn("${environment:queryparam}&from=${__from}&to=${__to}", link["url"])
            self.assertNotIn("$__all", link["url"])
        self.assertEqual(links["event_id"]["urlDisplayLabel"], "View event in Investigation")
        self.assertEqual(sum(method == "PUT" and path == "/api/datasources/uid/loki"
                             for method, path, _, _ in fake.calls), 1)
        for method, path, org_id, _ in fake.calls:
            if method != "GET":
                self.assertEqual(org_id, 2)
                self.assertNotRegex(path, r'/api/(admin|orgs|users)')

    def test_evidence_links_preserve_unrelated_identifier_fields(self):
        fake = FakeGrafana()
        fake.org_id = 2
        fake.sources["loki"]["jsonData"]["derivedFields"].append({
            "name": "event_id", "matcherRegex": "custom-event", "url": "/custom-investigation",
        })
        original = copy.deepcopy(fake.sources["loki"])
        with self.assertRaisesRegex(PROVISION.ProvisioningError, "unrelated derived field"):
            fake.update_evidence_links()
        self.assertEqual(fake.sources["loki"], original)
        self.assertTrue(all(method == "GET" for method, _, _, _ in fake.calls))

    def test_wrong_organization_source_or_unavailable_payload_stops_before_mutation(self):
        for change in ("organization", "datasource", "payload", "unrelated_rule"):
            fake = FakeGrafana()
            if change == "organization":
                fake.org["name"] = "JengaSec ENT-A APP01"
            elif change == "datasource":
                fake.sources["loki"]["orgId"] = 1
            elif change == "payload":
                fake.supports_payload = False
            else:
                fake.rules = [{"folderUID": PROVISION.FOLDER_UID, "ruleGroup": self.definition["group"], "labels": {"owner": "other"}}]
            with self.subTest(change=change), self.assertRaises(PROVISION.ProvisioningError):
                PROVISION.apply(fake, self.dashboards, self.definition, "validation-topic-no-identities")
            self.assertTrue(all(method == "GET" for method, _, _, _ in fake.calls))

    def test_grafana_only_mode_cannot_fall_through_to_an_external_receiver(self):
        fake = FakeGrafana()
        PROVISION.apply(fake, self.dashboards, self.definition)
        self.assertEqual(fake.contacts, [])
        self.assertEqual(fake.policy["routes"][0]["receiver"], "empty")
        self.assertFalse(fake.policy["routes"][0]["continue"])
        with self.assertRaises(PROVISION.ProvisioningError):
            PROVISION.notification_policy({"receiver": "external"}, False)

    def test_public_payload_has_only_topic_fixed_text_and_counts(self):
        payload = PROVISION.contact_point("validation-topic-no-identities")
        self.assertEqual(payload["settings"]["url"], "https://ntfy.sh/")
        self.assertFalse(payload["disableResolveMessage"])
        template = payload["settings"]["payload"]["template"]
        for disallowed in (".Labels", ".Annotations", ".CommonLabels", ".CommonAnnotations", ".ExternalURL", "range ", ".Status"):
            self.assertNotIn(disallowed, template)
        self.assertIn('len .Alerts.Firing', template)
        self.assertIn('len .Alerts.Resolved', template)
        for topic in ("short", 'bad"topic-value-with-quotes', "space in a sufficiently long topic"):
            with self.assertRaises(PROVISION.ProvisioningError):
                PROVISION.contact_point(topic)

    def test_credentials_require_private_files_and_tls_or_loopback(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "credential"
            path.write_text("private-value")
            path.chmod(0o644)
            with self.assertRaises(PROVISION.ProvisioningError):
                PROVISION.private_text(path)
            path.chmod(0o600)
            self.assertEqual(PROVISION.private_text(path), "private-value")
        for url in ("http://example.invalid", "https://user:password@example.invalid", "https://example.invalid?token=value"):
            with self.assertRaises(PROVISION.ProvisioningError):
                PROVISION.validate_url(url)


def interpolate(expression, values):
    def replace(match):
        name, formatter = match.groups()
        value = values[name]
        if formatter == "doublequote":
            return json.dumps(value)
        if value == "$__all":
            return ".*"
        return re.escape(value).replace("\\", "\\\\")
    return (re.sub(r'\$\{([a-z_]+):(doublequote|regex)\}', replace, expression)
            .replace("$__range", "5m").replace("$__rate_interval", "2m").replace("$__interval", "30s"))


def native_queries(url, password_file):
    grafana = PROVISION.Grafana(url, "admin", PROVISION.private_text(password_file))
    grafana.inspect_staff()
    # A labelled healthy series must suppress the unlabelled fallback entirely.
    for expression, expected in (
        ('label_replace(vector(1), "resource_id", "vm101", "", "") or on() vector(-1)', 1),
        ('up{job="missing-validation-target"} or on() vector(-1)', -1),
    ):
        result = grafana.request("GET", "/api/datasources/proxy/uid/prometheus/api/v1/query",
                                 params={"query": expression})["data"]["result"]
        if len(result) != 1 or float(result[0]["value"][1]) != expected:
            raise AssertionError("Expected-host fallback did not preserve the correct single state")
    dashboards = PROVISION.load_dashboards(DIRECTORY)
    queries = []
    for dashboard in dashboards:
        values = {variable["name"]: "$__all" if variable["type"] in {"custom", "query"} else ""
                  for variable in dashboard["templating"]["list"]}
        values["environment"] = "live"
        for panel in panels(dashboard):
            for target in panel.get("targets", []):
                expression = interpolate(target["expr"], values)
                queries.append((panel["title"], panel["datasource"]["uid"], panel["type"], expression))
    for rule in PROVISION.load_rules(RULES_FILE)["rules"]:
        queries.append((rule["title"], rule["datasource"], "stat", rule["query"]))
    end = time.time()
    with_results = 0
    for title, source, kind, expression in queries:
        base = f"/api/datasources/proxy/uid/{source}" + ("/api/v1" if source == "prometheus" else "/loki/api/v1")
        ranged = source == "loki" and kind not in {"stat", "table"}
        parameters = {"query": expression}
        if ranged:
            parameters.update(start=f"{end - 300:.3f}", end=f"{end:.3f}", step="30", limit="10")
        else:
            parameters["time"] = f"{end:.3f}"
        try:
            result = grafana.request("GET", base + ("/query_range" if ranged else "/query"), params=parameters)
        except PROVISION.ProvisioningError as error:
            raise AssertionError(f"Native query failed for {title}: {error}") from error
        if result.get("status") != "success":
            raise AssertionError(f"Native query was unsuccessful: {title}")
        with_results += bool(result.get("data", {}).get("result"))
    print(f"Native query validation: {len(queries)} queries accepted; {with_results} have current results. Empty queries remain missing or quiet, not verified live coverage.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--grafana-url")
    parser.add_argument("--admin-password-file", type=Path)
    args = parser.parse_args()
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(DashboardTests))
    if not result.wasSuccessful():
        raise SystemExit(1)
    if args.grafana_url:
        if not args.admin_password_file:
            parser.error("--admin-password-file is required for native queries")
        native_queries(args.grafana_url, args.admin_password_file)
