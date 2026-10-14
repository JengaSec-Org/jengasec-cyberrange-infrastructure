#!/usr/bin/env python3
"""Converge staff dashboards and managed alerts without changing access.

Owner: Observability. The staff organization and its data sources must already
exist. Credentials and the optional ntfy topic are read from private files.
"""

import argparse
import copy
import json
import math
from pathlib import Path
import re
import sys
from urllib.parse import quote, urlparse

import requests


ROOT = Path(__file__).resolve().parents[1]
FOLDER_UID = "jengasec-infrastructure"
FOLDER_TITLE = "JengaSec Observability"
STAFF_ORG = "JengaSec Staff"
MANAGED_LABEL = "jengasec_managed"
RECEIVER_UID = "jengasec-infrastructure-ntfy"
RECEIVER_NAME = "JengaSec infrastructure"
DASHBOARDS = {
    "jengasec-overview", "jengasec-observability", "jengasec-infrastructure",
    "jengasec-kubernetes", "jengasec-network", "jengasec-investigation",
    "jengasec-telemetry-health",
}
NTFY_TEMPLATE = (
    '{{ coll.Dict "topic" .Vars.topic "title" "JengaSec observability" '
    '"message" (printf "%d alert(s) firing; %d resolved. Open the staff dashboard for details." '
    '(len .Alerts.Firing) (len .Alerts.Resolved)) "priority" 3 '
    '"tags" (coll.Slice "computer") | data.ToJSON }}'
)


class ProvisioningError(ValueError):
    """A safe, operator-facing failure without response bodies or credentials."""


def private_text(path):
    if path.stat().st_mode & 0o077:
        raise ProvisioningError("Credential files must not be accessible to group or other")
    value = path.read_text(encoding="utf-8").strip()
    if not value:
        raise ProvisioningError("Credential file is empty")
    return value


def validate_url(url):
    parsed = urlparse(url)
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ProvisioningError("Grafana URL must not contain credentials, query or fragment")
    if parsed.scheme != "https" and not (
        parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    ):
        raise ProvisioningError("Grafana requires HTTPS unless the endpoint is loopback")


class Grafana:
    def __init__(self, url, user, password):
        validate_url(url)
        self.url = url.rstrip("/")
        self.session = requests.Session()
        self.session.auth = (user, password)
        self.org_id = None

    def request(self, method, path, *, expected=(200,), **kwargs):
        headers = kwargs.pop("headers", {})
        if self.org_id is not None:
            headers["X-Grafana-Org-Id"] = str(self.org_id)
        # Do not follow a redirect carrying administrator credentials.
        response = self.session.request(method, self.url + path, headers=headers,
                                        timeout=30, allow_redirects=False, **kwargs)
        if response.status_code not in expected:
            raise ProvisioningError(f"Grafana {method} {path} returned HTTP {response.status_code}")
        return response.json() if response.content else None

    def inspect_staff(self):
        health = self.request("GET", "/api/health")
        if health.get("database") != "ok":
            raise ProvisioningError("Grafana database is not healthy")
        org = self.request("GET", "/api/orgs/name/" + quote(STAFF_ORG, safe=""))
        if org.get("name") != STAFF_ORG or not isinstance(org.get("id"), int):
            raise ProvisioningError("Existing staff organization could not be verified")
        self.org_id = org["id"]
        for uid, expected_type in (("prometheus", "prometheus"), ("loki", "loki")):
            source = self.request("GET", "/api/datasources/uid/" + uid)
            if source.get("uid") != uid or source.get("type") != expected_type:
                raise ProvisioningError("Existing staff data source has an unexpected type or UID")
            if source.get("orgId") != self.org_id:
                raise ProvisioningError("Data source does not belong to the verified staff organization")
            status = self.request("GET", f"/api/datasources/uid/{uid}/health")
            if str(status.get("status", "")).upper() != "OK":
                raise ProvisioningError("An existing staff data source is not healthy")

    def ensure_folder(self):
        folders = self.request("GET", "/api/folders", params={"limit": 1000})
        existing = next((folder for folder in folders if folder["uid"] == FOLDER_UID), None)
        if existing:
            if existing["title"] != FOLDER_TITLE:
                raise ProvisioningError("Managed folder UID is already used by another folder")
            return
        self.request("POST", "/api/folders", expected=(200, 201),
                     json={"uid": FOLDER_UID, "title": FOLDER_TITLE})

    def import_dashboard(self, dashboard):
        payload = copy.deepcopy(dashboard)
        payload["id"] = None
        self.request("POST", "/api/dashboards/db",
                     json={"dashboard": payload, "folderUid": FOLDER_UID, "overwrite": True})

    def update_evidence_links(self):
        source = self.request("GET", "/api/datasources/uid/loki")
        desired = copy.deepcopy(source.get("jsonData", {}))
        names = {"Event evidence", "Request trail", "Trace trail"}
        fields = [field for field in desired.get("derivedFields", []) if field.get("name") not in names]
        for name, field, variable, label in (
            ("Event evidence", "event_id", "event_id", "View event"),
            ("Request trail", "request_id", "correlation", "Follow request"),
            ("Trace trail", "trace_id", "correlation", "Follow trace"),
        ):
            fields.append({
                "name": name, "matcherType": "label", "matcherRegex": f"^{field}$",
                "url": "/d/jengasec-investigation?" + f"var-{variable}=${{__value.raw}}"
                       "&var-environment=$__all&from=${__from}&to=${__to}",
                "urlDisplayLabel": label,
            })
        desired["derivedFields"] = fields
        if source.get("jsonData", {}) == desired:
            return
        payload = {key: value for key, value in source.items()
                   if key not in {"id", "orgId", "version", "readOnly", "secureJsonFields"}}
        payload["jsonData"] = desired
        # No secureJsonData is supplied: Grafana retains the existing tenant secret.
        payload.pop("secureJsonData", None)
        self.request("PUT", "/api/datasources/uid/loki", json=payload)
        after = self.request("GET", "/api/datasources/uid/loki")
        before_fields = {key: value for key, value in source.items() if key not in {"jsonData", "version"}}
        after_fields = {key: value for key, value in after.items() if key not in {"jsonData", "version"}}
        if before_fields != after_fields or after.get("jsonData") != desired:
            raise ProvisioningError("Data source changed outside the requested evidence links")
        health = self.request("GET", "/api/datasources/uid/loki/health")
        if str(health.get("status", "")).upper() != "OK":
            raise ProvisioningError("Loki data source health failed after updating evidence links")


def load_dashboards(directory):
    dashboards = []
    for uid in sorted(DASHBOARDS):
        dashboard = json.loads((directory / (uid + ".json")).read_text())
        if dashboard.get("uid") != uid or not dashboard.get("panels"):
            raise ProvisioningError("Dashboard has an unexpected UID or no panels")
        dashboards.append(dashboard)
    return dashboards


def load_rules(path):
    definition = json.loads(path.read_text())
    if definition.get("version") != 1 or definition.get("group") != "jengasec-infrastructure":
        raise ProvisioningError("Unsupported alert definition")
    if definition.get("interval_seconds") != 60:
        raise ProvisioningError("Unexpected alert evaluation interval")
    seen = set()
    for rule in definition.get("rules", []):
        uid = rule.get("uid", "")
        if not re.fullmatch(r"jengasec-[a-z0-9-]{1,30}", uid) or uid in seen:
            raise ProvisioningError("Invalid or duplicate alert UID")
        seen.add(uid)
        if rule.get("datasource") not in {"loki", "prometheus"}:
            raise ProvisioningError("Unexpected alert data source")
        if rule.get("dashboard_uid") not in DASHBOARDS:
            raise ProvisioningError("Alert references an unmanaged dashboard")
        if rule.get("no_data_state") not in {"NoData", "OK"}:
            raise ProvisioningError("Invalid missing-data behavior")
        if rule.get("severity") not in {"warning", "critical"}:
            raise ProvisioningError("Invalid severity")
        if not isinstance(rule.get("threshold"), (int, float)) or not math.isfinite(rule["threshold"]):
            raise ProvisioningError("Invalid alert threshold")
        if not re.fullmatch(r"[1-9][0-9]*m", rule.get("for", "")):
            raise ProvisioningError("Alerts require a sustained duration")
        if not isinstance(rule.get("query"), str) or '$' in rule["query"]:
            raise ProvisioningError("Managed alert queries cannot contain dashboard variables")
    if not seen:
        raise ProvisioningError("Alert definition has no rules")
    return definition


def native_rule(rule, org_id):
    uid = rule["datasource"]
    query = {"refId": "A", "datasource": {"type": uid, "uid": uid},
             "editorMode": "code", "expr": rule["query"], "instant": True,
             "range": False, "intervalMs": 1000, "maxDataPoints": 43200}
    if uid == "loki":
        query["queryType"] = "instant"
    return {
        "uid": rule["uid"], "orgID": org_id, "folderUID": FOLDER_UID,
        "ruleGroup": "jengasec-infrastructure", "title": rule["title"],
        "condition": "B", "noDataState": rule["no_data_state"],
        "execErrState": "Error", "for": rule["for"],
        "keepFiringFor": rule.get("keep_firing_for", "1m"), "isPaused": False,
        "labels": {MANAGED_LABEL: "infrastructure", "environment": "live", "severity": rule["severity"]},
        "annotations": {"summary": rule["summary"], "__dashboardUid__": rule["dashboard_uid"],
                        "__panelId__": str(rule["panel_id"])},
        "data": [
            {"refId": "A", "queryType": "instant" if uid == "loki" else "",
             "relativeTimeRange": {"from": 900, "to": 0}, "datasourceUid": uid, "model": query},
            {"refId": "B", "relativeTimeRange": {"from": 0, "to": 0}, "datasourceUid": "__expr__",
             "model": {"refId": "B", "type": "threshold", "expression": "A",
                       "datasource": {"type": "__expr__", "uid": "__expr__"},
                       "conditions": [{"type": "query", "evaluator": {"type": "gt", "params": [rule["threshold"]]},
                                       "operator": {"type": "and"}, "query": {"params": ["B"]},
                                       "reducer": {"type": "last", "params": []}}]}},
        ],
    }


def contact_point(topic):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{19,119}", topic):
        raise ProvisioningError("ntfy topic must be a private, unique topic of 20 to 120 URL-safe characters")
    return {"uid": RECEIVER_UID, "name": RECEIVER_NAME, "type": "webhook",
            "disableResolveMessage": False,
            "settings": {"url": "https://ntfy.sh/", "httpMethod": "POST", "maxAlerts": "30",
                         "payload": {"template": NTFY_TEMPLATE, "vars": {"topic": topic}}}}


def notification_policy(existing, enabled):
    policy = copy.deepcopy(existing)
    matcher = [MANAGED_LABEL, "=", "infrastructure"]
    policy["routes"] = [route for route in policy.get("routes", [])
                        if route.get("object_matchers") != [matcher]]
    if not enabled and existing.get("receiver") != "empty":
        raise ProvisioningError("Grafana-only mode requires the existing empty root receiver")
    # Place the exact managed branch first so another broad route cannot absorb it.
    # Grafana-only mode explicitly selects the verified non-delivery receiver.
    policy["routes"].insert(0, {
        "receiver": RECEIVER_NAME if enabled else "empty", "object_matchers": [matcher],
        "group_by": ["grafana_folder", "severity"], "group_wait": "30s",
        "group_interval": "5m", "repeat_interval": "4h", "continue": False,
    })
    return policy


def apply(grafana, dashboards, definition, topic=None):
    grafana.inspect_staff()
    # Preflight before any mutation, including when custom payload support is absent.
    if topic is not None:
        notifier = next((entry for entry in grafana.request("GET", "/api/alert-notifiers")
                         if entry.get("type") == "webhook"), {})
        if not any(option.get("propertyName") == "payload" for option in notifier.get("options", [])):
            raise ProvisioningError("Grafana webhook custom payload is unavailable; use explicit Grafana-only mode")
        contact = contact_point(topic)
    policy = grafana.request("GET", "/api/v1/provisioning/policies")
    desired_policy = notification_policy(policy, topic is not None)
    existing_rules = grafana.request("GET", "/api/v1/provisioning/alert-rules")
    for rule in existing_rules:
        if rule.get("folderUID") == FOLDER_UID and rule.get("ruleGroup") == definition["group"]:
            if rule.get("labels", {}).get(MANAGED_LABEL) != "infrastructure":
                raise ProvisioningError("Managed rule group contains an unrelated alert")
    grafana.ensure_folder()
    for dashboard in dashboards:
        grafana.import_dashboard(dashboard)
    grafana.update_evidence_links()
    if topic is not None:
        contacts = grafana.request("GET", "/api/v1/provisioning/contact-points")
        existing = next((entry for entry in contacts if entry.get("uid") == RECEIVER_UID), None)
        if existing:
            if existing.get("name") != RECEIVER_NAME or existing.get("type") != "webhook":
                raise ProvisioningError("Managed contact point UID is already in use")
            grafana.request("PUT", "/api/v1/provisioning/contact-points/" + RECEIVER_UID,
                            expected=(200, 202), json=contact)
        else:
            grafana.request("POST", "/api/v1/provisioning/contact-points", expected=(200, 202), json=contact)
    if desired_policy != policy:
        grafana.request("PUT", "/api/v1/provisioning/policies", expected=(200, 202), json=desired_policy)
    rules = [native_rule(rule, grafana.org_id) for rule in definition["rules"]]
    grafana.request("PUT", "/api/v1/provisioning/folder/" + FOLDER_UID + "/rule-groups/" + definition["group"],
                    json={"title": definition["group"], "folderUid": FOLDER_UID,
                          "interval": definition["interval_seconds"], "rules": rules})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--grafana-url", required=True)
    parser.add_argument("--admin-user", default="admin")
    parser.add_argument("--admin-password-file", type=Path, required=True)
    parser.add_argument("--dashboards-dir", type=Path, default=ROOT / "observability/grafana/dashboards")
    parser.add_argument("--rules-file", type=Path, default=ROOT / "observability/grafana/alerting/infrastructure-rules.json")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--ntfy-topic-file", type=Path)
    mode.add_argument("--grafana-only", action="store_true", help="Keep alerts visible only in Grafana")
    parser.add_argument("--dry-run", action="store_true", help="Validate definitions and inspect existing staff resources without writing")
    args = parser.parse_args()
    dashboards = load_dashboards(args.dashboards_dir)
    definition = load_rules(args.rules_file)
    topic = private_text(args.ntfy_topic_file) if args.ntfy_topic_file else None
    if topic is not None:
        contact_point(topic)
    grafana = Grafana(args.grafana_url, args.admin_user, private_text(args.admin_password_file))
    if args.dry_run:
        grafana.inspect_staff()
        print(f"Verified existing staff organization; {len(dashboards)} dashboards and {len(definition['rules'])} managed alerts are ready")
    else:
        apply(grafana, dashboards, definition, topic)
        print(f"Converged {len(dashboards)} staff dashboards and {len(definition['rules'])} alerts; "
              + ("ntfy route configured" if topic else "Grafana-only notifications"))


if __name__ == "__main__":
    try:
        main()
    except (ProvisioningError, OSError, json.JSONDecodeError, requests.RequestException) as error:
        # HTTP response bodies can contain webhook credentials. Never include them.
        print(str(error) if isinstance(error, ProvisioningError) else "Grafana provisioning failed; inspect local configuration and endpoint availability", file=sys.stderr)
        raise SystemExit(1)
