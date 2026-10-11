#!/usr/bin/env python3
"""Provision scoped, read-only Grafana organisations from the OBS access view.

Owner: Observability. Run with the platform exports and Grafana admin secret.
Changes: converges managed organisations, memberships, data sources and dashboards.
"""

import argparse
import csv
import json
import pathlib
import re
import sys
import urllib.parse

import requests


PARTICIPANT_ID = re.compile(r"^JS26-P-[0-9]{4,6}$")
TEAM_ID = re.compile(r"^JS26-[A-Z]+-[0-9]{3}$")
APPLICATION = re.compile(r"^APP0[1-9]$")
ROLES = {"blue_team", "red_team", "judge", "staff"}


def fail(message):
    raise SystemExit(message)


def read_csv(path, required_fields):
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        missing = required_fields - set(reader.fieldnames or [])
        if missing:
            fail(f"{path}: missing columns: {', '.join(sorted(missing))}")
        rows = list(reader)
    if not rows:
        fail(f"{path}: export contains no rows")
    return rows


def build_plan(access_path, applications_path, dashboards_dir, staff_dashboard):
    application_rows = read_csv(
        applications_path,
        {
            "contract_version",
            "enterprise",
            "application",
            "namespace",
            "service_name",
        },
    )
    applications = {}
    for row in application_rows:
        if row["contract_version"] != "1":
            fail("application export has an unsupported contract version")
        enterprise = row["enterprise"]
        application = row["application"]
        namespace = row["namespace"]
        if enterprise not in {"ENT-A", "ENT-B"} or not APPLICATION.fullmatch(application):
            fail("application export contains an invalid identifier")
        if namespace != f"jengasec-{enterprise.lower()}-{application.lower()}":
            fail("application export contains a non-canonical namespace")
        key = (enterprise, application)
        if key in applications:
            fail("application export contains a duplicate application")
        applications[key] = {
            "enterprise": enterprise,
            "application": application,
            "namespace": namespace,
            "service_name": row["service_name"],
            "org_name": f"JengaSec {enterprise} {application}",
            "dashboard": str(dashboards_dir / f"{namespace}.json"),
            "members": set(),
        }
    if len(applications) != 18:
        fail("application export must contain all 18 application instances")

    access_rows = read_csv(
        access_path,
        {
            "contract_version",
            "participant_id",
            "role",
            "team_id",
            "enterprise",
            "application",
            "namespace",
        },
    )
    staff_members = set()
    participant_roles = {}
    for row in access_rows:
        participant = row["participant_id"]
        role = row["role"]
        if row["contract_version"] != "1":
            fail("access export has an unsupported contract version")
        if not PARTICIPANT_ID.fullmatch(participant) or role not in ROLES:
            fail("access export contains an invalid participant or role")
        participant_roles.setdefault(participant, set()).add(role)
        if role in {"judge", "staff"}:
            if any(row[field] for field in ("team_id", "enterprise", "application", "namespace")):
                fail("staff and judge access rows must not contain application scope")
            staff_members.add(participant)
            continue
        if not TEAM_ID.fullmatch(row["team_id"]):
            fail("team access row contains an invalid team identifier")
        key = (row["enterprise"], row["application"])
        application_record = applications.get(key)
        if application_record is None or row["namespace"] != application_record["namespace"]:
            fail("access row references an unknown or inconsistent application")
        application_record["members"].add(participant)

    for participant, roles in participant_roles.items():
        if roles & {"judge", "staff"} and roles & {"blue_team", "red_team"}:
            fail(f"{participant}: global and application roles cannot be combined")

    for application_record in applications.values():
        dashboard_path = pathlib.Path(application_record["dashboard"])
        if not dashboard_path.is_file():
            fail(f"missing application dashboard: {dashboard_path}")
        application_record["members"] = sorted(application_record["members"])

    if not staff_dashboard.is_file():
        fail(f"missing staff dashboard: {staff_dashboard}")
    return {
        "contract_version": 1,
        "staff": {
            "org_name": "JengaSec Staff",
            "dashboard": str(staff_dashboard),
            "members": sorted(staff_members),
        },
        "applications": sorted(
            applications.values(),
            key=lambda item: (item["enterprise"], item["application"]),
        ),
    }


class Grafana:
    def __init__(self, url, user, password):
        self.url = url.rstrip("/")
        self.session = requests.Session()
        self.session.auth = (user, password)

    def request(self, method, path, *, org_id=None, expected=(200,), **kwargs):
        headers = kwargs.pop("headers", {})
        if org_id is not None:
            headers["X-Grafana-Org-Id"] = str(org_id)
        response = self.session.request(
            method,
            self.url + path,
            headers=headers,
            timeout=15,
            **kwargs,
        )
        if response.status_code not in expected:
            fail(f"Grafana {method} {path} returned HTTP {response.status_code}")
        if not response.content:
            return None
        return response.json()

    def ensure_org(self, name):
        encoded = urllib.parse.quote(name, safe="")
        response = self.session.get(
            self.url + f"/api/orgs/name/{encoded}", timeout=15
        )
        if response.status_code == 200:
            return response.json()["id"]
        if response.status_code != 404:
            fail(f"Grafana organisation lookup returned HTTP {response.status_code}")
        return self.request(
            "POST", "/api/orgs", expected=(200,), json={"name": name}
        )["orgId"]

    def lookup_user(self, login):
        response = self.session.get(
            self.url + "/api/users/lookup",
            params={"loginOrEmail": login},
            timeout=15,
        )
        if response.status_code == 404:
            return None
        if response.status_code != 200:
            fail(f"Grafana user lookup returned HTTP {response.status_code}")
        return response.json()

    def ensure_user(self, login, password, org_id):
        user = self.lookup_user(login)
        if user is not None:
            return user["id"]
        if not password:
            fail(f"Grafana identity does not exist: {login}")
        response = self.request(
            "POST",
            "/api/admin/users",
            expected=(200,),
            json={
                "name": login,
                "email": f"{login.lower()}@example.invalid",
                "login": login,
                "password": password,
                "OrgId": org_id,
            },
        )
        return response["id"]

    def converge_members(self, org_id, desired, user_ids):
        existing = self.request("GET", f"/api/orgs/{org_id}/users")
        existing_by_login = {row["login"]: row for row in existing}
        for login in sorted(desired):
            if login not in existing_by_login:
                self.request(
                    "POST",
                    f"/api/orgs/{org_id}/users",
                    expected=(200,),
                    json={"loginOrEmail": login, "role": "Viewer"},
                )
            elif existing_by_login[login]["role"] != "Viewer":
                self.request(
                    "PATCH",
                    f"/api/orgs/{org_id}/users/{user_ids[login]}",
                    expected=(200,),
                    json={"role": "Viewer"},
                )
        for login, row in existing_by_login.items():
            if login != "admin" and login not in desired:
                self.request(
                    "DELETE",
                    f"/api/orgs/{org_id}/users/{row['userId']}",
                    expected=(200,),
                )

    def upsert_datasource(self, org_id, payload):
        uid = payload["uid"]
        response = self.session.get(
            self.url + f"/api/datasources/uid/{uid}",
            headers={"X-Grafana-Org-Id": str(org_id)},
            timeout=15,
        )
        if response.status_code == 404:
            self.request(
                "POST", "/api/datasources", org_id=org_id, expected=(200,), json=payload
            )
            return
        if response.status_code != 200:
            fail(f"Grafana data source lookup returned HTTP {response.status_code}")
        self.request(
            "PUT",
            f"/api/datasources/uid/{uid}",
            org_id=org_id,
            expected=(200,),
            json=payload,
        )

    def import_dashboard(self, org_id, path):
        dashboard = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
        dashboard["id"] = None
        self.request(
            "POST",
            "/api/dashboards/db",
            org_id=org_id,
            expected=(200,),
            json={"dashboard": dashboard, "overwrite": True},
        )


def loki_datasource(tenant):
    tenant_id = tenant if tenant == "staff" else f"application-{tenant}"
    return {
        "name": "Loki",
        "uid": "loki",
        "type": "loki",
        "access": "proxy",
        "url": "http://loki:3100",
        "isDefault": False,
        "editable": False,
        "jsonData": {"httpHeaderName1": "X-Scope-OrgID", "maxLines": 1000},
        "secureJsonData": {"httpHeaderValue1": tenant_id},
    }


def prometheus_datasource(namespace=None):
    payload = {
        "name": "Prometheus",
        "uid": "prometheus",
        "type": "prometheus",
        "access": "proxy",
        "url": "http://prometheus:9090",
        "isDefault": True,
        "editable": False,
        "jsonData": {"httpMethod": "POST", "timeInterval": "5s"},
    }
    if namespace:
        payload["url"] = "http://prometheus-scope-proxy:8080"
        payload["jsonData"]["httpHeaderName1"] = "X-JengaSec-Namespace"
        payload["secureJsonData"] = {"httpHeaderValue1": namespace}
    return payload


def load_passwords(path):
    if path is None:
        return {}
    if path.stat().st_mode & 0o077:
        fail(f"{path}: credential file must not be accessible to group or other")
    try:
        passwords = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as error:
        fail(f"{path}: invalid credential file: {error}")
    if not isinstance(passwords, dict) or not all(
        isinstance(key, str) and isinstance(value, str)
        for key, value in passwords.items()
    ):
        fail(f"{path}: expected a string-to-string JSON object")
    return passwords


def apply_plan(grafana, plan, passwords):
    records = [plan["staff"], *plan["applications"]]
    org_ids = {record["org_name"]: grafana.ensure_org(record["org_name"]) for record in records}
    desired_orgs = {}
    for record in records:
        for participant in record["members"]:
            desired_orgs.setdefault(participant, []).append(record["org_name"])

    user_ids = {}
    for participant, organisations in sorted(desired_orgs.items()):
        primary_org = org_ids[sorted(organisations)[0]]
        user_ids[participant] = grafana.ensure_user(
            participant, passwords.get(participant), primary_org
        )

    staff = plan["staff"]
    staff_org = org_ids[staff["org_name"]]
    grafana.converge_members(staff_org, set(staff["members"]), user_ids)
    grafana.upsert_datasource(staff_org, prometheus_datasource())
    grafana.upsert_datasource(staff_org, loki_datasource("staff"))
    grafana.import_dashboard(staff_org, staff["dashboard"])

    for record in plan["applications"]:
        org_id = org_ids[record["org_name"]]
        grafana.converge_members(org_id, set(record["members"]), user_ids)
        grafana.upsert_datasource(org_id, prometheus_datasource(record["namespace"]))
        grafana.upsert_datasource(org_id, loki_datasource(record["namespace"]))
        grafana.import_dashboard(org_id, record["dashboard"])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--grafana-url")
    parser.add_argument("--admin-user", default="admin")
    parser.add_argument("--admin-password-file", type=pathlib.Path)
    parser.add_argument("--user-passwords-file", type=pathlib.Path)
    parser.add_argument("--access-principals", type=pathlib.Path, required=True)
    parser.add_argument("--applications", type=pathlib.Path, required=True)
    parser.add_argument("--dashboards-dir", type=pathlib.Path, required=True)
    parser.add_argument(
        "--staff-dashboard",
        type=pathlib.Path,
        default=pathlib.Path(
            "observability/grafana/dashboards/jengasec-observability.json"
        ),
    )
    parser.add_argument("--plan-output", type=pathlib.Path)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    plan = build_plan(
        args.access_principals,
        args.applications,
        args.dashboards_dir,
        args.staff_dashboard,
    )
    if args.plan_output:
        args.plan_output.write_text(
            json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    if args.dry_run:
        print(
            f"would converge {len(plan['applications'])} application organisations "
            f"and {len(plan['staff']['members'])} staff/judge viewers"
        )
        return
    if not args.grafana_url or not args.admin_password_file:
        fail("--grafana-url and --admin-password-file are required unless --dry-run is used")
    password = args.admin_password_file.read_text(encoding="utf-8").strip()
    if not password:
        fail("Grafana admin password file is empty")
    passwords = load_passwords(args.user_passwords_file)
    apply_plan(Grafana(args.grafana_url, args.admin_user, password), plan, passwords)
    print("Grafana access policy converged")


if __name__ == "__main__":
    try:
        main()
    except requests.RequestException as error:
        print(f"Grafana request failed: {error}", file=sys.stderr)
        raise SystemExit(1)
