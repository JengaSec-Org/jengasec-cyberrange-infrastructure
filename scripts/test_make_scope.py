"""Tests for the application ingress scope updater."""

import csv
import importlib.util
import json
import pathlib
import tempfile
import unittest
from unittest.mock import Mock, patch

import yaml


SCRIPT_PATH = pathlib.Path(__file__).with_name("make-scope.py")
SPEC = importlib.util.spec_from_file_location("make_scope", SCRIPT_PATH)
make_scope = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(make_scope)


class ScopeUpdaterTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)
        self.cells_path = self.root / "cells.yaml"
        self.scope_path = self.root / "scope.csv"
        self.cells_path.write_text(
            yaml.safe_dump({
                "cells": [
                    {
                        "namespace": "jengasec-ent-a-app01",
                        "enterprise": "ENT-A",
                        "application": "APP01",
                        "reserved_ip": "10.108.0.11",
                        "team": "JS26-B-001",
                        "enabled": True,
                    },
                    {
                        "namespace": "jengasec-ent-a-app08",
                        "enterprise": "ENT-A",
                        "application": "APP08",
                        "reserved_ip": "10.108.0.18",
                        "team": "JS26-B-008",
                        "enabled": False,
                    },
                ]
            }),
            encoding="utf-8",
        )
        self.scope_rows = [
            {
                "team_id": "JS26-R-001",
                "source_cidr": "10.60.1.0/24",
                "enterprise": "ENT-A",
                "application": "APP01",
                "namespace": "jengasec-ent-a-app01",
                "target_ip": "10.108.0.11",
                "active": "true",
                "notes": "active",
            },
            {
                "team_id": "JS26-R-002",
                "source_cidr": "10.60.2.0/24",
                "enterprise": "ENT-A",
                "application": "APP01",
                "namespace": "jengasec-ent-a-app01",
                "target_ip": "10.108.0.11",
                "active": "false",
                "notes": "inactive",
            },
            {
                "team_id": "JS26-AIR-001",
                "source_cidr": "10.64.1.0/24",
                "enterprise": "ENT-A",
                "application": "APP01",
                "namespace": "jengasec-ent-a-app01",
                "target_ip": "10.108.0.11",
                "active": "true",
                "notes": "AI Red scope",
            },
        ]
        self.write_scope()

    def write_scope(self):
        with self.scope_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(
                handle, fieldnames=make_scope.SCOPE_FIELDS, lineterminator="\n"
            )
            writer.writeheader()
            writer.writerows(self.scope_rows)

    def test_allowlist_includes_staff_owner_and_active_red_only(self):
        allowlists = make_scope.read_scope_inputs(self.cells_path, self.scope_path)
        self.assertEqual(
            allowlists["jengasec-ent-a-app01"]["ranges"],
            {
                "10.63.0.0/24",
                "10.61.1.0/24",
                "10.60.1.0/24",
                "10.64.1.0/24",
            },
        )
        self.assertEqual(list(allowlists), ["jengasec-ent-a-app01"])

    def test_invalid_owner_team_is_rejected(self):
        document = yaml.safe_load(self.cells_path.read_text(encoding="utf-8"))
        document["cells"][0]["team"] = "JS26-R-001"
        self.cells_path.write_text(yaml.safe_dump(document), encoding="utf-8")
        with self.assertRaisesRegex(make_scope.ScopeError, "owner team identifier"):
            make_scope.read_scope_inputs(self.cells_path, self.scope_path)

    def test_mismatched_assignment_target_is_rejected(self):
        self.scope_rows[0]["target_ip"] = "10.108.0.12"
        self.write_scope()
        with self.assertRaisesRegex(make_scope.ScopeError, "does not match cell"):
            make_scope.read_scope_inputs(self.cells_path, self.scope_path)

    def test_assignment_cidr_must_match_red_team_address_plan(self):
        self.scope_rows[0]["source_cidr"] = "10.63.0.0/24"
        self.write_scope()
        with self.assertRaisesRegex(make_scope.ScopeError, "must be a /24"):
            make_scope.read_scope_inputs(self.cells_path, self.scope_path)

    def test_red_team_number_is_not_assumed_to_match_competition_pool_ordinal(self):
        self.scope_rows[0]["team_id"] = "JS26-R-014"
        self.write_scope()
        allowlists = make_scope.read_scope_inputs(self.cells_path, self.scope_path)
        self.assertIn(
            "10.60.1.0/24",
            allowlists["jengasec-ent-a-app01"]["ranges"],
        )

    def test_live_scope_is_fetched_from_competition_scoped_platform_exports(self):
        rows = []
        for enterprise, namespace_enterprise, offset in (
            ("enta", "ent-a", 10),
            ("entb", "ent-b", 20),
        ):
            for number in range(1, 10):
                application = f"APP{number:02}"
                rows.append({
                    "name": f"jengasec-{namespace_enterprise}-{application.lower()}",
                    "enterprise": enterprise,
                    "code": application,
                    "kind": "app",
                    "enabled": True,
                    "service": application,
                    "team": f"JS26-B-{number:03}",
                    "service_ip": f"10.108.0.{offset + number}",
                })
        cells_yaml = yaml.safe_dump({"cells": rows}, sort_keys=False)
        scope_csv = "\n".join([
            "red_team,red_cell,enterprise,target_cell,target_namespace,"
            "target_service_ip,wg_range,round_active,notes",
            "JS26-R-014,APPRED01,enta,APP01,jengasec-ent-a-app01,"
            "10.108.0.11,10.60.1.0/24,true,active",
            "",
        ])
        response = Mock()
        response.read.return_value = json.dumps({
            "cells_yaml": cells_yaml,
            "scope_csv": scope_csv,
        }).encode("utf-8")
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)

        with patch.object(make_scope.urllib.request, "urlopen", return_value=response) as urlopen:
            allowlists = make_scope.read_live_scope_inputs(
                "https://site.example", "deploy-token", "12"
            )

        request = urlopen.call_args.args[0]
        self.assertEqual(
            request.full_url,
            "https://site.example/deployments/api/range-exports/?competition=12",
        )
        self.assertEqual(request.get_header("X-deploy-token"), "deploy-token")
        self.assertEqual(
            allowlists["jengasec-ent-a-app01"]["ranges"],
            {"10.63.0.0/24", "10.61.1.0/24", "10.60.1.0/24"},
        )

    def test_live_scope_request_fails_closed_when_platform_rejects_token(self):
        error = make_scope.urllib.error.HTTPError(
            "https://site.example/deployments/api/range-exports/?competition=12",
            403,
            "Forbidden",
            {},
            None,
        )
        with patch.object(make_scope.urllib.request, "urlopen", side_effect=error):
            with self.assertRaisesRegex(make_scope.ScopeError, "HTTP 403"):
                make_scope.read_live_scope_inputs(
                    "https://site.example", "wrong-token", "12"
                )

    def test_dry_run_preserves_values_and_updates_only_allowlist(self):
        allowlists = make_scope.read_scope_inputs(self.cells_path, self.scope_path)
        with patch.object(make_scope.subprocess, "run") as run:
            def inspect_command(command, check):
                self.assertTrue(check)
                self.assertEqual(command[:4], [
                    "helm", "upgrade", "jengasec-ent-a-app01",
                    str(self.root / "chart"),
                ])
                self.assertIn("--reuse-values", command)
                self.assertIn("--dry-run=client", command)
                values_path = pathlib.Path(command[command.index("--values") + 1])
                self.assertEqual(
                    yaml.safe_load(values_path.read_text(encoding="utf-8")),
                    {"ingress": {"allowedRanges": [
                        "10.60.1.0/24",
                        "10.61.1.0/24",
                        "10.63.0.0/24",
                        "10.64.1.0/24",
                    ]}},
                )

            run.side_effect = inspect_command
            make_scope.apply_scope(
                allowlists, self.root / "chart", "helm", dry_run=True
            )
        run.assert_called_once()


if __name__ == "__main__":
    unittest.main()
