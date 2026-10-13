"""Tests for the application ingress scope updater."""

import csv
import importlib.util
import pathlib
import tempfile
import unittest
from unittest.mock import patch

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
        self.scope_rows[0]["source_cidr"] = "0.0.0.0/0"
        self.write_scope()
        with self.assertRaisesRegex(make_scope.ScopeError, "source_cidr must be"):
            make_scope.read_scope_inputs(self.cells_path, self.scope_path)

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
