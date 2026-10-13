"""Tests for the competition-platform export adapter."""

import csv
import contextlib
import io
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml

from import_platform_exports import (
    ExportError,
    main,
    read_platform_cells,
    read_platform_scope,
)


def platform_cells():
    rows = []
    for enterprise, prefix in (("enta", "ENT-A"), ("entb", "ENT-B")):
        offset = 10 if enterprise == "enta" else 20
        for number in range(1, 10):
            application = f"APP{number:02}"
            rows.append({
                "name": f"jengasec-{prefix.lower()}-{application.lower()}",
                "enterprise": enterprise,
                "code": application,
                "kind": "app",
                "enabled": True,
                "service": f"Service {application}",
                "team": f"JS26-B-{number:03}",
                "service_ip": f"10.108.0.{offset + number}",
            })
    return {"cells": rows}


def write_scope(path, **overrides):
    row = {
        "red_team": "JS26-R-001",
        "red_cell": "APPRED01",
        "enterprise": "enta",
        "target_cell": "APP01",
        "target_namespace": "jengasec-ent-a-app01",
        "target_service_ip": "10.108.0.11",
        "wg_range": "10.60.1.0/24",
        "round_active": "true",
        "notes": "test assignment",
    }
    row.update(overrides)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(row))
        writer.writeheader()
        writer.writerow(row)


class PlatformExportTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = pathlib.Path(self.directory.name)
        self.cells_path = self.root / "cells.yaml"
        self.cells_path.write_text(yaml.safe_dump(platform_cells()), encoding="utf-8")
        self.scope_path = self.root / "scope.csv"

    def test_cell_and_scope_exports_map_to_infrastructure_contract(self):
        write_scope(self.scope_path)
        cells = read_platform_cells(self.cells_path)
        scope = read_platform_scope(self.scope_path, cells)

        self.assertEqual(len(cells["cells"]), 18)
        self.assertEqual(cells["cells"][0], {
            "namespace": "jengasec-ent-a-app01",
            "enterprise": "ENT-A",
            "application": "APP01",
            "reserved_ip": "10.108.0.11",
            "optional": False,
            "enabled": True,
            "service": "Service APP01",
        })
        self.assertEqual(scope, [{
            "team_id": "JS26-R-001",
            "source_cidr": "10.60.1.0/24",
            "enterprise": "ENT-A",
            "application": "APP01",
            "namespace": "jengasec-ent-a-app01",
            "target_ip": "10.108.0.11",
            "active": "true",
            "notes": "test assignment",
        }])

    def test_noncanonical_namespace_is_rejected(self):
        document = platform_cells()
        document["cells"][0]["name"] = "enta-app01"
        self.cells_path.write_text(yaml.safe_dump(document), encoding="utf-8")

        with self.assertRaisesRegex(ExportError, "namespace must be jengasec-ent-a-app01"):
            read_platform_cells(self.cells_path)

    def test_mismatched_scope_service_ip_is_rejected(self):
        write_scope(self.scope_path, target_service_ip="10.108.0.12")
        cells = read_platform_cells(self.cells_path)

        with self.assertRaisesRegex(ExportError, "mismatched target service IP"):
            read_platform_scope(self.scope_path, cells)

    def test_missing_application_instance_is_rejected(self):
        document = platform_cells()
        document["cells"].pop()
        self.cells_path.write_text(yaml.safe_dump(document), encoding="utf-8")

        with self.assertRaisesRegex(ExportError, "expected 18 application cells"):
            read_platform_cells(self.cells_path)

    def test_optional_applications_must_be_enabled_symmetrically(self):
        document = platform_cells()
        document["cells"][8]["enabled"] = False
        self.cells_path.write_text(yaml.safe_dump(document), encoding="utf-8")

        with self.assertRaisesRegex(ExportError, "APP09 must be enabled symmetrically"):
            read_platform_cells(self.cells_path)

    def test_cli_writes_infrastructure_cells_and_scope_exports(self):
        write_scope(self.scope_path)
        cells_output = self.root / "generated" / "cells.yaml"
        scope_output = self.root / "generated" / "scope.csv"
        args = [
            "import_platform_exports.py",
            "--cells", str(self.cells_path),
            "--scope", str(self.scope_path),
            "--cells-output", str(cells_output),
            "--scope-output", str(scope_output),
        ]
        with patch.object(sys, "argv", args), contextlib.redirect_stdout(io.StringIO()):
            main()

        generated_cells = yaml.safe_load(cells_output.read_text(encoding="utf-8"))
        self.assertEqual(len(generated_cells["cells"]), 18)
        with scope_output.open(newline="", encoding="utf-8") as handle:
            generated_scope = list(csv.DictReader(handle))
        self.assertEqual(generated_scope[0]["target_ip"], "10.108.0.11")


if __name__ == "__main__":
    unittest.main()
