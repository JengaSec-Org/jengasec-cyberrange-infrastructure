#!/usr/bin/env python3
"""Verify that absent or malformed publishers cannot redirect local telemetry."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]


class PublisherTests(unittest.TestCase):
    def render(self, output, url=None):
        command = [sys.executable, str(ROOT / "scripts/render-vector-catalogue.py"),
                   "--catalogue", str(ROOT / "contracts/telemetry-event-catalogue.yaml"),
                   "--cells", str(ROOT / "scripts/cells.yaml"),
                   "--template", str(ROOT / "observability/vector/vector.yaml"),
                   "--output-dir", str(output)]
        if url is not None:
            command += ["--website-feed-url", url]
        return subprocess.run(command, capture_output=True, text=True)

    def test_unconfigured_publisher_keeps_local_storage_and_normalization(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            self.assertEqual(self.render(output).returncode, 0)
            disabled = yaml.safe_load((output / "vector.yaml").read_text())
            self.assertNotIn("website_feed_publisher", disabled["sinks"])
            self.assertNotIn("sanitized_website_feed", disabled["transforms"])
            self.assertEqual(self.render(output, "https://receiver.example/api/feed").returncode, 0)
            enabled = yaml.safe_load((output / "vector.yaml").read_text())
            self.assertEqual(enabled["sinks"].pop("website_feed_publisher")["uri"],
                             "https://receiver.example/api/feed")
            enabled["transforms"].pop("sanitized_website_feed")
            self.assertEqual(disabled, enabled)

    def test_rejected_urls_cannot_replace_existing_configuration(self):
        urls = ["https://user:secret@receiver.example/api/feed",
                "https://receiver.example/api/feed?token=secret",
                "https://receiver.example/api/feed#fragment", "file:///api/feed",
                "https://receiver.example/other", "//receiver.example/api/feed"]
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            self.assertEqual(self.render(output).returncode, 0)
            original = (output / "vector.yaml").read_bytes()
            for url in urls:
                with self.subTest(url=url):
                    self.assertNotEqual(self.render(output, url).returncode, 0)
                    self.assertEqual((output / "vector.yaml").read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
