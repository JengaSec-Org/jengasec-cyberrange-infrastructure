#!/usr/bin/env python3
"""Exercise OBS configuration notifications and the native mTLS receiver.

Run with ansible-playbook on PATH, or set OBS_TEST_ANSIBLE. OBS_TEST_SOURCE_ROOT
may select a source checkout; the test copies it before running the role.
The nginx checks are mandatory in hosted CI and use its already cached image.
Set OBS_TEST_NGINX=1 for that check locally, or OBS_TEST_NGINX_BIN to an existing
nginx executable. All listeners, certificates and state are disposable.
"""

import hashlib
import http.client
import http.server
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(os.environ.get("GITHUB_ACTIONS") == "true" or os.environ.get("OBS_TEST_NGINX") == "1"
                     or os.environ.get("OBS_TEST_NGINX_BIN"), "set OBS_TEST_NGINX=1 or OBS_TEST_NGINX_BIN")
class NativeReceiverTlsTests(unittest.TestCase):
    def test_real_nginx_enforces_default_pin_methods_tenant_and_ingest_separation(self):
        from jinja2 import Environment, StrictUndefined

        source = Path(os.environ.get("OBS_TEST_SOURCE_ROOT", ROOT)).resolve()
        spec = importlib.util.spec_from_file_location("scoring_tls_fixture", source / "observability/tests/test-scoring-collector.py")
        fixture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixture)
        template = Environment(undefined=StrictUndefined).from_string(
            (source / "ansible/roles/observability/templates/infrastructure-nginx.conf.j2").read_text())
        image = yaml.safe_load((source / "observability/compose.production.yaml").read_text())["services"]["prometheus-write-proxy"]["image"]
        binary = None if os.environ.get("GITHUB_ACTIONS") == "true" else os.environ.get("OBS_TEST_NGINX_BIN")
        if not binary:
            # The preceding OBS VM rehearsal populated this exact image. Never
            # pull images implicitly, locally or when prerequisites regress.
            subprocess.run(["docker", "image", "inspect", image], check=True, capture_output=True, timeout=10)
        received = []

        class Upstream(http.server.BaseHTTPRequestHandler):
            def respond(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                received.append((self.command, self.path, self.headers.get("X-Scope-OrgID"),
                                 self.headers.get("Authorization"), body))
                if self.path == "/loki/api/v1/push":
                    self.send_response(204)
                    self.end_headers()
                    return
                data = b'{"status":"success","data":{"result":[]}}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = respond

            def log_message(self, *args):
                pass

        upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        worker = threading.Thread(target=upstream.serve_forever, daemon=True)
        worker.start()
        self.addCleanup(worker.join)
        self.addCleanup(upstream.server_close)
        self.addCleanup(upstream.shutdown)

        def unused_port():
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                return listener.getsockname()[1]

        with tempfile.TemporaryDirectory(prefix="obs-native-mtls-") as directory:
            root = Path(directory)
            material = fixture.tls_fixture(root)

            def fingerprint(identity):
                return hashlib.sha1(ssl.PEM_cert_to_DER_cert(Path(material[identity]["cert_file"]).read_text())).hexdigest()

            for pinned in (None, "collector", "generic"):
                with self.subTest(scoring_certificate_pin=pinned):
                    port, health = unused_port(), unused_port()
                    values = yaml.safe_load((source / "ansible/roles/observability/defaults/main.yml").read_text())
                    values["obs_infrastructure_attribution_certificate_sha1"] = fingerprint("generic")
                    if pinned:
                        values["obs_infrastructure_scoring_certificate_sha1"] = fingerprint(pinned)
                    if pinned == "generic":
                        values["obs_infrastructure_attribution_certificate_sha1"] = ""
                    config = template.render(values)
                    mounted = str(root) if binary else "/fixture"
                    scratch = str(root / "nginx-temp") if binary else "/tmp"
                    config = "pid " + scratch + "/nginx.pid;\nerror_log stderr warn;\n" + config
                    config = config.replace("http {", "http {\n" + "\n".join(
                        f"  {kind}_temp_path {scratch}/{kind};" for kind in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi")))
                    config = config.replace("listen 9443 ssl;", f"listen 127.0.0.1:{port} ssl;")
                    config = config.replace("listen 127.0.0.1:9090;", f"listen 127.0.0.1:{health};")
                    config = config.replace("/etc/jengasec-infrastructure/tls/server/server.crt", mounted + "/server.crt")
                    config = config.replace("/etc/jengasec-infrastructure/tls/server/server.key", mounted + "/server.key")
                    config = config.replace("/etc/jengasec-infrastructure/tls/ca.crt", mounted + "/ca.crt")
                    for upstream_name in ("loki:3100", "prometheus:9090", "vector:8687", "vector:8688", "vector:4317"):
                        config = config.replace(upstream_name, f"127.0.0.1:{upstream.server_port}")
                    if binary:
                        version = subprocess.run([binary, "-v"], check=True, capture_output=True, text=True).stderr
                        release = tuple(map(int, re.search(r"nginx/(\d+)\.(\d+)\.(\d+)", version).groups()))
                        if release < (1, 25, 1):
                            # Older installed nginx expresses only the HTTP/2
                            # switch differently; access and proxy rules stay exact.
                            config = config.replace("    http2 on;\n", "").replace(f":{port} ssl;", f":{port} ssl http2;")
                        Path(scratch).mkdir(exist_ok=True)
                    path = root / "nginx.conf"
                    path.write_text(config)
                    process, container = None, None
                    log = (root / "nginx.log").open("w+")
                    try:
                        if binary:
                            process = subprocess.Popen([binary, "-p", str(root), "-c", str(path),
                                                        "-g", "daemon off; master_process off;"], stdout=log, stderr=log)
                        else:
                            container = subprocess.run(["docker", "run", "--detach", "--pull=never",
                                "--network=host", "--read-only", "--security-opt=no-new-privileges:true",
                                "--tmpfs", "/tmp", "--tmpfs", "/var/cache/nginx", "--tmpfs", "/var/run",
                                "--mount", f"type=bind,src={root},dst=/fixture,readonly", "--entrypoint=nginx", image,
                                "-c", "/fixture/nginx.conf", "-g", "daemon off;"], check=True,
                                capture_output=True, text=True, timeout=15).stdout.strip()
                        for _ in range(100):
                            try:
                                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                                    break
                            except OSError:
                                if process and process.poll() is not None:
                                    break
                                time.sleep(0.05)
                        else:
                            self.fail("isolated nginx did not start")

                        def request(identity, method, route, body=None):
                            context = (fixture.client_tls(material[identity]) if identity is not None
                                       else ssl.create_default_context(cafile=material["collector"]["ca_file"]))
                            connection = http.client.HTTPSConnection("127.0.0.1", port, context=context, timeout=3)
                            try:
                                connection.request(method, route, body=body)
                                response = connection.getresponse()
                                response.read()
                                return response.status
                            except (ssl.SSLError, http.client.RemoteDisconnected):
                                return 0  # TLS refused before an HTTP response.
                            finally:
                                connection.close()

                        reads = "/loki/api/v1/query_range"
                        writes = "/loki/api/v1/push"
                        ingest = ("/api/v1/write", "/api/v1/infrastructure-events", "/api/v1/infrastructure-attribution",
                                  "/opentelemetry.proto.collector.logs.v1.LogsService/Export")
                        if pinned == "generic":
                            # A valid fingerprint without the dedicated CN must
                            # grant neither native reads/writes nor generic ingest.
                            for route, method in ((reads, "GET"), (writes, "POST"), *[(item, "POST") for item in ingest]):
                                self.assertEqual(request("generic", method, route), 403)
                            continue
                        self.assertEqual(request("generic", "POST", ingest[0], b"{}"), 200)
                        self.assertEqual(request("generic", "POST", ingest[1], b"{}"), 200)
                        self.assertEqual(request("generic", "POST", ingest[2], b"{}"), 200)
                        self.assertEqual(request("generic", "GET", ingest[0]), 403)
                        before = len(received)
                        expected = 403 if pinned else 404
                        self.assertEqual(request("generic", "GET", reads), expected)
                        self.assertEqual(request("generic", "POST", writes, b"{}"), expected)
                        self.assertIn(request(None, "GET", reads), (0, 400, 403))
                        self.assertIn(request("foreign", "GET", reads), (0, 400, 403))
                        for identity in ("collector", "retired"):
                            for route in ingest:
                                self.assertEqual(request(identity, "POST", route, b"{}"), 403)
                        self.assertEqual(request("retired", "GET", reads), expected)
                        self.assertEqual(request("retired", "POST", writes, b"{}"), expected)
                        self.assertEqual(len(received), before)
                        if not pinned:
                            self.assertEqual(request("collector", "GET", reads), 404)
                            continue
                        for route, methods in ((reads, ("POST", "HEAD", "PUT", "DELETE", "OPTIONS")),
                                               (writes, ("GET", "HEAD", "PUT", "DELETE", "OPTIONS"))):
                            for method in methods:
                                self.assertEqual(request("collector", method, route), 405, (route, method))
                        for route in ("/api/v1/query", "/loki/api/v1/delete", reads + "/extra"):
                            self.assertEqual(request("collector", "GET", route), 404)
                        self.assertEqual(len(received), before)
                        client = fixture.Client(f"https://127.0.0.1:{port}", tls=material["collector"],
                                                headers={"X-Scope-OrgID": "application-other", "Authorization": "Bearer fixture-only"})
                        query = reads + "?query=%7Bnamespace%3D%22scoped-target%22%7D"
                        self.assertEqual(client.call(query)[0], 200)
                        payload = {"streams": [{"stream": {"record_family": "competition_measurement", "source": "functional_probe"},
                                               "values": [["1", "fixture observation"]]}]}
                        self.assertEqual(client.call(writes, payload), (204, {}))
                        self.assertEqual(client.call(query)[0], 200)  # A repeated native read remains available.
                        for method, route, tenant, authorization, body in received[before:]:
                            self.assertEqual(tenant, "staff")
                            self.assertIsNone(authorization)
                            if method == "POST":
                                self.assertEqual(json.loads(body), payload)
                        self.assertEqual(received[before][1], query)
                    finally:
                        if process:
                            process.terminate()
                            process.wait(timeout=5)
                        if container:
                            subprocess.run(["docker", "logs", container], stdout=log, stderr=log, timeout=5)
                            subprocess.run(["docker", "rm", "-f", container], check=True, capture_output=True, timeout=10)
                        log.seek(0)
                        diagnostic = log.read()
                        log.close()
                        self.assertNotIn("[emerg]", diagnostic, diagnostic[-3000:])


class ConfigurationNotificationTests(unittest.TestCase):
    def test_publisher_and_environment_changes_notify_but_identical_runs_do_not(self):
        ansible = os.environ.get("OBS_TEST_ANSIBLE") or shutil.which("ansible-playbook")
        self.assertTrue(ansible, "ansible-playbook is required for the notification regression")
        source = Path(os.environ.get("OBS_TEST_SOURCE_ROOT", ROOT)).resolve()
        with tempfile.TemporaryDirectory(prefix="jengasec-config-notifications-") as temporary:
            base = Path(temporary)
            checkout = base / "source"
            # Freeze the inputs across every same-release run. No source checkout
            # or running service is changed by this test.
            for directory in ("scripts", "contracts", "observability", "ansible/roles/observability"):
                shutil.copytree(source / directory, checkout / directory,
                                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".runtime"))
            play = yaml.safe_load((source / "ansible/observability-rehearsal.yml").read_text())[0]
            play["vars"].update({
                "obs_rehearsal_root": str(base / "runtime"),
                "obs_rehearsal_mode": False,
                "obs_attribution_mode": "disabled",
                "obs_infrastructure_enabled": False,
                "obs_manage_packages": False,
                "obs_manage_systemd": False,
                "obs_manage_storage_ownership": False,
                "obs_validate_runtime": False,
                "obs_validate_network": False,
                "obs_start": False,
                "obs_python_command": sys.executable,
            })
            play["handlers"] = [{
                "name": "Record a requested OBS restart in the isolated test directory",
                "listen": "Restart observability stack",
                "ansible.builtin.command": {
                    "argv": [sys.executable, "-c",
                             "import pathlib,sys; "
                             "pathlib.Path(sys.argv[1]).open('a', encoding='utf-8').write('notified\\n')",
                             "{{ obs_rehearsal_root }}/notifications.txt"],
                },
                "changed_when": True,
            }]
            playbook = checkout / "ansible/config-notifications.yml"
            playbook.write_text(yaml.safe_dump([play], sort_keys=False))
            runtime = base / "runtime"
            runtime.mkdir(mode=0o700)
            notifications = runtime / "notifications.txt"
            values = {"obs_website_feed_url": "https://receiver.example/api/feed", "obs_grafana_port": 3000}

            def run(expected_error=None):
                variables = base / "variables.json"
                variables.write_text(json.dumps(values))
                environment = dict(os.environ, ANSIBLE_NOCOLOR="1", ANSIBLE_STDOUT_CALLBACK="default")
                result = subprocess.run(
                    [ansible, "--inventory", "localhost,", "--forks", "1", str(playbook),
                     "--extra-vars", "@" + str(variables)],
                    cwd=checkout, env=environment, text=True, capture_output=True, timeout=180)
                if expected_error:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(expected_error, result.stdout + result.stderr)
                    return None
                self.assertEqual(result.returncode, 0, (result.stdout + result.stderr)[-6000:])
                recap = re.search(r"localhost\s+:\s+ok=\d+\s+changed=(\d+)\s+unreachable=0\s+failed=0", result.stdout)
                self.assertIsNotNone(recap, result.stdout[-1500:])
                return int(recap.group(1))

            def notification_count():
                return len(notifications.read_text().splitlines()) if notifications.exists() else 0

            def vector():
                return yaml.safe_load((runtime / "state/lookups/vector.yaml").read_text())

            self.assertGreater(run(), 0)
            self.assertIn("website_feed_publisher", vector()["sinks"])
            initial_notifications = notification_count()
            self.assertGreater(initial_notifications, 0)
            fingerprint = (runtime / "opt/current/.source-sha256").read_bytes()
            refresh_unit = runtime / "etc/units/jengasec-observability-refresh.service"
            self.assertNotIn("--manage-grafana-access", refresh_unit.read_text())

            self.assertEqual(run(), 0, "identical configured deployment must be idempotent")
            self.assertEqual(notification_count(), initial_notifications)

            values["obs_website_feed_url"] = ""
            self.assertGreater(run(), 0, "disabling the publisher must request a restart")
            self.assertNotIn("website_feed_publisher", vector()["sinks"])
            self.assertNotIn("sanitized_website_feed", vector()["transforms"])
            self.assertEqual(notification_count(), initial_notifications + 1)
            self.assertEqual((runtime / "opt/current/.source-sha256").read_bytes(), fingerprint)

            self.assertEqual(run(), 0, "identical disabled deployment must be idempotent")
            self.assertEqual(notification_count(), initial_notifications + 1)

            values["obs_grafana_port"] = 3001
            self.assertGreater(run(), 0, "an environment-only change must request a restart")
            self.assertIn("JENGASEC_GRAFANA_PORT=3001", (runtime / "etc/observability.env").read_text())
            self.assertEqual(notification_count(), initial_notifications + 2)
            self.assertEqual((runtime / "opt/current/.source-sha256").read_bytes(), fingerprint)

            self.assertEqual(run(), 0, "identical environment deployment must be idempotent")
            self.assertEqual(notification_count(), initial_notifications + 2)
            self.assertFalse((runtime / "systemd").exists(), "test must not install host systemd units")

            values["obs_manage_grafana_access"] = False
            self.assertGreater(run(), 0)
            self.assertIn("--manage-grafana-access false", refresh_unit.read_text())
            self.assertEqual(notification_count(), initial_notifications + 2,
                             "changing only refresh access must not restart the stack")
            self.assertEqual((runtime / "opt/current/.source-sha256").read_bytes(), fingerprint)
            self.assertEqual(run(), 0, "identical access settings must be idempotent")

            current = (runtime / "opt/current").resolve()
            retained = runtime / "opt/releases/older-refresh"
            shutil.copytree(current, retained)
            (retained / "scripts/refresh-observability-state.sh").write_text("#!/bin/sh\nexit 0\n")
            values.update(obs_activate_existing_release=True, obs_release_id="older-refresh")
            run("The selected release cannot disable Grafana access management")
            self.assertEqual((runtime / "opt/current").resolve(), current)
            self.assertIn("--manage-grafana-access false", refresh_unit.read_text())
            self.assertEqual(notification_count(), initial_notifications + 2)


if __name__ == "__main__":
    unittest.main()
