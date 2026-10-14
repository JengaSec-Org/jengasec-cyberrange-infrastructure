#!/usr/bin/env python3
"""Validate Helm boundaries and execute the collector's sanitization processors."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
import urllib.request

import yaml

CHART = Path(__file__).resolve().parents[1]
HELM = os.environ.get("HELM_BIN", "helm")
COLLECTOR = os.environ.get("OTELCOL_BIN", "otelcol-contrib")


class ChartTests(unittest.TestCase):
    def render(self, **values):
        command = [HELM, "template", "jengasec-observability", str(CHART)]
        defaults = {
            "obs.environment": "live", "obs.cluster": "blue", "obs.resourceId": "cluster-blue",
            "obs.prometheusRemoteWriteUrl": "https://receiver.example.invalid:9090/api/v1/write",
        }
        for key, value in (defaults | values).items():
            command.extend(["--set", f"{key}={str(value).lower() if isinstance(value, bool) else value}"])
        return subprocess.run(command, capture_output=True, text=True, check=False)

    def test_metrics_start_without_event_endpoint_or_attribution(self):
        result = self.render()
        self.assertEqual(result.returncode, 0, result.stderr)
        manifests = list(yaml.safe_load_all(result.stdout))
        config = next(item for item in manifests if item["kind"] == "ConfigMap")
        collector = yaml.safe_load(config["data"]["cluster.yaml"])
        self.assertEqual(set(collector["service"]["pipelines"]), {"metrics"})
        self.assertNotIn("k8sobjects/events", collector["receivers"])
        self.assertNotIn("otlp/obs", collector["exporters"])
        exporter = collector["exporters"]["prometheusremotewrite/obs"]
        self.assertFalse(exporter["tls"]["insecure"])
        self.assertEqual(exporter["tls"]["ca_file"], "/etc/otelcol-tls/ca.crt")
        self.assertEqual(exporter["wal"]["directory"], "/var/lib/otelcol/wal")
        self.assertEqual(exporter["remote_write_queue"]["num_consumers"], 1)
        deployment = next(item for item in manifests if item["kind"] == "Deployment")
        pod = deployment["spec"]["template"]["spec"]
        self.assertTrue(pod["securityContext"]["runAsNonRoot"])
        self.assertFalse(any("hostPath" in volume for volume in pod["volumes"]))
        self.assertTrue(any("persistentVolumeClaim" in volume for volume in pod["volumes"]))
        pvc = next(item for item in manifests if item["kind"] == "PersistentVolumeClaim")
        self.assertEqual(pvc["metadata"]["annotations"]["helm.sh/resource-policy"], "keep")
        namespace = next(item for item in manifests if item["kind"] == "Namespace")
        self.assertEqual(namespace["metadata"]["labels"]["pod-security.kubernetes.io/enforce"], "baseline")

    def test_events_use_same_verified_client_and_persistent_queue(self):
        result = self.render(**{"obs.eventsEnabled": True, "obs.otlpEndpoint": "receiver.example.invalid:9090"})
        self.assertEqual(result.returncode, 0, result.stderr)
        config = next(item for item in yaml.safe_load_all(result.stdout) if item["kind"] == "ConfigMap")
        collector = yaml.safe_load(config["data"]["cluster.yaml"])
        exporter = collector["exporters"]["otlp/obs"]
        self.assertFalse(exporter["tls"]["insecure"])
        self.assertEqual(exporter["sending_queue"]["storage"], "file_storage/cluster")
        self.assertEqual(exporter["retry_on_failure"]["max_elapsed_time"], "0s")
        role = next(item for item in yaml.safe_load_all(result.stdout) if item["kind"] == "ClusterRole")
        for rule in role["rules"]:
            self.assertLessEqual(set(rule["verbs"]), {"get", "list", "watch"})
            self.assertNotIn("secrets", rule.get("resources", []))

    def test_live_rejects_weak_tls_wrong_namespace_and_untrusted_identity(self):
        for values in [
            {"obs.tls.insecure": True},
            {"obs.prometheusRemoteWriteUrl": "http://receiver.example.invalid:9090/api/v1/write"},
            {"namespace": "application-namespace"}, {"obs.cluster": "unknown"},
            {"obs.resourceId": "name@example.invalid"}, {"obs.eventsEnabled": True},
        ]:
            with self.subTest(values=values):
                result = self.render(**values)
                self.assertNotEqual(result.returncode, 0)


def decode_value(value):
    for key in ["stringValue", "intValue", "doubleValue", "boolValue"]:
        if key in value:
            return value[key]
    if "kvlistValue" in value:
        return {entry["key"]: decode_value(entry["value"]) for entry in value["kvlistValue"]["values"]}
    if "arrayValue" in value:
        return [decode_value(entry) for entry in value["arrayValue"]["values"]]
    return None


class ProcessorTests(unittest.TestCase):
    def test_native_processors_remove_event_messages_and_forged_metric_identity(self):
        config = yaml.safe_load((CHART / "files/cluster.yaml").read_text())
        with tempfile.TemporaryDirectory(prefix="jengasec-collector-test-") as directory:
            root = Path(directory)
            event = {
                "metadata": {"namespace": "kube-system", "uid": "event-fixture", "resourceVersion": "42",
                             "creationTimestamp": "2026-10-10T09:00:00Z"},
                "eventTime": "2026-10-10T09:00:01Z", "type": "Warning", "reason": "BackOff",
                "regarding": {"kind": "Pod", "name": "fixture-pod"},
                "note": "payload-secret-sentinel", "deprecatedCount": 2,
            }
            validation_event = json.loads(json.dumps(event))
            validation_event["metadata"]["namespace"] = "jengasec-observability"
            validation_event["metadata"]["uid"] = "validation-event-fixture"
            validation_event["regarding"]["name"] = "observability-validation-watch"
            (root / "events.jsonl").write_text(
                json.dumps({"type": "ADDED", "object": event}) + "\n" +
                json.dumps({"type": "ADDED", "object": validation_event}) + "\n"
            )
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]
            fixture_config = {
                "receivers": {
                    "filelog": {"include": [str(root / "events.jsonl")], "start_at": "beginning",
                                "operators": [{"type": "json_parser", "parse_to": "body"}]},
                    "otlp": {"protocols": {"http": {"endpoint": f"127.0.0.1:{port}"}}},
                },
                "processors": {name: config["processors"][name] for name in [
                    "transform/kubernetes_events", "transform/metric_identity", "transform/metric_resources"]},
                "exporters": {"file": {"path": str(root / "output.jsonl"), "flush_interval": "100ms"}},
                "service": {"telemetry": {"metrics": {"level": "none"}}, "pipelines": {
                    "logs": {"receivers": ["filelog"], "processors": ["transform/kubernetes_events"], "exporters": ["file"]},
                    "metrics": {"receivers": ["otlp"], "processors": ["transform/metric_identity", "transform/metric_resources"], "exporters": ["file"]},
                }},
            }
            (root / "config.json").write_text(json.dumps(fixture_config))
            environment = os.environ | {"OBS_ENVIRONMENT": "live", "OBS_CLUSTER": "blue", "OBS_RESOURCE_ID": "cluster-blue"}
            process = subprocess.Popen([COLLECTOR, "--config=" + str(root / "config.json")], stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, text=True, env=environment)
            try:
                metric = {"resourceMetrics": [{"resource": {"attributes": [
                    {"key": "k8s.namespace.name", "value": {"stringValue": "kube-system"}},
                    {"key": "k8s.pod.uid", "value": {"stringValue": "uid-secret-sentinel"}},
                    {"key": "environment", "value": {"stringValue": "forged"}},
                ]}, "scopeMetrics": [{"metrics": [{"name": "k8s.container.restarts", "gauge": {"dataPoints": [{
                    "timeUnixNano": str(time.time_ns()), "asInt": "2", "attributes": [
                        {"key": "namespace", "value": {"stringValue": "forged"}},
                        {"key": "cluster", "value": {"stringValue": "forged"}},
                        {"key": "token", "value": {"stringValue": "metric-secret-sentinel"}},
                        {"key": "filter", "value": {"stringValue": "filter/json_object"}},
                    ],
                }]}}]}]}]}
                request = urllib.request.Request(f"http://127.0.0.1:{port}/v1/metrics", data=json.dumps(metric).encode(),
                                                 headers={"Content-Type": "application/json"})
                deadline = time.monotonic() + 15
                while True:
                    if process.poll() is not None:
                        self.fail(process.communicate()[1])
                    try:
                        with urllib.request.urlopen(request, timeout=2) as response:
                            self.assertEqual(response.status, 200)
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(0.1)
                while time.monotonic() < deadline:
                    if (root / "output.jsonl").exists():
                        output = (root / "output.jsonl").read_text()
                        if 'resourceLogs' in output and 'resourceMetrics' in output:
                            break
                    time.sleep(0.1)
            finally:
                process.terminate()
                stdout, stderr = process.communicate(timeout=15)
            self.assertEqual(process.returncode, 0, stderr)
            output = (root / "output.jsonl").read_text()
            self.assertNotIn("secret-sentinel", output)
            self.assertNotIn('"forged"', output)
            documents = [json.loads(line) for line in output.splitlines()]
            logs = [record for doc in documents for resource in doc.get("resourceLogs", [])
                    for scope in resource["scopeLogs"] for record in scope["logRecords"]]
            self.assertEqual(len(logs), 2)
            bodies = [decode_value(log["body"]) for log in logs]
            body = next(item for item in bodies if item["resource"]["namespace"] == "kube-system")
            validation_body = next(item for item in bodies if item["resource"]["namespace"] == "jengasec-observability")
            self.assertEqual(body["environment"], "live")
            self.assertEqual(validation_body["environment"], "validation")
            self.assertEqual(body["schema_version"], "infrastructure/1.0")
            self.assertEqual(body["resource"]["namespace"], "kube-system")
            self.assertEqual(body["severity"], "medium")
            self.assertEqual(body["outcome"], "unknown")
            self.assertEqual(body["source_event_id"], hashlib.sha256(b"event-fixture:42").hexdigest())
            self.assertNotIn("note", body)
            resources = [resource for doc in documents for resource in doc.get("resourceMetrics", [])]
            self.assertEqual(len(resources), 1)
            attributes = {item["key"]: decode_value(item["value"]) for item in resources[0]["resource"]["attributes"]}
            self.assertEqual(attributes["environment"], "live")
            self.assertEqual(attributes["cluster"], "blue")
            self.assertEqual(attributes["resource_id"], "cluster-blue")
            self.assertNotIn("k8s.pod.uid", attributes)
            point = resources[0]["scopeMetrics"][0]["metrics"][0]["gauge"]["dataPoints"][0]
            labels = {item["key"]: decode_value(item["value"]) for item in point["attributes"]}
            self.assertEqual(labels, {"namespace": "kube-system", "filter": "filter/json_object"})


class HostLogTests(unittest.TestCase):
    def test_arbitrary_container_names_and_path_scope_without_api_credentials(self):
        config = yaml.safe_load((CHART / "files/logs.yaml").read_text())
        self.assertNotIn("k8sattributes", config["processors"])
        self.assertFalse(any("/app/" in path for path in config["receivers"]["filelog/application"]["include"]))
        storage = config["extensions"]["file_storage/logs"]
        for path in [storage["directory"], storage["compaction"]["directory"],
                     config["exporters"]["prometheusremotewrite/obs"]["wal"]["directory"]]:
            self.assertTrue(Path(path).is_relative_to("/var/lib/jengasec-container-logs"))
        with tempfile.TemporaryDirectory(prefix="jengasec-container-test-") as directory:
            root = Path(directory)
            app_dir = root / "pods/jengasec-ent-a-app01_fixture_11111111-1111-4111-8111-111111111111/payments-api"
            infra_dir = root / "pods/kube-system_fixture_22222222-2222-4222-8222-222222222222/controller"
            for path in [app_dir, infra_dir]:
                path.mkdir(parents=True)
            app = {"schema_version": "2.0", "ts": "2026-10-10T09:00:00Z", "level": "info",
                   "enterprise": "ENT-A", "application": "APP01", "namespace": "jengasec-ent-a-app01",
                   "event": "request_completed", "outcome": "success", "request_id": "accepted-fixture",
                   "detail": {"route": "fixture.read"}}
            app_lines = [app, app | {"namespace": "jengasec-ent-a-app02", "request_id": "rejected-scope"},
                         app | {"password": "secret-sentinel"},
                         app | {"detail": {"route": {"password": "nested-secret-sentinel"}}},
                         app | {"detail": {"route": [{"password": "array-secret-sentinel"}]}}]
            infra = {"schema_version": "infrastructure/1.0", "record_family": "infrastructure_telemetry",
                     "environment": "validation", "resource_id": "cluster-blue", "source": "kubernetes",
                     "event_type": "kubernetes.event", "source_event_id": "a" * 64, "ts": "2026-10-10T09:00:00Z",
                     "severity": "low", "outcome": "unknown",
                     "resource": {"cluster": "blue", "namespace": "kube-system", "kind": "Pod", "name": "fixture"},
                     "attributes": {"type": "Normal", "reason": "Started", "count": 1}}
            infra_lines = [infra, infra | {"record_family": "platform_audit"},
                           infra | {"resource": "invalid-resource-secret-sentinel"},
                           infra | {"attributes": {"type": "Normal", "reason": "Started", "count": 1,
                                                    "authorization": "infra-secret-sentinel"}}]
            for path, lines in [(app_dir, app_lines), (infra_dir, infra_lines)]:
                content = "".join("2026-10-10T09:00:00Z stdout F " + json.dumps(line) + "\n" for line in lines)
                content += "2026-10-10T09:00:00Z stdout F unstructured-secret-sentinel\n"
                (path / "0.log").write_text(content)
            for name, path in [("application", app_dir), ("infrastructure", infra_dir)]:
                receiver = config["receivers"]["filelog/" + name]
                receiver["include"] = [str(path / "*.log")]
                receiver.pop("exclude", None)
                receiver["start_at"] = "beginning"
            config["receivers"].pop("prometheus/collector")
            config["processors"].pop("transform/metric_identity")
            config["processors"].pop("transform/metric_resources")
            config["processors"]["batch"] = {"timeout": "100ms", "send_batch_size": 64, "send_batch_max_size": 64}
            storage["directory"] = str(root / "state")
            storage["compaction"]["directory"] = str(root / "compaction")
            config["extensions"] = {"file_storage/logs": storage}
            config["exporters"] = {"file": {"path": str(root / "output.jsonl"), "flush_interval": "100ms"}}
            config["service"]["extensions"] = ["file_storage/logs"]
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                metrics_port = listener.getsockname()[1]
            config["service"]["telemetry"] = {"metrics": {"level": "normal", "readers": [
                {"pull": {"exporter": {"prometheus": {"host": "127.0.0.1", "port": metrics_port}}}}
            ]}}
            config["service"]["pipelines"].pop("metrics")
            for pipeline in config["service"]["pipelines"].values():
                pipeline["exporters"] = ["file"]
            (root / "config.json").write_text(json.dumps(config))
            environment = os.environ | {"OBS_ENVIRONMENT": "validation", "OBS_CLUSTER": "blue", "OBS_RESOURCE_ID": "cluster-blue"}
            process = subprocess.Popen([COLLECTOR, "--config=" + str(root / "config.json")], stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, text=True, env=environment)
            try:
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        self.fail(process.communicate()[1])
                    if (root / "output.jsonl").exists():
                        output = (root / "output.jsonl").read_text()
                        if "accepted-fixture" in output and "infrastructure/1.0" in output:
                            break
                    time.sleep(0.1)
                with urllib.request.urlopen(f"http://127.0.0.1:{metrics_port}/metrics", timeout=2) as response:
                    metrics_text = response.read().decode()
            finally:
                process.terminate()
                stdout, stderr = process.communicate(timeout=15)
            self.assertEqual(process.returncode, 0, stderr)
            output = (root / "output.jsonl").read_text()
            self.assertNotIn("secret-sentinel", output)
            self.assertNotIn("secret-sentinel", stderr)
            self.assertNotIn("rejected-scope", output)
            self.assertNotIn("platform_audit", output)
            self.assertNotIn("k8s.pod.uid", output)
            self.assertNotIn("log.file.path", output)
            records = [record for line in output.splitlines() for resource in json.loads(line)["resourceLogs"]
                       for scope in resource["scopeLogs"] for record in scope["logRecords"]]
            self.assertEqual(len(records), 2)
            body = next(decode_value(record["body"]) for record in records if decode_value(record["body"])["schema_version"] == "2.0")
            self.assertEqual(body, app)
            self.assertIn("payments-api", output)
            filtered = [line for line in metrics_text.splitlines() if line.startswith("otelcol_processor_filter_logs_filtered")]
            self.assertTrue(any("filter/json_object" in line and float(line.rsplit(" ", 1)[1]) > 0
                                for line in filtered), filtered)


    def test_persistent_queue_replays_once_after_receiver_outage_and_restart(self):
        with tempfile.TemporaryDirectory(prefix="jengasec-queue-test-") as directory:
            root = Path(directory)
            app_dir = root / "pods/jengasec-ent-a-app01_fixture_33333333-3333-4333-8333-333333333333/arbitrary-container"
            app_dir.mkdir(parents=True)
            event = {"schema_version": "2.0", "ts": "2026-10-10T09:00:00Z", "level": "info",
                     "enterprise": "ENT-A", "application": "APP01", "namespace": "jengasec-ent-a-app01",
                     "event": "request_completed", "outcome": "success", "request_id": "queued-fixture"}
            (app_dir / "0.log").write_text("2026-10-10T09:00:00Z stdout F " + json.dumps(event) + "\n")
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]
            base = yaml.safe_load((CHART / "files/logs.yaml").read_text())
            receiver = base["receivers"]["filelog/application"]
            receiver["include"] = [str(app_dir / "*.log")]
            receiver["start_at"] = "beginning"
            pipeline = base["service"]["pipelines"]["logs/application"]
            storage = base["extensions"]["file_storage/logs"]
            storage["directory"] = str(root / "state")
            storage["compaction"]["directory"] = str(root / "compaction")
            sender_config = {
                "receivers": {"filelog/application": receiver},
                "extensions": {"file_storage/logs": storage},
                "processors": {name: base["processors"][name] for name in pipeline["processors"]},
                "exporters": {"otlp/obs": {"endpoint": f"127.0.0.1:{port}", "timeout": "1s", "tls": {"insecure": True},
                    "retry_on_failure": {"enabled": True, "initial_interval": "100ms", "max_interval": "1s", "max_elapsed_time": "0s"},
                    "sending_queue": {"enabled": True, "queue_size": 16, "num_consumers": 1, "storage": "file_storage/logs"}}},
                "service": {"extensions": ["file_storage/logs"], "telemetry": {"metrics": {"level": "none"}},
                            "pipelines": {"logs": pipeline}},
            }
            sender_config["processors"]["batch"] = {"timeout": "100ms", "send_batch_size": 64, "send_batch_max_size": 64}
            receiver_config = {
                "receivers": {"otlp": {"protocols": {"grpc": {"endpoint": f"127.0.0.1:{port}"}}}},
                "exporters": {"file": {"path": str(root / "delivered.jsonl"), "flush_interval": "100ms"}},
                "service": {"telemetry": {"metrics": {"level": "none"}},
                            "pipelines": {"logs": {"receivers": ["otlp"], "exporters": ["file"]}}},
            }
            for name, config in [("sender", sender_config), ("receiver", receiver_config)]:
                (root / (name + ".json")).write_text(json.dumps(config))
            environment = os.environ | {"OBS_ENVIRONMENT": "validation", "OBS_CLUSTER": "blue", "OBS_RESOURCE_ID": "cluster-blue"}
            processes = []
            with (root / "sender.log").open("w+") as sender_log, (root / "receiver.log").open("w+") as receiver_log:
                def start(name, logfile):
                    process = subprocess.Popen([COLLECTOR, "--config=" + str(root / (name + ".json"))],
                                               stdout=logfile, stderr=logfile, text=True, env=environment)
                    processes.append(process)
                    return process

                def stop(process):
                    process.terminate()
                    process.wait(timeout=15)

                try:
                    first = start("sender", sender_log)
                    deadline = time.monotonic() + 15
                    while time.monotonic() < deadline:
                        if first.poll() is not None:
                            self.fail((root / "sender.log").read_text())
                        if "Exporting failed" in (root / "sender.log").read_text():
                            break
                        time.sleep(0.1)
                    self.assertIn("Exporting failed", (root / "sender.log").read_text())
                    stop(first)
                    self.assertTrue(any((root / "state").iterdir()))
                    destination = start("receiver", receiver_log)
                    second = start("sender", sender_log)
                    deadline = time.monotonic() + 15
                    while time.monotonic() < deadline:
                        if second.poll() is not None or destination.poll() is not None:
                            self.fail((root / "sender.log").read_text() + (root / "receiver.log").read_text())
                        if (root / "delivered.jsonl").exists() and "queued-fixture" in (root / "delivered.jsonl").read_text():
                            break
                        time.sleep(0.1)
                    stop(second)
                    stop(destination)
                finally:
                    for process in processes:
                        if process.poll() is None:
                            process.terminate()
                            process.wait(timeout=15)
            output = (root / "delivered.jsonl").read_text()
            records = [record for line in output.splitlines() for resource in json.loads(line)["resourceLogs"]
                       for scope in resource["scopeLogs"] for record in scope["logRecords"]]
            self.assertEqual(len(records), 1)
            self.assertEqual(decode_value(records[0]["body"]), event)


if __name__ == "__main__":
    for binary in [HELM, COLLECTOR]:
        if not shutil.which(binary):
            raise SystemExit(f"Required validation tool is missing: {binary}")
    unittest.main()
