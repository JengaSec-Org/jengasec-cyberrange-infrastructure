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
            (root / "events.jsonl").write_text(json.dumps(event) + "\n")
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
            self.assertEqual(len(logs), 1)
            body = decode_value(logs[0]["body"])
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
            self.assertEqual(labels, {"namespace": "kube-system"})


if __name__ == "__main__":
    for binary in [HELM, COLLECTOR]:
        if not shutil.which(binary):
            raise SystemExit(f"Required validation tool is missing: {binary}")
    unittest.main()
