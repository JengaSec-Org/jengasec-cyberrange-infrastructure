#!/usr/bin/env python3
"""Pause only OBS collectors when their remote-write WAL threatens local disk.

The timer observes allocated bytes as well as logical size. A pause is latched
before stopping collection, preserves all state, and requires explicit resume.
The limit can overshoot by a check interval plus graceful shutdown time.
"""

import argparse
import fcntl
import json
import os
import shutil
import stat
import subprocess
import tempfile
import time
from pathlib import Path


NAMESPACE = "jengasec-observability"
DEPLOYMENT = "observability-cluster-collector"
CLAIM = "observability-cluster-state"
HOST_UNIT = "jengasec-container-logs.service"
HOST_WAL = Path("/var/lib/jengasec-container-logs/wal")
STORAGE_ROOT = Path("/var/lib/rancher/k3s/storage")
STATE_ROOT = Path("/var/lib/jengasec-observability-wal-guard")
METRICS_FILE = Path("/var/lib/jengasec-node-metrics/observability-wal-guard.prom")
K3S = "/usr/local/bin/k3s"
KUBECONFIG = "/etc/rancher/k3s/k3s.yaml"
COMPONENTS = {"cluster": "cluster-collector", "host": "container-log-reader"}


class GuardError(Exception):
    """A failed ownership check, measurement or OBS-only operation."""


def run(argv):
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=90,
                                env=os.environ | {"KUBECONFIG": KUBECONFIG})
    except (OSError, subprocess.TimeoutExpired) as error:
        raise GuardError("OBS command unavailable or timed out") from error
    if result.returncode:
        raise GuardError("OBS command failed")
    return result.stdout.strip()


def atomic_write(path, value, mode):
    if path.is_symlink() or path.parent.resolve() != path.parent:
        raise GuardError("Refusing a symlinked output path")
    with tempfile.NamedTemporaryFile("w", dir=path.parent, prefix=".wal-guard-", delete=False) as handle:
        temporary = Path(handle.name)
        try:
            os.fchmod(handle.fileno(), mode)
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


def directory(path):
    if not path.is_absolute() or path.resolve(strict=True) != path or not path.is_dir():
        raise GuardError("Refusing a missing, noncanonical or symlinked WAL path")
    return path


def measure(path):
    directory(path)
    used = 0
    for base, dirs, files in os.walk(path, followlinks=False):
        for name in dirs + files:
            item = Path(base) / name
            try:
                info = item.lstat()
            except FileNotFoundError:
                continue  # A writer may truncate a completed segment during inspection.
            if stat.S_ISLNK(info.st_mode) or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                raise GuardError("Refusing a nonregular WAL entry")
            if stat.S_ISREG(info.st_mode):
                used += max(info.st_size, info.st_blocks * 512)
    return used, shutil.disk_usage(path).free


def validate(config):
    if set(config) != {"cluster", "host_enabled", "max_wal_bytes", "min_free_bytes"}:
        raise GuardError("Unexpected guard configuration fields")
    if config["cluster"] not in ("red", "blue") or type(config["host_enabled"]) is not bool:
        raise GuardError("Invalid guard identity")
    for key in ("max_wal_bytes", "min_free_bytes"):
        if type(config[key]) is not int or not 0 < config[key] < 2**50:
            raise GuardError("Guard storage limits must be positive byte counts")
    return config


class Guard:
    def __init__(self, config, command=run, clock=time.time):
        self.config = validate(config)
        self.command = command
        self.clock = clock
        self.state_file = STATE_ROOT / "state.json"
        self.state = {"schema_version": 1, "targets": {}}
        if self.state_file.exists() or self.state_file.is_symlink():
            if self.state_file.is_symlink():
                raise GuardError("Refusing symlinked guard state")
            self.state = json.loads(self.state_file.read_text())
            if (self.state.get("schema_version") != 1
                    or not isinstance(self.state.get("targets"), dict)
                    or set(self.state["targets"]) - set(COMPONENTS)):
                raise GuardError("Invalid guard state; collection must remain paused")
            for value in self.state["targets"].values():
                if not isinstance(value, dict) or type(value.get("paused")) is not bool:
                    raise GuardError("Invalid target latch")

    def save(self):
        atomic_write(self.state_file, json.dumps(self.state, sort_keys=True) + "\n", 0o600)

    def kube(self, *args):
        return self.command([K3S, "kubectl", "--request-timeout=10s",
                             "--cache-dir=" + str(STATE_ROOT / "kubectl-cache"), *args])

    def object(self, kind, name, namespaced=True):
        args = ["get", kind, name, "-o", "json"]
        if namespaced:
            args += ["--namespace", NAMESPACE]
        return json.loads(self.kube(*args))

    def discover(self, target):
        if target == "host":
            directory(HOST_WAL)
            # The only service this guard may control is checked by exact unit name.
            unit = self.command(["systemctl", "show", HOST_UNIT, "--property=FragmentPath", "--value"])
            if unit != "/etc/systemd/system/" + HOST_UNIT:
                raise GuardError("Host reader is not the installed OBS unit")
            return {"path": str(HOST_WAL), "wal_inode": HOST_WAL.stat().st_ino}
        namespace = self.object("namespace", NAMESPACE, False)
        if namespace["metadata"].get("labels", {}).get("app.kubernetes.io/component") != "observability":
            raise GuardError("Cluster namespace is not OBS-owned")
        deployment = self.object("deployment", DEPLOYMENT)
        pod = deployment["spec"]["template"]["spec"]
        if (pod.get("serviceAccountName") != "observability-agent"
                or not any(v.get("persistentVolumeClaim", {}).get("claimName") == CLAIM
                           for v in pod.get("volumes", []))):
            raise GuardError("Deployment is not the OBS collector")
        claim = self.object("pvc", CLAIM)
        if claim.get("status", {}).get("phase") != "Bound":
            raise GuardError("OBS claim is not bound")
        volume = self.object("pv", claim["spec"]["volumeName"], False)
        ref = volume["spec"]["claimRef"]
        if (ref.get("namespace"), ref.get("name"), ref.get("uid")) != (NAMESPACE, CLAIM, claim["metadata"]["uid"]):
            raise GuardError("Volume does not belong to the OBS claim")
        source = volume["spec"].get("local", volume["spec"].get("hostPath", {}))
        path = Path(source.get("path", ""))
        if path.parent != STORAGE_ROOT or not path.name.endswith("_" + NAMESPACE + "_" + CLAIM):
            raise GuardError("OBS volume is outside the approved local storage path")
        wal = directory(path / "wal")
        return {"path": str(wal), "wal_inode": wal.stat().st_ino,
                "pvc_uid": claim["metadata"]["uid"], "pv_uid": volume["metadata"]["uid"]}

    def stop(self, target):
        if target == "host":
            self.command(["systemctl", "stop", HOST_UNIT])
            state = self.command(["systemctl", "show", HOST_UNIT, "--property=ActiveState", "--value"])
            if state not in ("inactive", "failed"):
                raise GuardError("OBS host reader did not stop")
        else:
            self.kube("scale", "deployment/" + DEPLOYMENT, "--namespace", NAMESPACE, "--replicas=0")
            self.kube("wait", "--for=delete", "pod", "--selector=app.kubernetes.io/name=" + DEPLOYMENT,
                      "--namespace", NAMESPACE, "--timeout=70s")

    def start(self, target):
        if target == "host":
            self.command(["systemctl", "start", HOST_UNIT])
        else:
            self.kube("scale", "deployment/" + DEPLOYMENT, "--namespace", NAMESPACE, "--replicas=1")

    def can_start(self, target):
        return not self.state["targets"].get(target, {}).get("paused", False)

    def observe(self, target):
        identity = self.discover(target)
        used, available = measure(Path(identity["path"]))
        previous = self.state["targets"].get(target, {})
        if previous.get("paused") and previous.get("identity") != identity:
            raise GuardError("Paused WAL identity changed; refusing to control a replacement")
        return identity, used, available

    def check(self):
        metrics = []
        successful = True
        targets = ["cluster", "host"] if self.config["host_enabled"] else ["cluster"]
        for target in targets:
            previous = self.state["targets"].get(target, {"paused": False})
            result = {"paused": int(previous["paused"]), "check_success": 0,
                      "stop_success": int(previous.get("stop_success", True)),
                      "pause_timestamp_seconds": previous.get("paused_at", 0),
                      "last_check_timestamp_seconds": self.clock(),
                      "limit_bytes": self.config["max_wal_bytes"],
                      "minimum_free_bytes": self.config["min_free_bytes"]}
            try:
                identity, used, available = self.observe(target)
                result.update(bytes=used, filesystem_available_bytes=available)
                reason = ("wal_limit" if used >= self.config["max_wal_bytes"]
                          else "disk_floor" if available < self.config["min_free_bytes"] else "")
                if reason and not previous["paused"]:
                    previous = {"paused": True, "reason": reason, "paused_at": self.clock(),
                                "identity": identity, "observed_bytes": used, "available_bytes": available,
                                "max_wal_bytes": self.config["max_wal_bytes"],
                                "min_free_bytes": self.config["min_free_bytes"], "stop_success": False}
                    self.state["targets"][target] = previous
                    self.save()  # Persist the latch before an interruptible service operation.
                result.update(paused=int(previous["paused"]), pause_timestamp_seconds=previous.get("paused_at", 0))
                if previous["paused"]:
                    previous["stop_success"] = False
                    self.save()
                    self.stop(target)  # Reassert a latch; never restart automatically.
                    previous["stop_success"] = True
                    self.save()
                result.update(check_success=1, stop_success=1)
            except (GuardError, OSError, ValueError, KeyError, TypeError):
                successful = False
                result["stop_success"] = int(previous.get("stop_success", True))
            for name, value in result.items():
                labels = f'cluster="{self.config["cluster"]}",component="{COMPONENTS[target]}"'
                metrics.append(f"jengasec_observability_wal_guard_{name}{{{labels}}} {value}")
        atomic_write(METRICS_FILE, "\n".join(metrics) + "\n", 0o644)
        return successful

    def resume(self, target):
        if target == "host" and not self.config["host_enabled"]:
            raise GuardError("Host collection is disabled in the guard configuration")
        previous = self.state["targets"].get(target)
        if not previous or not previous["paused"]:
            raise GuardError("Target has no recorded pause to resume")
        _, used, available = self.observe(target)
        if used >= self.config["max_wal_bytes"] or available < self.config["min_free_bytes"]:
            raise GuardError("Resume refused: WAL limit or free-space floor is still violated")
        previous["paused"] = False
        previous["resumed_at"] = self.clock()
        self.save()  # The host ExecCondition must see the cleared latch.
        try:
            self.start(target)
        except GuardError:
            previous["paused"] = True
            previous["stop_success"] = False
            self.save()
            self.stop(target)
            raise
        return self.check()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "resume", "can-start"))
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--target", choices=tuple(COMPONENTS))
    args = parser.parse_args()
    if args.command != "check" and args.target is None:
        parser.error("--target is required for resume and can-start")
    try:
        directory(STATE_ROOT)
        config = json.loads(args.config.read_text())
        if args.command == "can-start":
            return 0 if Guard(config).can_start(args.target) else 1
        lock = STATE_ROOT / "lock"
        if lock.is_symlink():
            raise GuardError("Refusing a symlinked guard lock")
        with lock.open("a") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            guard = Guard(config)
            ok = guard.check() if args.command == "check" else guard.resume(args.target)
        return 0 if ok else 1
    except (GuardError, OSError, ValueError, KeyError, TypeError) as error:
        # Paths, endpoint details and Kubernetes payloads must not enter logs.
        print(str(error) if isinstance(error, GuardError) else "Guard input or state is unavailable")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
