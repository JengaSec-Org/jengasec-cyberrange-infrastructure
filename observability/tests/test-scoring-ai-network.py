#!/usr/bin/env python3
"""Exercise the production actuator in disposable, routed Linux namespaces.

Run with sudo and --require-netns in CI. An unprivileged local run may skip.
All interfaces, addresses and nftables changes belong to child namespaces;
there are no named namespace mounts or host firewall changes.
"""

import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = Path(__file__).resolve()
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from scoring_ai.actuator import Actuator, Nft, Verifier
from scoring_ai.authority import Authority, Tokens
from scoring_ai.common import Rejected, canonical, decode_json, run_bounded
from scoring_ai.probe import FunctionalProbe
from scoring_ai.store import Store


BODY = b'{"fixture":"ready"}\n'
SOURCE, CONTROL = "10.50.0.12", "10.50.0.13"
TARGET, OTHER_TARGET = "10.60.0.11", "10.60.0.12"
PORT, OTHER_PORT = 8080, 8081


def require_isolation():
    if os.readlink("/proc/self/ns/net") == os.readlink(f"/proc/{os.getppid()}/ns/net"):
        raise RuntimeError("Refusing to run fixture operations in the parent's network namespace")


def command(*argv):
    return subprocess.run(argv, check=True, capture_output=True, text=True, timeout=10).stdout


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
    for stream in (process.stdout, process.stderr):
        if stream:
            stream.close()


def start(stack, argv):
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stack.callback(stop, process)
    readable, _, _ = select.select([process.stdout], [], [], 5)
    if not readable or process.stdout.readline().strip() != "ready":
        raise RuntimeError("Fixture process did not become ready")
    return process


def namespace(pid):
    return [shutil.which("nsenter"), "--target", str(pid), "--net", "--"]


def hold():
    parent = os.getppid()
    print("ready", flush=True)
    while os.getppid() == parent:
        time.sleep(0.2)


def interrupted(*_args):
    raise SystemExit(130)


def topology(stack):
    require_isolation()
    links = json.loads(command(shutil.which("ip"), "-j", "link", "show"))
    if {link["ifname"] for link in links} != {"lo"}:
        raise RuntimeError("The router namespace must be new and empty")
    children = []
    for side, network, addresses in (
        ("source", "10.50.0", (SOURCE, CONTROL)),
        ("target", "10.60.0", (TARGET, OTHER_TARGET)),
    ):
        peer = start(stack, [shutil.which("unshare"), "--net", sys.executable, str(HERE), "--hold"])
        children.append(peer)
        router_link, peer_link = side + "-r", side + "-p"
        ip = shutil.which("ip")
        command(ip, "link", "add", router_link, "type", "veth", "peer", "name", peer_link)
        command(ip, "link", "set", peer_link, "netns", str(peer.pid))
        command(ip, "address", "add", network + ".1/24", "dev", router_link)
        command(ip, "link", "set", router_link, "up")
        command(*namespace(peer.pid), ip, "link", "set", "lo", "up")
        for address in addresses:
            command(*namespace(peer.pid), ip, "address", "add", address + "/24", "dev", peer_link)
        command(*namespace(peer.pid), ip, "link", "set", peer_link, "up")
        command(*namespace(peer.pid), ip, "route", "add", "default", "via", network + ".1")
    Path("/proc/sys/net/ipv4/ip_forward").write_text("1\n")
    start(stack, [*namespace(children[1].pid), sys.executable, str(HERE), "--serve"])
    return children[0].pid


def serve():
    require_isolation()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(BODY)))
            self.end_headers()
            self.wfile.write(BODY)

        def log_message(self, *_args):
            pass

    for address, port in ((TARGET, PORT), (TARGET, OTHER_PORT), (OTHER_TARGET, PORT)):
        server = ThreadingHTTPServer((address, port), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind((TARGET, PORT))

    def echo():
        while True:
            content, peer = udp.recvfrom(128)
            udp.sendto(content, peer)

    threading.Thread(target=echo, daemon=True).start()
    hold()


def fixtures():
    # Reuse the existing canonical identity/token fixtures, not their fake NFT backend.
    spec = importlib.util.spec_from_file_location("scoring_ai_fixtures", HERE.with_name("test-scoring-ai.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def exercise():
    require_isolation()
    with contextlib.ExitStack() as stack:
        directory = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="jengasec-ai-network-")))
        source_pid = topology(stack)
        fixture = fixtures()
        now = time.time()
        identity_path, token_path = directory / "identity.json", directory / "tokens.json"
        snapshot = fixture.identity(now)
        fixture.write_json(identity_path, snapshot)
        fixture.write_json(token_path, {"principals": [
            {"sha256": hashlib.sha256(token.encode()).hexdigest(), "kind": kind, "team": team,
             "cell_id": cell, "source_id": source}
            for token, kind, team, cell, source in (
                (fixture.TOKEN, "competitor", fixture.TEAM, "AIB01", "network-fixture"),
                (fixture.OPERATOR_TOKEN, "operator", None, None, "network-operator"),
            )
        ]})
        check = {"competition": 1, "target_id": fixture.TARGET,
                 "frozen_digest": snapshot["targets"][0]["frozen_digest"],
                 "source_ip": SOURCE, "control_source_ip": CONTROL, "target_ip": TARGET,
                 "protocol": "tcp", "port": PORT, "host": "fixture.internal", "path": "/healthz",
                 "tls": False, "expected_status": 200,
                 "expected_body_sha256": "sha256:" + hashlib.sha256(BODY).hexdigest()}
        probe_path = directory / "probe.json"
        fixture.write_json(probe_path, {"checks": [check], "evidence_directory": str(directory / "evidence")})
        probe_command = [*namespace(source_pid), sys.executable, str(HERE), "--probe", str(probe_path)]
        store = Store(directory / "actuator" / "state.sqlite", "network-actuator")
        nft = Nft(store, executable=shutil.which("nft"), table="jengasec_ai_network_fixture")
        assert nft.tables() == [], "The router namespace already contains firewall tables"
        actuator = Actuator(Tokens(token_path), Authority(identity_path, ["10.50.0.0/24", "10.60.0.0/24"],
                           ["10.50.0.1/32", "10.60.0.1/32"], [9090]), store, nft, Verifier(probe_command))

        def reach(*, source=SOURCE, target=TARGET, port=PORT, protocol="tcp"):
            payload = {"check": {**check, "target_ip": target, "port": port, "protocol": protocol}, "source_ip": source}
            result = decode_json(run_bounded([*namespace(source_pid), sys.executable, str(HERE), "--request"],
                                            canonical(payload), timeout=7, maximum=16384))
            return result["functional_success"]

        def execute(key, ttl=30):
            result = actuator.execute(fixture.TOKEN, {**fixture.block(key), "ttl_seconds": ttl})
            assert result["state"] == "verified", result
            action = store.action(action_id=result["action_id"])
            assert nft.contains(action), "The verified action has no kernel element"
            return action

        first = execute("network-reversal")
        assert not reach(), "The exact authorized TCP tuple remained reachable"
        assert reach(source=CONTROL), "Independent source traffic was blocked"
        assert reach(target=OTHER_TARGET), "An unrelated target was blocked"
        assert reach(port=OTHER_PORT), "An unrelated port was blocked"
        assert reach(protocol="udp"), "An unrelated protocol was blocked"
        restored = actuator.revert(fixture.TOKEN, first["action_id"])
        assert restored["state"] == "reverted" and not nft.contains(first), restored
        assert reach() and reach(source=CONTROL), "Explicit reversal did not restore traffic"
        print("PASS: exact tuple, independent controls and explicit reversal", flush=True)

        expiring = execute("network-kernel-expiry", ttl=10)
        deadline = time.monotonic() + max(0, expiring["expires"] - time.time()) + 2
        while nft.contains(expiring) and time.monotonic() < deadline:
            time.sleep(0.2)
        assert not nft.contains(expiring), "The kernel did not expire its lease"
        assert store.action(action_id=expiring["action_id"])["state"] == "verified", "A reconciler hid failed kernel expiry"
        assert reach() and reach(source=CONTROL), "Traffic did not recover after kernel expiry"
        actuator.dispatch({"operation": "reconcile", "token": fixture.OPERATOR_TOKEN})
        assert store.action(action_id=expiring["action_id"])["state"] == "reverted"
        print("PASS: kernel lease expiry without an actuator sweep", flush=True)

        killed = execute("network-kill-switch")
        result = actuator.dispatch({"operation": "kill-switch", "token": fixture.OPERATOR_TOKEN, "enabled": True})
        assert result == {"kill_switch": True, "unresolved_actions": 0}, result
        assert not nft.contains(killed) and reach(), "The kill switch did not restore traffic"
        assert store.action(action_id=killed["action_id"])["state"] == "reverted"
        try:
            actuator.execute(fixture.TOKEN, fixture.block("network-after-kill"))
        except Rejected as error:
            assert error.code == "kill_switch_active", error.code
        else:
            raise AssertionError("The kill switch allowed a new action")
        assert all(p.stat().st_mode & 0o077 == 0 for p in (directory / "evidence").glob("air_*.json"))
        assert len(list((directory / "evidence").glob("air_*.json"))) == 9
        print("PASS: kill switch, durable receipts and private effect proof", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-netns", action="store_true", help="Fail rather than skip without root/network namespaces")
    for flag in ("hold", "serve", "exercise", "capability-check", "request"):
        parser.add_argument("--" + flag, action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--probe", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.hold:
        require_isolation()
        hold()
        return 0
    if args.serve:
        serve()
        return 0
    if args.probe or args.request:
        require_isolation()
        body = decode_json(sys.stdin.buffer.read(16385), 16384)
        if args.probe:
            result = FunctionalProbe(json.loads(Path(args.probe).read_text())).execute(body)
        elif body["check"]["protocol"] == "udp":
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(1)
                sock.bind((body["source_ip"], 0))
                sock.sendto(BODY, (body["check"]["target_ip"], body["check"]["port"]))
                result = {"functional_success": sock.recv(128) == BODY}
        else:
            result = FunctionalProbe({}).request(body["check"], body["source_ip"])
        sys.stdout.buffer.write(canonical(result))
        return 0
    if args.capability_check:
        require_isolation()
        command(shutil.which("nft"), "-j", "list", "tables")
        return 0
    if args.exercise:
        signal.signal(signal.SIGTERM, interrupted)
        exercise()
        return 0
    signal.signal(signal.SIGTERM, interrupted)
    required = args.require_netns or os.environ.get("CI", "").lower() == "true"
    missing = [name for name in ("ip", "nft", "unshare", "nsenter") if not shutil.which(name)]
    reason = "root is required" if os.geteuid() != 0 else ("missing tools: " + ", ".join(missing) if missing else None)
    if reason is None:
        capability = subprocess.run([shutil.which("unshare"), "--net", sys.executable, str(HERE), "--capability-check"],
                                    capture_output=True, text=True, timeout=15)
        if capability.returncode:
            if "Operation not permitted" not in capability.stderr and "Permission denied" not in capability.stderr:
                sys.stderr.write(capability.stderr)
                return 1
            reason = "network namespace or nftables capability is unavailable"
    if reason:
        print(("FAIL" if required else "SKIP") + ": " + reason, file=sys.stderr if required else sys.stdout)
        return 1 if required else 0
    process = subprocess.Popen([shutil.which("unshare"), "--net", sys.executable, str(HERE), "--exercise"])
    try:
        return process.wait(timeout=120)
    finally:
        stop(process)


if __name__ == "__main__":
    raise SystemExit(main())
