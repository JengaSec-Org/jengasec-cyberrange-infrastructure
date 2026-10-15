"""Deployment entrypoints for the AI gateway, narrow actuator and effect probe."""

import argparse
import os
import signal
import sys
import threading

from .actuator import Actuator, Nft, RemoteActuator, Verifier
from .authority import Authority, Tokens
from .common import Rejected, canonical, decode_json, read_json
from .gateway import Gateway
from .http_api import Server
from .probe import FunctionalProbe
from .store import Store
from .telemetry import Cursors, Telemetry


def base(config):
    tokens = Tokens(config["tokens_file"])
    authority = Authority(config["identity_file"], config["competition_networks"], config["protected_networks"], config.get("protected_ports", []))
    store = Store(config["state_file"], config["source_id"])
    return tokens, authority, store


def build_gateway(config):
    tokens, authority, store = base(config)
    telemetry = Telemetry(config["telemetry_directory"], authority, Cursors(config["cursor_secret"]))
    actuator = RemoteActuator(config["actuator_command"], config["actuator_operator_token"])
    return Gateway(tokens, authority, store, telemetry, actuator, config["evidence_directory"])


def build_actuator(config):
    tokens, authority, store = base(config)
    return Actuator(tokens, authority, store,
                    Nft(store, config.get("nft_executable", "/usr/sbin/nft"), config.get("nft_table", "jengasec_ai_actions")),
                    Verifier(config["verifier_command"]))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("serve", "actuator", "probe", "sync", "check"))
    parser.add_argument("--config", required=True)
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        config = read_json(args.config, maximum=256 * 1024, secret=True)
        if args.mode in ("actuator", "probe"):
            body = decode_json(sys.stdin.buffer.read(65537))
            if args.mode == "probe":
                result = FunctionalProbe(config).execute(body)
            else:
                result = build_actuator(config).dispatch(body)
            print(canonical(result).decode())
            return 0
        gateway = build_gateway(config)
        if args.mode == "check":
            gateway.authority.load(gateway.clock())
            print('{"identity":"fresh","config":"valid","live_actions":"not_tested"}')
            return 0
        if args.mode == "sync":
            gateway.synchronize()
            print('{"synchronized":true}')
            return 0
        server = Server((config.get("listen_address", "127.0.0.1"), config.get("listen_port", 9681)), gateway)
        stopped = threading.Event()

        def synchronize():
            while not stopped.is_set():
                try:
                    gateway.synchronize()
                    gateway.store.meta("actuator_error", "")
                except (Rejected, OSError):
                    try:
                        gateway.store.meta("actuator_error", "actuator_sync_failed")
                    except (Rejected, OSError):
                        pass
                stopped.wait(1)

        worker = threading.Thread(target=synchronize, daemon=True)
        worker.start()

        def stop(signum, frame):
            stopped.set()
            threading.Thread(target=server.shutdown, daemon=True).start()

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        try:
            server.serve_forever(poll_interval=0.25)
        finally:
            stopped.set()
            server.server_close()
            worker.join(timeout=1)
        return 0
    except (Rejected, KeyError, TypeError, ValueError, OSError) as error:
        code = error.code if isinstance(error, Rejected) else "configuration_or_io_error"
        status = error.status if isinstance(error, Rejected) else 503
        # Errors go through a fixed envelope; paths and child output stay private.
        print(canonical({"error": code, "status": status}).decode())
        return 0 if args.mode == "actuator" else 1


if __name__ == "__main__":
    raise SystemExit(main())
