#!/usr/bin/env python3
"""Pipe local GoFlow2 output directly into the sanitized durable event queue."""

import argparse
import pathlib
import signal
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--goflow2", type=pathlib.Path, required=True)
    parser.add_argument("--config", type=pathlib.Path, required=True)
    parser.add_argument("--softflowctl", type=pathlib.Path)
    parser.add_argument("--control-socket", type=pathlib.Path)
    args = parser.parse_args()
    if not args.goflow2.is_absolute() or not args.config.is_absolute():
        raise ValueError("decoder paths must be absolute")
    if bool(args.softflowctl) != bool(args.control_socket) or any(
            path is not None and not path.is_absolute() for path in (args.softflowctl, args.control_socket)):
        raise ValueError("template recovery requires absolute control paths")
    collector = pathlib.Path(__file__).with_name("collect-infrastructure-events.py")
    decoder = subprocess.Popen([str(args.goflow2), "-listen", "netflow://127.0.0.1:2055", "-format", "json", "-transport", "file", "-loglevel", "error", "-addr", "127.0.0.1:8081"], stdout=subprocess.PIPE)
    forwarder = subprocess.Popen([sys.executable, str(collector), "--config", str(args.config), "--decode-flows"], stdin=decoder.stdout)
    decoder.stdout.close()
    stopping = False
    def stop(_signal, _frame):
        nonlocal stopping
        stopping = True
        decoder.terminate()
        forwarder.terminate()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        if args.control_socket and args.control_socket.is_socket():
            # The exporter otherwise waits for its normal template interval
            # after a decoder restart. This command affects only its next export.
            subprocess.run([str(args.softflowctl), "-c", str(args.control_socket), "send-template"],
                           check=True, timeout=5, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        code = forwarder.wait()
        return 0 if stopping else code or decoder.poll() or 0
    finally:
        for process in (forwarder, decoder):
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=10)


if __name__ == "__main__":
    raise SystemExit(main())
