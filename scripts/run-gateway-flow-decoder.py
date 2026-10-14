#!/usr/bin/env python3
"""Pipe local GoFlow2 output directly into the sanitized durable event queue."""

import argparse
import os
import pathlib
import signal
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--goflow2", type=pathlib.Path, required=True)
    parser.add_argument("--config", type=pathlib.Path, required=True)
    args = parser.parse_args()
    if not args.goflow2.is_absolute() or not args.config.is_absolute():
        raise ValueError("decoder paths must be absolute")
    collector = pathlib.Path(__file__).with_name("collect-infrastructure-events.py")
    decoder = subprocess.Popen([str(args.goflow2), "-listen", "netflow://127.0.0.1:2055", "-format", "json", "-transport", "file", "-loglevel", "error", "-addr", "127.0.0.1:8081"], stdout=subprocess.PIPE)
    forwarder = subprocess.Popen([sys.executable, str(collector), "--config", str(args.config), "--decode-flows"], stdin=decoder.stdout)
    decoder.stdout.close()
    def stop(_signal, _frame):
        decoder.terminate()
        forwarder.terminate()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        code = forwarder.wait()
        return code if code else decoder.poll() or 0
    finally:
        for process in (forwarder, decoder):
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=10)


if __name__ == "__main__":
    raise SystemExit(main())
