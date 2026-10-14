#!/usr/bin/env python3
"""
what:    Write this scenario's events as JSON lines in the telemetry-event shape
owner:   AIC-A3
usage:   ./generate.py --seed 1 --out events.jsonl
reads:   scenario.yaml next to this file
changes: writes --out and answer-key.yaml only
safe to run again: yes (deterministic for a given --seed)
"""
import argparse
import pathlib
import sys
from datetime import timedelta

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE.parent))
from _lib import START, Scenario  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--out", default=str(HERE / "events.jsonl"))
    a = ap.parse_args()
    s = Scenario(HERE, a.seed)

    # TODO(AIC-A3): benign noise first (Blue-side addresses 10.61.<n>.x), then the attack with malicious=True.
    # See s01-credential-stuffing for a full example. Event types come from contracts/event-catalogue.yaml.
    for i in range(5):
        s.event(START + timedelta(seconds=i * s.rng.randint(1, 5)), "application", "authentication_failure", "low",
                "failure", actor={"ip": "10.60.5.14", "team": "JS26-R-005"}, malicious=True)

    s.write(a.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
