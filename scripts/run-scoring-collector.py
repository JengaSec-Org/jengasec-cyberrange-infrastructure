#!/usr/bin/env python3
"""Collect real competition evidence and publish versioned score decisions."""

from scoring_obs.cli import main
from scoring_obs.common import Invalid

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (Invalid, OSError, ValueError, KeyError):
        raise SystemExit("Scoring collector configuration is unavailable or invalid.") from None
