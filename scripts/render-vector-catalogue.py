#!/usr/bin/env python3
"""Render Vector's runtime lookup and sensitive-key pattern from the catalogue."""

import argparse
import csv
import os
import pathlib
import re
import tempfile

import yaml


def write_atomic(path, writer):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", newline="", dir=path.parent, delete=False
    ) as handle:
        temporary = pathlib.Path(handle.name)
        writer(handle)
    os.replace(temporary, path)


def catalogue_rows(catalogue):
    for application, brief in sorted(catalogue["briefs"].items()):
        for mapping in [*catalogue["common"], *brief["events"]]:
            yield {
                "application": application,
                "event": mapping["event"],
                "event_type": mapping["event_type"],
                "severity": mapping["severity"],
                "detail_keys": "|".join(mapping.get("detail", [])),
                "attack_mapping": "|".join(mapping.get("attack", [])),
            }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--catalogue", type=pathlib.Path, required=True)
    parser.add_argument("--template", type=pathlib.Path, required=True)
    parser.add_argument("--output-dir", type=pathlib.Path, required=True)
    args = parser.parse_args()

    with args.catalogue.open(encoding="utf-8") as handle:
        catalogue = yaml.safe_load(handle)

    rows = list(catalogue_rows(catalogue))
    if not rows:
        raise SystemExit("event catalogue produced no Vector mappings")

    lookup_path = args.output_dir / "event-catalogue.csv"

    def write_lookup(handle):
        writer = csv.DictWriter(
            handle,
            fieldnames=(
                "application",
                "event",
                "event_type",
                "severity",
                "detail_keys",
                "attack_mapping",
            ),
        )
        writer.writeheader()
        writer.writerows(rows)

    write_atomic(lookup_path, write_lookup)

    sensitive_keys = catalogue["never_log_keys"]
    if not sensitive_keys:
        raise SystemExit("event catalogue has no never-log keys")
    sensitive_pattern = "|".join(re.escape(key) for key in sensitive_keys)
    template = args.template.read_text(encoding="utf-8")
    rendered = template.replace("__SENSITIVE_KEY_PATTERN__", sensitive_pattern)
    if rendered == template:
        raise SystemExit("Vector template has no sensitive-key placeholder")

    config_path = args.output_dir / "vector.yaml"
    write_atomic(config_path, lambda handle: handle.write(rendered))
    print(f"rendered {len(rows)} event mappings and {len(sensitive_keys)} sensitive keys")


if __name__ == "__main__":
    main()
