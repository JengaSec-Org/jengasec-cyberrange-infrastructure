#!/usr/bin/env python3
"""Render Vector's runtime lookup and sensitive-key pattern from the catalogue."""

import argparse
import csv
import json
import os
import pathlib
import re
import tempfile
import urllib.parse

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
                "source": "application",
                "application": application,
                "event": mapping["event"],
                "event_type": mapping["event_type"],
                "severity": mapping["severity"],
                "detail_keys": "|".join(mapping.get("detail", [])),
                "attack_mapping": "|".join(mapping.get("attack", [])),
            }

    for source, mappings in sorted(catalogue["source_events"].items()):
        for mapping in mappings:
            yield {
                "source": source,
                "application": "",
                "event": mapping["event"],
                "event_type": mapping["event_type"],
                "severity": mapping["severity"],
                "detail_keys": "|".join(mapping.get("detail", [])),
                "attack_mapping": "|".join(mapping.get("attack", [])),
            }


def application_rows(cells):
    for cell in sorted(cells["cells"], key=lambda item: item["reserved_ip"]):
        yield {
            "ip_address": cell["reserved_ip"],
            "enterprise": cell["enterprise"],
            "application": cell["application"],
            "namespace": cell["namespace"],
            "asset": f'{cell["namespace"]}/app',
        }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--catalogue", type=pathlib.Path, required=True)
    parser.add_argument("--cells", type=pathlib.Path, required=True)
    parser.add_argument("--template", type=pathlib.Path, required=True)
    parser.add_argument("--output-dir", type=pathlib.Path, required=True)
    parser.add_argument("--website-feed-url", default="")
    args = parser.parse_args()

    website_feed_url = urllib.parse.urlsplit(args.website_feed_url)
    if args.website_feed_url and (
        website_feed_url.scheme not in {"http", "https"}
        or not website_feed_url.hostname
        or website_feed_url.username
        or website_feed_url.password
        or website_feed_url.query
        or website_feed_url.fragment
        or website_feed_url.path != "/api/feed"
    ):
        raise SystemExit("website feed URL must be an HTTP(S) /api/feed URL without credentials")

    with args.catalogue.open(encoding="utf-8") as handle:
        catalogue = yaml.safe_load(handle)
    with args.cells.open(encoding="utf-8") as handle:
        cells = yaml.safe_load(handle)

    rows = list(catalogue_rows(catalogue))
    if not rows:
        raise SystemExit("event catalogue produced no Vector mappings")
    applications = list(application_rows(cells))
    if len(applications) != 18:
        raise SystemExit("cell inventory must contain 18 application instances")
    if len({row["ip_address"] for row in applications}) != len(applications):
        raise SystemExit("cell inventory contains duplicate application addresses")

    lookup_path = args.output_dir / "event-catalogue.csv"

    def write_lookup(handle):
        writer = csv.DictWriter(
            handle,
            fieldnames=(
                "source",
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

    applications_path = args.output_dir / "applications.csv"

    def write_applications(handle):
        writer = csv.DictWriter(
            handle,
            fieldnames=(
                "ip_address",
                "enterprise",
                "application",
                "namespace",
                "asset",
            ),
        )
        writer.writeheader()
        writer.writerows(applications)

    write_atomic(applications_path, write_applications)

    sensitive_keys = catalogue["never_log_keys"]
    if not sensitive_keys:
        raise SystemExit("event catalogue has no never-log keys")
    sensitive_pattern = "|".join(re.escape(key) for key in sensitive_keys)
    template = args.template.read_text(encoding="utf-8")
    rendered = template.replace("__SENSITIVE_KEY_PATTERN__", sensitive_pattern)
    if rendered == template:
        raise SystemExit("Vector template has no sensitive-key placeholder")
    rendered_with_feed = rendered.replace(
        "__WEBSITE_FEED_URL__", json.dumps(args.website_feed_url)
    )
    if rendered_with_feed == rendered:
        raise SystemExit("Vector template has no website-feed placeholder")
    if not args.website_feed_url:
        # An unconfigured optional receiver must not block local collection or
        # silently send records to a rehearsal endpoint.
        config = yaml.safe_load(rendered_with_feed)
        config["transforms"].pop("sanitized_website_feed")
        config["sinks"].pop("website_feed_publisher")
        rendered_with_feed = yaml.safe_dump(config, sort_keys=False)

    config_path = args.output_dir / "vector.yaml"
    write_atomic(config_path, lambda handle: handle.write(rendered_with_feed))
    print(
        f"rendered {len(rows)} event mappings, {len(applications)} applications "
        f"and {len(sensitive_keys)} sensitive keys"
    )


if __name__ == "__main__":
    main()
