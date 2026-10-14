#!/usr/bin/env python3
"""
what:    Check the AI track's data: scenario events against telemetry contract v2 and the event catalogue,
         integrity hashes, answer keys against ground-truth labels, and scripts/ai-teams.yaml
owner:   AIC
usage:   python ai-api/scripts/validate-scenarios.py
reads:   contracts/telemetry-event.schema.json, contracts/telemetry-event-catalogue.yaml, scripts/cells.yaml,
         scripts/ai-teams.yaml, scenarios/*/events.jsonl, scenarios/*/answer-key.yaml
changes: nothing; exit code 1 if anything is wrong
safe to run again: yes
"""
import hashlib
import ipaddress
import json
import pathlib
import re
import sys

import yaml
from jsonschema import Draft202012Validator, FormatChecker

ROOT = pathlib.Path(__file__).resolve().parents[2]
problems = []


def load_yaml(rel):
    return yaml.safe_load((ROOT / rel).read_text(encoding="utf-8"))


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def check_ai_teams(cells):
    teams = load_yaml("scripts/ai-teams.yaml")["teams"]
    codes = {t["code"] for t in teams}
    ids = [t["team_id"] for t in teams]
    if len(set(ids)) != len(ids):
        problems.append("ai-teams.yaml: team_id values must be unique")
    expected = {"ai-blue": ("10.62.0.0/16", r"^AI-0[1-9]$"), "ai-red": ("10.64.0.0/16", r"^RI-0[1-9]$")}
    for t in teams:
        if t["role"] not in expected:
            problems.append(f"ai-teams.yaml: {t['code']} has unknown role {t['role']}")
            continue
        parent, code_pattern = expected[t["role"]]
        if not re.match(code_pattern, t["code"]):
            problems.append(f"ai-teams.yaml: {t['code']} does not look like a {t['role']} code")
        if not re.match(r"^JS26-[A-Z]+-[0-9]{3}$", t["team_id"]):
            problems.append(f"ai-teams.yaml: {t['code']} team_id {t['team_id']} breaks the telemetry team_id pattern")
        if not ipaddress.ip_network(t["wg_range"]).subnet_of(ipaddress.ip_network(parent)):
            problems.append(f"ai-teams.yaml: {t['code']} range {t['wg_range']} is outside {parent} (address plan)")
        if t["role"] == "ai-red" and t.get("paired") not in codes:
            problems.append(f"ai-teams.yaml: {t['code']} is paired with unknown team {t.get('paired')}")
    return teams


def main() -> int:
    schema = json.loads((ROOT / "contracts/telemetry-event.schema.json").read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    catalogue = load_yaml("contracts/telemetry-event-catalogue.yaml")
    raw_to_type = {e["event"]: e["event_type"] for e in catalogue["common"]}
    for brief in catalogue["briefs"].values():
        raw_to_type.update({e["event"]: e["event_type"] for e in brief["events"]})
    cells = {(c["enterprise"], c["application"]): c for c in load_yaml("scripts/cells.yaml")["cells"]}
    teams = {t["team_id"]: t for t in check_ai_teams(cells)}

    checked, seen_anywhere = 0, {}
    for path in sorted(ROOT.glob("scenarios/s*/events.jsonl")):
        name = path.parent.name
        events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        key = yaml.safe_load((path.parent / "answer-key.yaml").read_text(encoding="utf-8"))
        malicious = set(key["malicious_event_ids"] or [])
        for i, ev in enumerate(events, 1):
            checked += 1
            where = f"{name} line {i}"
            err = next(iter(validator.iter_errors(ev)), None)
            if err:
                problems.append(f"{where}: {'/'.join(map(str, err.path)) or '<root>'}: {err.message}")
                continue
            body = {k: v for k, v in ev.items() if k != "integrity_hash"}
            if ev["integrity_hash"] != "sha256:" + hashlib.sha256(canonical(body).encode()).hexdigest():
                problems.append(f"{where}: integrity_hash does not match the event")
            if ev["event_id"] in seen_anywhere:
                problems.append(f"{where}: event_id already used in {seen_anywhere[ev['event_id']]}")
            seen_anywhere[ev["event_id"]] = where
            cell = cells.get((ev["enterprise"], ev["application"]))
            if not cell or cell["namespace"] != ev["namespace"] or ev["target"].get("ip") != cell["reserved_ip"]:
                problems.append(f"{where}: enterprise/application/namespace/target.ip disagree with scripts/cells.yaml")
            raw = ev.get("raw_event")
            if raw and raw_to_type.get(raw) != ev["event_type"]:
                problems.append(f"{where}: raw_event {raw} maps to {raw_to_type.get(raw)} in the catalogue, not {ev['event_type']}")
            actor = ev.get("actor") or {}
            if actor.get("team_label") in ("red-ai", "blue-ai") and actor.get("team_id") not in teams:
                problems.append(f"{where}: AI team_id {actor.get('team_id')} is not in scripts/ai-teams.yaml")
            red = actor.get("team_label", "").startswith("red-")
            if red != (ev["event_id"] in malicious):
                problems.append(f"{where}: team_label disagrees with the answer key (labels are the ground truth)")
        missing = malicious - {e["event_id"] for e in events}
        if missing:
            problems.append(f"{name}: answer key names {len(missing)} event ids not in events.jsonl")

    for msg in problems:
        print(f"FAIL  {msg}")
    print(f"{checked} scenario events checked, {len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
