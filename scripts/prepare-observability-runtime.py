#!/usr/bin/env python3
"""Create untracked development credentials for the observability stack.

Owner: Observability. Run before Docker Compose startup.
Changes: creates or extends mode-0600 files under the selected runtime directory.
"""

import argparse
import csv
import json
import os
import pathlib
import re
import secrets
import tempfile


PARTICIPANT_ID = re.compile(r"^JS26-P-[0-9]{4,6}$")


def fail(message):
    raise SystemExit(message)


def write_atomic(path, content):
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as handle:
        temporary = pathlib.Path(handle.name)
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-dir", type=pathlib.Path, required=True)
    parser.add_argument("--access-principals", type=pathlib.Path, required=True)
    args = parser.parse_args()

    os.umask(0o077)
    args.runtime_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(args.runtime_dir, 0o700)

    admin_path = args.runtime_dir / "grafana-admin-password"
    if not admin_path.exists():
        write_atomic(admin_path, secrets.token_urlsafe(32) + "\n")
    elif admin_path.stat().st_mode & 0o077:
        fail(f"{admin_path}: credentials must not be accessible to group or other")

    with args.access_principals.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    participants = sorted({row["participant_id"] for row in rows})
    if not participants or not all(PARTICIPANT_ID.fullmatch(item) for item in participants):
        fail("access fixture contains an invalid participant identifier")

    users_path = args.runtime_dir / "grafana-user-passwords.json"
    passwords = {}
    if users_path.exists():
        if users_path.stat().st_mode & 0o077:
            fail(f"{users_path}: credentials must not be accessible to group or other")
        try:
            passwords = json.loads(users_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as error:
            fail(f"{users_path}: invalid credential file: {error}")
    if not isinstance(passwords, dict):
        fail(f"{users_path}: expected a JSON object")
    for participant in participants:
        passwords.setdefault(participant, secrets.token_urlsafe(32))
    write_atomic(users_path, json.dumps(passwords, sort_keys=True) + "\n")
    print(f"prepared untracked Grafana credentials for {len(participants)} test users")


if __name__ == "__main__":
    main()
