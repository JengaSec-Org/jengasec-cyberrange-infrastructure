#!/usr/bin/env bash
# Verify spare-space provisioning on an expanded disposable GPT disk.
# Owner: Observability. Requires root, gdisk, util-linux and e2fsprogs.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TEST_ROOT="$(mktemp -d /tmp/jengasec-storage.XXXXXX)"
disk=""
cleanup() {
  mountpoint -q "$TEST_ROOT/data" && umount "$TEST_ROOT/data"
  [[ -z "$disk" ]] || losetup --detach "$disk"
  rm -rf -- "$TEST_ROOT"
}
trap cleanup EXIT

[[ "$EUID" == 0 ]] || { echo 'Run the storage test as root' >&2; exit 1; }
truncate --size 128M "$TEST_ROOT/disk.img"
sgdisk --clear --new=1:2048:+8M --new=2:0:+64M --new=3:0:+8M \
  --typecode=1:ef00 --typecode=2:8300 --typecode=3:8200 \
  "$TEST_ROOT/disk.img" >/dev/null
truncate --size 384M "$TEST_ROOT/disk.img"
disk="$(losetup --find --show --partscan "$TEST_ROOT/disk.img")"
printf 'preserve existing partition contents\n' | dd of="${disk}p2" status=none
dd if="${disk}p2" count=1 status=none | sha256sum > "$TEST_ROOT/before.sha256"
printf '# disposable test fstab\n' > "$TEST_ROOT/fstab"
storage=(python3 "$REPO_ROOT/scripts/prepare-observability-storage.py"
  --device "$disk" --mountpoint "$TEST_ROOT/data"
  --backup-dir "$TEST_ROOT/backup" --fstab "$TEST_ROOT/fstab")
"${storage[@]}" > "$TEST_ROOT/plan.json"

# A stale plan must fail before creating a backup or changing the disk.
python3 - "$TEST_ROOT/plan.json" "$TEST_ROOT/stale.json" <<'PY'
import json
import sys
plan = json.load(open(sys.argv[1]))
plan['disk_bytes'] += 512
json.dump(plan, open(sys.argv[2], 'w'))
PY
if "${storage[@]}" --apply "$TEST_ROOT/stale.json" >"$TEST_ROOT/stale.log" 2>&1; then
  echo 'stale layout was accepted' >&2
  exit 1
fi
[[ ! -e "$TEST_ROOT/backup" ]]
"${storage[@]}" --apply "$TEST_ROOT/plan.json" > "$TEST_ROOT/first.json"
dd if="${disk}p2" count=1 status=none | sha256sum > "$TEST_ROOT/after.sha256"
cmp "$TEST_ROOT/before.sha256" "$TEST_ROOT/after.sha256"
printf 'persistent OBS data\n' > "$TEST_ROOT/data/sentinel"
"${storage[@]}" --apply "$TEST_ROOT/plan.json" > "$TEST_ROOT/second.json"
python3 - "$TEST_ROOT" <<'PY'
import json
from pathlib import Path
import sys
root = Path(sys.argv[1])
first = json.loads((root / 'first.json').read_text())
second = json.loads((root / 'second.json').read_text())
assert first['changed'] is True and second['changed'] is False
assert first['uuid'] == second['uuid']
assert (root / 'data/sentinel').read_text() == 'persistent OBS data\n'
assert (root / 'backup/before.gpt').is_file()
assert len([line for line in (root / 'fstab').read_text().splitlines()
            if line.startswith('UUID=')]) == 1
PY
umount "$TEST_ROOT/data"
"${storage[@]}" --apply "$TEST_ROOT/plan.json" > "$TEST_ROOT/remounted.json"
[[ "$(cat "$TEST_ROOT/data/sentinel")" == 'persistent OBS data' ]]
echo 'Storage: stale-plan refusal, partition preservation, repeat apply and remount passed'
