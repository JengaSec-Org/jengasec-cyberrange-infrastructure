#!/usr/bin/env python3
"""Inspect, then provision unused GPT space for the OBS VM data volume.

Owner: Observability. Run without --apply to save the inspected plan as JSON.
Apply requires that exact plan. Existing partitions are never resized/formatted.
Recovery records live outside the new volume. See runbooks/observability.md.
"""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import time


LABEL = "JENGASEC-OBS"


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def table(device):
    return json.loads(run("sfdisk", "--json", device))["partitiontable"]


def number(partition):
    return int(re.search(r"(\d+)$", partition["node"])[1])


def inspect(device, mountpoint):
    require(stat.S_ISBLK(os.stat(device).st_mode), "device must be a block device")
    layout = table(device)
    size = int(run("blockdev", "--getsize64", device))
    require(layout["label"] == "gpt", "only GPT disks are supported")
    require(layout.get("sectorsize") == 512 and layout["firstlba"] == 34,
            "expected a standard 512-byte-sector GPT layout")
    partitions = layout.get("partitions", [])
    require(partitions, "expected an existing OS partition table")
    require(all(p.get("name") != LABEL for p in partitions),
            "an OBS-labelled partition already exists; use its recovery record")
    start = ((max(p["start"] + p["size"] for p in partitions) + 2047) // 2048) * 2048
    end = size // 512 - 34
    require(end - start + 1 >= 131072, "less than 64 MiB of unused trailing space")
    partition_number = max(map(number, partitions)) + 1
    require(partition_number <= 128, "no supported GPT partition slot remains")
    require(not Path(mountpoint).is_mount(), "mount point is already in use")
    require(not Path(mountpoint).exists() or not any(Path(mountpoint).iterdir()),
            "mount point is not empty")
    return {
        "version": 1, "device": device, "disk_bytes": size,
        "layout": layout, "mountpoint": mountpoint,
        "partition_number": partition_number, "start": start, "end": end,
    }


def assert_preserved(plan):
    current = table(plan["device"])
    original = plan["layout"]
    require(current["id"] == original["id"], "disk identifier changed")
    for partition in original["partitions"]:
        require(partition in current["partitions"], "an original partition changed")
    require(len(current["partitions"]) == len(original["partitions"]) + 1,
            "unexpected partition count after provisioning")
    added = next(p for p in current["partitions"] if number(p) == plan["partition_number"])
    require(added["start"] == plan["start"] and
            added["size"] == plan["end"] - plan["start"] + 1 and
            added.get("name") == LABEL,
            "OBS partition does not match the inspected plan")
    return added["node"]


def signatures(device):
    return json.loads(run("wipefs", "--no-act", "--json", device))["signatures"]


def atomic_write(path, content, mode=0o600):
    fd, temporary = tempfile.mkstemp(prefix=".obs-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def finish_mount(plan, record, fstab):
    node = assert_preserved(plan)
    require(run("blkid", "-s", "TYPE", "-o", "value", node) == "ext4",
            "recorded OBS partition is not ext4")
    require(run("blkid", "-s", "UUID", "-o", "value", node) == record["uuid"],
            "recorded filesystem UUID changed; refusing to format or mount")
    mountpoint = Path(plan["mountpoint"])
    source = "UUID=" + record["uuid"]
    entries = [line.split() for line in fstab.read_text().splitlines()
               if line.strip() and not line.lstrip().startswith("#")]
    matches = [entry for entry in entries if entry[0] == source or
               (len(entry) > 1 and entry[1] == str(mountpoint))]
    expected = [source, str(mountpoint), "ext4", "defaults", "0", "2"]
    require(not matches or matches == [expected], "conflicting fstab entry")
    mounted = mountpoint.is_mount()
    if not mounted:
        require(not mountpoint.exists() or not any(mountpoint.iterdir()),
                "unmounted data directory is not empty")
    changed = False
    if not matches:
        content = fstab.read_text().rstrip() + "\n" + "\t".join(expected) + "\n"
        atomic_write(fstab, content, stat.S_IMODE(fstab.stat().st_mode))
        changed = True
    mountpoint.mkdir(parents=True, exist_ok=True)
    if not mounted:
        # Explicit arguments also allow a disposable test fstab.
        run("mount", "--source", source, "--target", str(mountpoint))
        changed = True
    mounted_uuid = run("findmnt", "--noheadings", "--output", "UUID", "--mountpoint", str(mountpoint))
    require(mounted_uuid == record["uuid"], "wrong filesystem at data mount")
    return changed


def apply(plan, backup, fstab):
    record_path = backup / "volume.json"
    if record_path.exists():
        saved_plan = json.loads((backup / "plan.json").read_text())
        require(plan == saved_plan, "supplied plan differs from the recovery record")
        record = json.loads(record_path.read_text())
        changed = finish_mount(plan, record, fstab)
        return {"changed": changed, **record}

    require(inspect(plan["device"], plan["mountpoint"]) == plan,
            "disk layout changed since inspection; no changes made")
    require(not backup.exists(), "incomplete storage operation; inspect the existing backup first")
    # Check the free region without writing a partition table or filesystem.
    loop = run("losetup", "--find", "--show", "--read-only", "--offset",
               str(plan["start"] * 512), "--sizelimit",
               str((plan["end"] - plan["start"] + 1) * 512), plan["device"])
    try:
        require(not signatures(loop), "unused space has a filesystem signature; refusing to format")
    finally:
        run("losetup", "--detach", loop)

    backup.mkdir(parents=True, mode=0o700)
    atomic_write(backup / "plan.json", json.dumps(plan, indent=2) + "\n")
    shutil.copy2(fstab, backup / "fstab.before")
    run("sgdisk", "--backup=" + str(backup / "before.gpt"), plan["device"])
    n = plan["partition_number"]
    run("sgdisk", "--move-second-header", f"--new={n}:{plan['start']}:{plan['end']}",
        f"--typecode={n}:8300", f"--change-name={n}:{LABEL}", plan["device"])
    node = assert_preserved(plan)
    if not Path(node).exists():
        run("partx", "--add", "--nr", str(n), plan["device"])
    for _ in range(50):
        if Path(node).exists():
            break
        time.sleep(0.1)
    require(Path(node).exists(), "kernel did not expose the new partition; inspect the backup")
    require(not signatures(node), "new partition has a filesystem signature; refusing to format")
    run("mkfs.ext4", "-q", "-L", "JENGASEC_OBS", node)
    record = {"partition": node, "uuid": run("blkid", "-s", "UUID", "-o", "value", node),
              "mountpoint": plan["mountpoint"]}
    atomic_write(record_path, json.dumps(record, indent=2) + "\n")
    finish_mount(plan, record, fstab)
    return {"changed": True, **record}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device", required=True)
    parser.add_argument("--mountpoint", default="/srv/jengasec-observability")
    parser.add_argument("--apply", type=Path, help="apply this previously inspected JSON plan")
    parser.add_argument("--backup-dir", type=Path, default=Path("/var/backups/jengasec-observability/storage"))
    parser.add_argument("--fstab", type=Path, default=Path("/etc/fstab"))
    args = parser.parse_args()
    try:
        require(os.geteuid() == 0, "run as root to inspect the block device")
        device = os.path.realpath(args.device)
        mountpoint = str(Path(args.mountpoint).absolute())
        require(re.fullmatch(r"/[A-Za-z0-9_./-]+", mountpoint) is not None and
                str(Path(mountpoint).resolve()) == mountpoint and mountpoint != "/",
                "mount point must be an absolute path without symlinks")
        require(str(args.backup_dir.resolve()) != mountpoint and
                not str(args.backup_dir.resolve()).startswith(mountpoint + "/"),
                "GPT backups must be outside the new data mount")
        if args.apply:
            plan = json.loads(args.apply.read_text())
            require(plan.get("version") == 1 and plan.get("device") == device and
                    plan.get("mountpoint") == mountpoint, "plan target does not match arguments")
            result = apply(plan, args.backup_dir, args.fstab)
        else:
            result = inspect(device, mountpoint)
        print(json.dumps(result, indent=2))
    except (ValueError, OSError, subprocess.CalledProcessError, KeyError) as error:
        parser.exit(1, f"Storage preparation stopped: {error}\n")


if __name__ == "__main__":
    main()
