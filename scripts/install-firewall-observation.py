#!/usr/bin/env python3
"""Install the reviewed observation hook against an exact private source copy.

Owner: Observability with the provisioning owner. This edits only the inspected
generator and its OBS helper. It does not invoke nft or restart the worker.
Run native preflight first; the deployment controller owns restart and rollback.
"""

import argparse
import ast
import os
import pathlib
import stat
import tempfile


def patch_source(source):
    tree = ast.parse(source)
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "apply_firewall"]
    if len(functions) != 1:
        raise ValueError("expected one reviewed firewall generator")
    segment = ast.get_source_segment(source, functions[0])
    marker = "    content='\\n'.join(lines)+'\\n'"
    if segment.count(marker) != 1 or "nft_verdict_logging" in segment:
        raise ValueError("firewall generator shape has changed")
    for required in ("JengaSec default deny", "JengaSec peer isolation", "JengaSec protected destinations"):
        if required not in segment:
            raise ValueError("reviewed firewall guards are missing")
    if "run(['nft','-c','-f','-'],content)" not in segment or "run(['nft','-f','-'],content)" not in segment:
        raise ValueError("reviewed native validation and apply sequence differs")
    replacement = segment.replace(marker, "    from nft_verdict_logging import add_verdict_observation\n    lines = add_verdict_observation(lines, table=NFT_TABLE)\n" + marker)
    changed = source.replace(segment, replacement, 1)
    compile(changed, "reviewed-provision-worker", "exec")
    return changed


def atomic_write(path, data, mode, owner=None):
    fd, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
            os.fchmod(handle.fileno(), mode)
            if owner:
                os.fchown(handle.fileno(), *owner)
        os.replace(temporary, path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def install(worker, reviewed, helper, backup, apply=False):
    if worker.is_symlink() or reviewed.is_symlink() or helper.is_symlink() or backup.is_symlink():
        raise ValueError("source and backup paths must not be symbolic links")
    original = reviewed.read_bytes()
    patched = patch_source(original.decode()).encode()
    current = worker.read_bytes()
    if current not in (original, patched):
        raise ValueError("deployed worker differs from the exact reviewed source")
    helper_bytes = helper.read_bytes()
    compile(helper_bytes, str(helper), "exec")
    target_helper = worker.with_name("nft_verdict_logging.py")
    if target_helper.exists() and target_helper.read_bytes() != helper_bytes:
        raise ValueError("existing helper differs from the reviewed module")
    if not apply:
        return "preflight"
    backup.mkdir(mode=0o700, parents=True, exist_ok=True)
    if backup.stat().st_mode & 0o077:
        raise ValueError("backup directory must be owner-only")
    saved = backup / "provision_worker.py.original"
    if saved.exists() and saved.read_bytes() != original:
        raise ValueError("existing rollback source differs")
    if not saved.exists():
        atomic_write(saved, original, 0o600)
    attrs = worker.stat()
    if worker.read_bytes() != current:
        raise ValueError("worker changed during preflight")
    atomic_write(target_helper, helper_bytes, 0o644, (attrs.st_uid, attrs.st_gid))
    if current != patched:
        atomic_write(worker, patched, stat.S_IMODE(attrs.st_mode), (attrs.st_uid, attrs.st_gid))
    return "installed" if current != patched else "unchanged"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", type=pathlib.Path, required=True)
    parser.add_argument("--reviewed-source", type=pathlib.Path, required=True)
    parser.add_argument("--helper", type=pathlib.Path, required=True)
    parser.add_argument("--backup-dir", type=pathlib.Path, required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    print(install(args.worker, args.reviewed_source, args.helper, args.backup_dir, args.apply))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, SyntaxError) as error:
        print(f"firewall observation installation failed: {error}", file=os.sys.stderr)
        raise SystemExit(1) from error
