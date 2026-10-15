"""Bounded, canonical data handling for scoring delivery."""

import datetime as dt
import hashlib
import json
import os
import pathlib
import stat
import tempfile


UTC = dt.timezone.utc


class Invalid(ValueError):
    """A safe machine-readable validation reason."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def timestamp(value):
    if not isinstance(value, str) or len(value) > 40:
        raise Invalid("invalid_utc_time")
    try:
        result = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None or result.utcoffset() != dt.timedelta(0):
            raise ValueError
        return result.astimezone(UTC)
    except (ValueError, OverflowError):
        raise Invalid("invalid_utc_time") from None


def utc(value):
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def decode(raw, limit=1048576):
    if len(raw) > limit:
        raise Invalid("body_too_large")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise Invalid("duplicate_json_key")
            result[key] = value
        return result

    def constant(_):
        raise Invalid("nonfinite_number")

    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
        canonical(value)
        return value
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        raise Invalid("invalid_json") from None


def private_directory(path):
    path = pathlib.Path(path)
    if path.is_symlink():
        raise Invalid("symlink_state_directory")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.geteuid():
        raise Invalid("state_directory_not_private")
    return path


def secret(path):
    file = pathlib.Path(path)
    if file.is_symlink():
        raise Invalid("symlink_secret")
    info = file.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
        raise Invalid("secret_not_private")
    value = file.read_bytes()
    if len(value) > 4096:
        raise Invalid("secret_too_large")
    value = value.decode().strip()
    if not value or any(ord(char) < 33 or ord(char) > 126 for char in value):
        raise Invalid("invalid_secret")
    return value


def atomic(path, value, mode=0o600):
    path = pathlib.Path(path)
    if path.is_symlink():
        raise Invalid("symlink_output")
    fd, temp = tempfile.mkstemp(prefix=".scoring-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)
