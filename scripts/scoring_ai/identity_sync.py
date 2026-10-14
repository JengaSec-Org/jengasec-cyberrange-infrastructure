"""Publish current platform authority without sharing its read-only credential."""

import argparse
import fcntl
import grp
import http.client
import os
from pathlib import Path
import signal
import ssl
import stat
import tempfile
import time
import urllib.parse

from .common import Rejected, canonical, decode_json, integer, object_fields, timestamp


MAXIMUM = 1024 * 1024
OWNER_UID = 0
OWNER_GID = 0


def absolute_path(value):
    if (not isinstance(value, str) or not value.startswith("/")
            or any(char in value for char in ("\x00", "\r", "\n")) or ".." in Path(value).parts):
        raise Rejected("invalid_identity_path", 503)
    return Path(value)


def trusted_parents(path):
    for parent in path.parents:
        info = parent.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, OWNER_UID}
                or (info.st_mode & 0o022 and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX))):
            raise Rejected("untrusted_identity_directory", 503)


def owned_file(path, maximum, *, private=True):
    path = absolute_path(path)
    trusted_parents(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != OWNER_UID or info.st_size > maximum
                or info.st_mode & (0o077 if private else 0o022)):
            raise Rejected("insecure_identity_file", 503)
        with os.fdopen(fd, "rb", closefd=False) as handle:
            data = handle.read(maximum + 1)
        if len(data) > maximum:
            raise Rejected("identity_file_too_large", 503)
        return data
    finally:
        os.close(fd)


class IdentitySync:
    def __init__(self, config, clock=time.time, monotonic=time.monotonic):
        object_fields(config, ("schema_version", "origin", "competition", "token_file", "snapshot_file"),
                      ("reader_group", "ca_file"))
        if config["schema_version"] != "scoring-ai-identity/1.0":
            raise Rejected("unsupported_identity_sync_version", 503)
        self.competition = integer(config["competition"], 1, 2**63 - 1)
        try:
            origin = urllib.parse.urlsplit(config["origin"])
            port = 443 if origin.port is None else integer(origin.port, 1, 65535)
            if (origin.scheme != "https" or not origin.hostname or not origin.hostname.isascii()
                    or origin.username is not None or origin.password is not None
                    or origin.path not in ("", "/") or origin.query or origin.fragment
                    or any(char in config["origin"] for char in ("\r", "\n", "\x00"))):
                raise ValueError
        except (ValueError, TypeError, AttributeError):
            raise Rejected("identity_https_origin_required", 503) from None
        self.host, self.port = origin.hostname, port
        self.token_file = absolute_path(config["token_file"])
        self.snapshot = absolute_path(config["snapshot_file"])
        if self.token_file == self.snapshot or self.snapshot.name.startswith("."):
            raise Rejected("invalid_identity_path", 503)
        self.ca_file = absolute_path(config["ca_file"]) if config.get("ca_file") else None
        self.group = config.get("reader_group")
        self.gid = OWNER_GID
        if self.group is not None:
            if not isinstance(self.group, str) or not self.group:
                raise Rejected("identity_reader_group_required", 503)
            try:
                self.gid = grp.getgrnam(self.group).gr_gid
            except KeyError:
                raise Rejected("identity_reader_group_missing", 503) from None
            if self.gid == 0:
                raise Rejected("identity_reader_group_privileged", 503)
        self.mode = 0o640 if self.group is not None else 0o600
        self.directory_mode = 0o750 if self.group is not None else 0o700
        self.clock, self.monotonic = clock, monotonic

    def _directory(self):
        if os.geteuid() != OWNER_UID or os.getegid() != OWNER_GID:
            raise Rejected("identity_publisher_requires_root", 503)
        trusted_parents(self.snapshot)
        parent = self.snapshot.parent
        info = parent.lstat()
        if (info.st_uid != OWNER_UID or info.st_gid != self.gid
                or stat.S_IMODE(info.st_mode) != self.directory_mode):
            raise Rejected("insecure_identity_publication_directory", 503)
        return os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)

    def _fetch(self):
        token = owned_file(str(self.token_file), 4096).decode("ascii").strip()
        if not 32 <= len(token) <= 512 or any(ord(char) < 33 or ord(char) > 126 for char in token):
            raise Rejected("invalid_identity_credential", 503)
        if self.ca_file:
            owned_file(str(self.ca_file), MAXIMUM, private=False)
        context = ssl.create_default_context(cafile=str(self.ca_file) if self.ca_file else None)
        connection = http.client.HTTPSConnection(self.host, self.port, timeout=5, context=context)
        deadline = self.monotonic() + 8
        try:
            connection.request("GET", "/api/scoring/identity/?competition=" + str(self.competition),
                               headers={"X-Scoring-Identity-Token": token, "Accept": "application/json", "Connection": "close"})
            socket = connection.sock
            response = connection.getresponse()
            if response.status != 200 or response.getheader("Content-Encoding", "identity") != "identity":
                raise Rejected("identity_refresh_unavailable", 503)
            length = response.getheader("Content-Length")
            if length is not None and (not length.isdecimal() or int(length) > MAXIMUM):
                raise Rejected("identity_response_too_large", 503)
            data = bytearray()
            while True:
                if response.isclosed():
                    break
                remaining = deadline - self.monotonic()
                if remaining <= 0:
                    raise Rejected("identity_refresh_timeout", 503)
                socket.settimeout(min(5, remaining))
                chunk = response.read1(min(65536, MAXIMUM + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > MAXIMUM:
                    raise Rejected("identity_response_too_large", 503)
            if length is not None and len(data) != int(length):
                raise Rejected("identity_response_incomplete", 503)
            return decode_json(data, MAXIMUM)
        finally:
            connection.close()

    def validate(self, value):
        try:
            if value.get("schema_version") != "scoring-identity/2.0" or value.get("historical", False) is not False:
                raise Rejected("invalid_current_identity", 503)
            integer(value["revision"], 1, 2**63 - 1)
            if type(value["competition"]["id"]) is not int or value["competition"]["id"] != self.competition:
                raise Rejected("identity_competition_mismatch", 503)
            now = self.clock()
            captured, expires = timestamp(value["captured_at"]), timestamp(value["expires_at"])
            if not captured <= now < expires or expires - captured > 120:
                raise Rejected("stale_identity", 503)
            if not timestamp(value["competition"]["start"]) <= now < timestamp(value["competition"]["end"]):
                raise Rejected("outside_competition_window", 503)
            for section in ("teams", "targets", "allocations", "scopes"):
                if not isinstance(value[section], list) or len(value[section]) > 100000:
                    raise Rejected("invalid_current_identity", 503)
            data = canonical(value)
            if len(data) > MAXIMUM:
                raise Rejected("identity_response_too_large", 503)
            return data
        except (KeyError, TypeError, AttributeError):
            raise Rejected("invalid_current_identity", 503) from None

    def _publish(self, directory, data):
        fd, temporary = tempfile.mkstemp(prefix=".identity-", dir=self.snapshot.parent)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                os.fchown(handle.fileno(), OWNER_UID, self.gid)
                os.fchmod(handle.fileno(), self.mode)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(Path(temporary).name, self.snapshot.name, src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        finally:
            try:
                os.unlink(Path(temporary).name, dir_fd=directory)
            except FileNotFoundError:
                pass

    def refresh(self):
        directory = self._directory()
        lock = None
        try:
            lock = os.open(".refresh.lock", os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=directory)
            info = os.fstat(lock)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != OWNER_UID or info.st_mode & 0o077:
                raise Rejected("insecure_identity_refresh_lock", 503)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Rejected("identity_refresh_busy", 503) from None
            try:
                value = self._fetch()
                self._publish(directory, self.validate(value))
                return {"identity": "fresh", "competition": self.competition, "expires_at": value["expires_at"]}
            except BaseException:
                try:
                    os.unlink(self.snapshot.name, dir_fd=directory)
                except FileNotFoundError:
                    pass
                os.fsync(directory)
                raise
        finally:
            if lock is not None:
                os.close(lock)
            os.close(directory)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    args = parser.parse_args(argv)
    os.umask(0o077)

    def interrupted(signum, frame):
        raise Rejected("identity_refresh_interrupted", 503)

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        config = decode_json(owned_file(args.config, 65536))
        print(canonical(IdentitySync(config).refresh()).decode())
        return 0
    except (Rejected, OSError, ValueError, TypeError, http.client.HTTPException):
        print('{"error":"identity_refresh_failed"}')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
