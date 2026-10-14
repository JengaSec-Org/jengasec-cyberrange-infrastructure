"""Bounded transactional delivery state. The website alone stores scores."""

import contextlib
import json
import os
import pathlib
import sqlite3
import time

from .common import Invalid, canonical, decode, digest, private_directory


class Full(Invalid):
    pass


class Outbox:
    def __init__(self, path, *, max_bytes=64 * 1024 * 1024, max_rows=50000):
        path = pathlib.Path(path)
        private_directory(path.parent)
        if path.is_symlink():
            raise Invalid("symlink_outbox")
        if not 1024 <= max_bytes <= 64 * 1024 * 1024 or not 1 <= max_rows <= 50000:
            raise Invalid("invalid_outbox_limit")
        self.max_bytes, self.max_rows = max_bytes, max_rows
        self.db = sqlite3.connect(path, timeout=10, isolation_level=None)
        os.chmod(path, 0o600)
        self.db.execute("PRAGMA journal_mode=DELETE")
        self.db.execute("PRAGMA synchronous=FULL")
        page_size = self.db.execute("PRAGMA page_size").fetchone()[0]
        self.db.execute("PRAGMA max_page_count=" + str((64 * 1024 * 1024) // page_size))
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS components (
                identity TEXT PRIMARY KEY, revision INTEGER NOT NULL,
                fingerprint TEXT NOT NULL, outcome TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS pending (
                id INTEGER PRIMARY KEY, identity TEXT NOT NULL, revision INTEGER NOT NULL,
                kind TEXT NOT NULL, payload BLOB NOT NULL, bytes INTEGER NOT NULL,
                state TEXT NOT NULL DEFAULT 'pending', reason TEXT NOT NULL DEFAULT '',
                attempts INTEGER NOT NULL DEFAULT 0, due REAL NOT NULL DEFAULT 0,
                created REAL NOT NULL, UNIQUE(identity, revision));
            CREATE TABLE IF NOT EXISTS cursors (name TEXT PRIMARY KEY, value TEXT NOT NULL);
        """)

    def close(self):
        self.db.close()

    @contextlib.contextmanager
    def transaction(self):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
            self.db.execute("COMMIT")
        except BaseException as error:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            if isinstance(error, sqlite3.DatabaseError) and getattr(error, "sqlite_errorcode", None) == sqlite3.SQLITE_FULL:
                raise Full("outbox_full") from None
            raise

    def _room(self, size):
        rows, used = self.db.execute("SELECT count(*), coalesce(sum(bytes),0) FROM pending").fetchone()
        if rows >= self.max_rows or used + size > self.max_bytes:
            raise Full("outbox_full")

    def enqueue_score(self, competition, row, *, now=None):
        if type(competition) is not int or competition <= 0:
            raise Invalid("invalid_competition")
        if row.get("stage") != "main" or row.get("key") != "main:" + row.get("criterion", ""):
            raise Invalid("invalid_component")
        if "revision" in row:
            raise Invalid("revision_is_delivery_owned")
        identity = canonical([competition, row["team"], row["key"]]).decode()
        fingerprint = digest(row)
        with self.transaction():
            previous = self.db.execute(
                "SELECT revision,fingerprint FROM components WHERE identity=?", (identity,)
            ).fetchone()
            if previous and previous[1] == fingerprint:
                return previous[0]
            revision = previous[0] + 1 if previous else 1
            payload = canonical({"schema_version": "scoring-feed/2.0", "competition": competition,
                                 "scores": [dict(row, revision=revision)]})
            self._room(len(payload))
            self.db.execute("INSERT INTO pending(identity,revision,kind,payload,bytes,created) VALUES(?,?,?,?,?,?)",
                            (identity, revision, "score", payload, len(payload), time.time() if now is None else now))
            self.db.execute("INSERT INTO components VALUES(?,?,?,'pending') ON CONFLICT(identity) "
                            "DO UPDATE SET revision=excluded.revision,fingerprint=excluded.fingerprint,outcome='pending'",
                            (identity, revision, fingerprint))
        return revision

    def enqueue_observations(self, identity, payload, *, now=None):
        """A native Loki batch waiting for delivery, not a second event store."""
        encoded = canonical(payload)
        key = "observation:" + str(identity)
        with self.transaction():
            previous = self.db.execute("SELECT payload FROM pending WHERE identity=?", (key,)).fetchone()
            if previous:
                if previous[0] != encoded:
                    raise Invalid("conflicting_observation_retry")
                return
            self._room(len(encoded))
            self.db.execute("INSERT INTO pending(identity,revision,kind,payload,bytes,created) VALUES(?,1,'observation',?,?,?)",
                            (key, encoded, len(encoded), time.time() if now is None else now))

    def enqueue_receipt(self, payload, *, now=None):
        encoded = canonical(payload)
        key = "receipt:" + str(payload["producer_id"]) + ":" + str(payload["receipt_id"])
        with self.transaction():
            previous = self.db.execute("SELECT payload FROM pending WHERE identity=?", (key,)).fetchone()
            if previous:
                if previous[0] != encoded:
                    raise Invalid("conflicting_receipt_retry")
                return
            self._room(len(encoded))
            self.db.execute("INSERT INTO pending(identity,revision,kind,payload,bytes,created) VALUES(?,1,'receipt',?,?,?)",
                            (key, encoded, len(encoded), time.time() if now is None else now))

    def enqueue_probe(self, payload, cursor_key, slot, observation=None, *, now=None):
        """Queue both outputs and advance the scheduler cursor atomically."""
        items = [("receipt:" + payload["producer_id"] + ":" + payload["receipt_id"], "receipt", payload)]
        if observation is not None:
            items.append(("observation:" + payload["receipt_id"], "observation", observation))
        with self.transaction():
            if (self.cursor(cursor_key) or -1) >= slot:
                return
            for identity, kind, body in items:
                raw = canonical(body)
                self._room(len(raw))
                self.db.execute("INSERT INTO pending(identity,revision,kind,payload,bytes,created) VALUES(?,1,?,?,?,?)",
                                (identity, kind, raw, len(raw), time.time() if now is None else now))
            self.cursor(cursor_key, slot)

    def due(self, *, now=None, limit=100):
        stamp = time.time() if now is None else now
        if not 1 <= limit <= 100:
            raise Invalid("invalid_batch_limit")
        rows = self.db.execute("SELECT id,kind,payload,attempts FROM pending WHERE state='pending' AND due<=? "
                               "ORDER BY id LIMIT ?", (stamp, limit)).fetchall()
        return [{"id": row[0], "kind": row[1], "payload": decode(row[2]), "attempts": row[3]} for row in rows]

    def finish(self, identifier, outcome):
        if outcome not in {"accepted", "duplicate", "stale", "overridden", "held"}:
            raise Invalid("unknown_delivery_outcome")
        with self.transaction():
            row = self.db.execute("SELECT identity,revision FROM pending WHERE id=?", (identifier,)).fetchone()
            if not row:
                return
            self.db.execute("UPDATE components SET outcome=? WHERE identity=? AND revision=?",
                            (outcome, row[0], row[1]))
            self.db.execute("DELETE FROM pending WHERE id=?", (identifier,))

    def fail(self, identifier, reason, *, permanent=False, now=None, retry_after=None):
        if not reason or len(reason) > 80 or not all(c.isalnum() or c == "_" for c in reason):
            raise Invalid("unsafe_delivery_reason")
        stamp = time.time() if now is None else now
        with self.transaction():
            row = self.db.execute("SELECT attempts FROM pending WHERE id=?", (identifier,)).fetchone()
            if row:
                delay = min(300, 2 ** min(row[0] + 1, 8))
                if retry_after is not None:
                    delay = max(delay, min(300, max(1, retry_after)))
                self.db.execute("UPDATE pending SET attempts=attempts+1,state=?,reason=?,due=? WHERE id=?",
                                ("rejected" if permanent else "pending", reason, stamp + delay, identifier))

    def retry_rejected(self, identifier):
        self.db.execute("UPDATE pending SET state='pending',due=0 WHERE id=? AND state='rejected'", (identifier,))

    def cursor(self, name, value=None):
        if value is None:
            row = self.db.execute("SELECT value FROM cursors WHERE name=?", (name,)).fetchone()
            return json.loads(row[0]) if row else None
        self.db.execute("INSERT INTO cursors VALUES(?,?) ON CONFLICT(name) DO UPDATE SET value=excluded.value",
                        (name, canonical(value).decode()))

    def stats(self):
        rows, used, rejected = self.db.execute(
            "SELECT count(*),coalesce(sum(bytes),0),coalesce(sum(state='rejected'),0) FROM pending"
        ).fetchone()
        return {"rows": rows, "bytes": used, "rejected": rejected,
                "warning": rows >= self.max_rows * .75 or used >= self.max_bytes * .75}
