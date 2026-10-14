"""Durable delivery receipts and action leases; this store contains no marks."""

import contextlib
import fcntl
import hashlib
import os
import sqlite3
import stat
import threading
import time
from pathlib import Path

from .common import Rejected, canonical, decode_json, digest, stamp


class Store:
    def __init__(self, path, source_id, max_bytes=64 * 1024 * 1024, max_receipts=50000):
        self.path = Path(path)
        self.source_id = source_id
        self.max_bytes, self.max_receipts = max_bytes, max_receipts
        self.lock = threading.RLock()
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.path.parent.is_symlink() or stat.S_IMODE(self.path.parent.stat().st_mode) & 0o077:
            raise Rejected("insecure_state_directory", 503)
        if self.path.is_symlink():
            raise Rejected("insecure_state_file", 503)
        with self.connection() as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS receipts (
                    cursor INTEGER PRIMARY KEY AUTOINCREMENT,
                    receipt_id TEXT NOT NULL UNIQUE,
                    team TEXT NOT NULL,
                    body BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS actions (
                    action_id TEXT PRIMARY KEY,
                    competition INTEGER NOT NULL,
                    team TEXT NOT NULL,
                    target TEXT NOT NULL,
                    key TEXT NOT NULL,
                    request_hash TEXT NOT NULL,
                    created REAL NOT NULL,
                    expires REAL NOT NULL,
                    state TEXT NOT NULL,
                    body BLOB NOT NULL,
                    UNIQUE(competition, team, key)
                );
                CREATE INDEX IF NOT EXISTS action_budget ON actions(team, created);
                CREATE TABLE IF NOT EXISTS sequence_state (
                    source TEXT PRIMARY KEY, epoch TEXT NOT NULL, sequence INTEGER NOT NULL,
                    last_receipt TEXT NOT NULL, input_hash TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            """)
        os.chmod(self.path, 0o600)

    @contextlib.contextmanager
    def connection(self):
        try:
            with self.lock:
                db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
                db.row_factory = sqlite3.Row
                db.execute("PRAGMA synchronous=FULL")
                db.execute("PRAGMA foreign_keys=ON")
                db.execute("PRAGMA busy_timeout=5000")
                db.execute("PRAGMA max_page_count=16384")
                try:
                    yield db
                finally:
                    db.close()
        except sqlite3.Error:
            raise Rejected("receipt_store_unavailable", 503) from None

    @contextlib.contextmanager
    def transaction(self):
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                yield db
                db.commit()
            except BaseException:
                db.rollback()
                raise

    @contextlib.contextmanager
    def execution_lock(self):
        path = self.path.with_suffix(".execution.lock")
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        started = time.monotonic()
        try:
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() - started > 2:
                        raise Rejected("actuator_busy", 429)
                    time.sleep(0.02)
            yield
        finally:
            os.close(fd)

    def capacity(self, db, reserve=1):
        page_size = db.execute("PRAGMA page_size").fetchone()[0]
        pages = db.execute("PRAGMA page_count").fetchone()[0]
        free = db.execute("PRAGMA freelist_count").fetchone()[0]
        used = (pages - free) * page_size
        count = db.execute("SELECT count(*) FROM receipts").fetchone()[0]
        if used + reserve * 8192 > self.max_bytes or count + reserve > self.max_receipts:
            raise Rejected("receipt_store_full", 503)

    def emit(self, kind, context, case_id, payload, now, occurred_at=None, db=None, force=False):
        if db is None:
            with self.transaction() as connection:
                return self.emit(kind, context, case_id, payload, now, occurred_at, connection, force)
        if not force:
            self.capacity(db)
        seq = db.execute("SELECT value FROM meta WHERE key='receipt_sequence'").fetchone()
        sequence = int(seq[0]) + 1 if seq else 1
        db.execute("INSERT INTO meta(key,value) VALUES('receipt_sequence',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(sequence),))
        body = {"schema_version": "ai-receipt/1.0", "source_id": self.source_id,
                "sequence": sequence, "kind": kind, "occurred_at": occurred_at or stamp(now),
                "received_at": stamp(now), **context, "case_id": case_id, "payload": payload}
        body["receipt_id"] = "air_" + hashlib.sha256(canonical(body)).hexdigest()
        body["integrity_hash"] = digest(body)
        db.execute("INSERT INTO receipts(receipt_id,team,body) VALUES(?,?,?)",
                   (body["receipt_id"], body.get("team_id", "operator"), canonical(body)))
        return body

    def import_receipts(self, items):
        with self.transaction() as db:
            for item in items:
                copy = dict(item)
                integrity = copy.pop("integrity_hash", None)
                if integrity != digest(copy) or copy.get("schema_version") != "ai-receipt/1.0":
                    raise Rejected("invalid_actuator_receipt", 503)
                receipt_id = copy.pop("receipt_id", None)
                if receipt_id != "air_" + hashlib.sha256(canonical(copy)).hexdigest():
                    raise Rejected("invalid_actuator_receipt", 503)
                previous = db.execute("SELECT body FROM receipts WHERE receipt_id=?", (receipt_id,)).fetchone()
                if previous:
                    if bytes(previous[0]) != canonical(item):
                        raise Rejected("conflicting_actuator_receipt", 503)
                    continue
                self.capacity(db)
                db.execute("INSERT INTO receipts(receipt_id,team,body) VALUES(?,?,?)",
                           (receipt_id, item["team_id"], canonical(item)))

    def receipts(self, after=0, limit=200, team=None):
        with self.connection() as db:
            ack = db.execute("SELECT value FROM meta WHERE key='ack_cursor'").fetchone()
            if ack and after < int(ack[0]):
                raise Rejected("receipt_cursor_expired", 410)
            query = "SELECT cursor,body FROM receipts WHERE cursor>?"
            params = [after]
            if team:
                query += " AND team=?"
                params.append(team)
            rows = db.execute(query + " ORDER BY cursor LIMIT ?", (*params, limit)).fetchall()
        return {"receipts": [decode_json(bytes(r["body"])) for r in rows],
                "next_cursor": rows[-1]["cursor"] if rows else after}

    def acknowledge(self, through, now):
        """Drop only durably exported receipts, retaining live protocol state.

        The authenticated operator owns the retained copy. Expired cursor reads
        fail visibly instead of pretending the earlier history was empty.
        """
        with self.transaction() as db:
            highest = db.execute("SELECT seq FROM sqlite_sequence WHERE name='receipts'").fetchone()
            if type(through) is not int or through < 0 or through > (highest[0] if highest else 0):
                raise Rejected("invalid_acknowledgement")
            previous = db.execute("SELECT value FROM meta WHERE key='ack_cursor'").fetchone()
            if previous and through <= int(previous[0]):
                return
            db.execute("DELETE FROM receipts WHERE cursor<=? AND receipt_id NOT IN (SELECT last_receipt FROM sequence_state) "
                       "AND coalesce(json_extract(body,'$.payload.action_id'),'') NOT IN "
                       "(SELECT action_id FROM actions WHERE expires>? AND state NOT IN ('failed','rejected','reverted'))", (through, now))
            # Completed action keys and small outcome summaries still prevent
            # retries from executing again after their evidence was exported.
            for row in db.execute("SELECT action_id,body FROM actions WHERE expires<=? OR state IN ('failed','rejected','reverted')", (now,)).fetchall():
                action = decode_json(bytes(row["body"]))
                for result in action.get("verification", {}).values():
                    proof = result.get("proof")
                    if proof:
                        result["proof"] = {key: proof[key] for key in ("receipt_id", "integrity_hash")}
                db.execute("UPDATE actions SET body=? WHERE action_id=?", (canonical(action), row["action_id"]))
            db.execute("INSERT INTO meta(key,value) VALUES('ack_cursor',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(through),))

    def action_receipts(self, action_id):
        # action_id is never interpolated into SQL or a filesystem path.
        with self.connection() as db:
            rows = db.execute("SELECT body FROM receipts WHERE json_extract(body,'$.payload.action_id')=? ORDER BY cursor", (action_id,)).fetchall()
        return [decode_json(bytes(r[0])) for r in rows]

    def action(self, action_id=None, team=None, key=None, db=None, competition=None):
        if db is None:
            with self.connection() as connection:
                return self.action(action_id, team, key, connection, competition)
        if action_id:
            row = db.execute("SELECT body FROM actions WHERE action_id=?", (action_id,)).fetchone()
        else:
            row = db.execute("SELECT body FROM actions WHERE competition=? AND team=? AND key=?", (competition, team, key)).fetchone()
        return decode_json(bytes(row[0])) if row else None

    def reserve(self, action, db):
        self.capacity(db, reserve=10)
        now = action["created"]
        active = db.execute("SELECT 1 FROM actions WHERE team=? AND target=? AND state IN ('authorized','executed','verified','reverting','revert_failed') AND expires>?",
                            (action["team"], action["request"]["target_id"], now)).fetchone()
        if active:
            raise Rejected("active_action_limit", 429)
        for window, cap in ((60, 5), (3600, 30)):
            count = db.execute("SELECT count(*) FROM actions WHERE team=? AND created>?", (action["team"], now - window)).fetchone()[0]
            if count >= cap:
                raise Rejected("action_budget_exhausted", 429)
        db.execute("INSERT INTO actions VALUES(?,?,?,?,?,?,?,?,?,?)",
                   (action["action_id"], action["competition"], action["team"], action["request"]["target_id"], action["request"]["key"],
                    action["request_hash"], now, action["expires"], action["state"], canonical(action)))

    def update_action(self, action, db=None):
        if db is None:
            with self.transaction() as connection:
                return self.update_action(action, connection)
        db.execute("UPDATE actions SET state=?,body=? WHERE action_id=?",
                   (action["state"], canonical(action), action["action_id"]))

    def pending_actions(self):
        with self.connection() as db:
            rows = db.execute("SELECT body FROM actions WHERE state NOT IN ('reverted','failed','rejected')").fetchall()
        return [decode_json(bytes(r[0])) for r in rows]

    def meta(self, key, value=None):
        if value is None:
            with self.connection() as db:
                row = db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
                return row[0] if row else None
        with self.transaction() as db:
            db.execute("INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))

    def ingest_sequenced(self, principal, body, kind, context, payload, now):
        """An epoch is provisioned with the token; producers cannot reset loss history."""
        source = principal["source_id"]
        epoch = principal.get("epoch")
        if not epoch or body["epoch"] != epoch:
            raise Rejected("unregistered_source_epoch", 409)
        input_hash = digest(body)
        with self.transaction() as db:
            row = db.execute("SELECT * FROM sequence_state WHERE source=?", (source,)).fetchone()
            expected = row["sequence"] + 1 if row and row["epoch"] == epoch else 1
            if row and row["epoch"] == epoch and body["source_sequence"] == row["sequence"]:
                if row["input_hash"] != input_hash:
                    raise Rejected("conflicting_sequence", 409)
                saved = db.execute("SELECT body FROM receipts WHERE receipt_id=?", (row["last_receipt"],)).fetchone()
                return decode_json(bytes(saved[0])), True
            if body["source_sequence"] < expected:
                raise Rejected("stale_sequence", 409)
            payload = {**payload, "producer_source_id": source, "producer_kind": principal["kind"],
                       "source_sequence": body["source_sequence"], "epoch": epoch,
                       "sequence_gap": body["source_sequence"] - expected}
            receipt = self.emit(kind, context, body["case_id"], payload, now, body["occurred_at"], db)
            db.execute("INSERT INTO sequence_state VALUES(?,?,?,?,?) ON CONFLICT(source) DO UPDATE SET epoch=excluded.epoch,sequence=excluded.sequence,last_receipt=excluded.last_receipt,input_hash=excluded.input_hash",
                       (source, epoch, body["source_sequence"], receipt["receipt_id"], input_hash))
            return receipt, False
