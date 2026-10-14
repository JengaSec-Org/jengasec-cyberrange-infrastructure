"""Bounded source receipts and read cursors; contains no grading decisions."""

import hashlib
import json
import os
import pathlib
import sqlite3

from .common import Invalid, canonical, decode, private_directory, timestamp, utc


class SourceCache:
    def __init__(self, path, competition, *, max_bytes=256 * 1024 * 1024):
        path = pathlib.Path(path)
        private_directory(path.parent)
        if path.is_symlink() or type(competition) is not int or competition <= 0:
            raise Invalid("invalid_source_cache")
        if type(max_bytes) is not int or max_bytes < 1048576:
            raise Invalid("invalid_source_cache_budget")
        self.competition, self.max_bytes = competition, max_bytes
        self.db = sqlite3.connect(path, isolation_level=None)
        os.chmod(path, 0o600)
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA journal_mode=DELETE")
        page_size = self.db.execute("PRAGMA page_size").fetchone()[0]
        self.db.execute("PRAGMA max_page_count=" + str(max_bytes // page_size))
        self.db.executescript("""
          CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY,value TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS cases (id TEXT PRIMARY KEY,payload BLOB NOT NULL,bytes INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS receipts (
            id TEXT PRIMARY KEY,sequence INTEGER UNIQUE NOT NULL,case_id TEXT,
            kind TEXT NOT NULL,observed_at TEXT NOT NULL,payload BLOB NOT NULL,bytes INTEGER NOT NULL);
          CREATE INDEX IF NOT EXISTS receipt_window ON receipts(observed_at);
          CREATE TABLE IF NOT EXISTS proofs (
            family TEXT NOT NULL,id TEXT NOT NULL,payload BLOB NOT NULL,bytes INTEGER NOT NULL,
            PRIMARY KEY(family,id));
        """)
        saved = self.db.execute("SELECT value FROM metadata WHERE key='competition'").fetchone()
        if saved and saved[0] != str(competition):
            raise Invalid("source_cache_competition_mismatch")
        self.db.execute("INSERT OR IGNORE INTO metadata VALUES('competition',?)", (str(competition),))

    def close(self):
        self.db.close()

    def cursor(self, key):
        row = self.db.execute("SELECT value FROM metadata WHERE key=?", (key,)).fetchone()
        return int(row[0]) if row else 0

    def ingest(self, page):
        if page.get("schema_version") != "scoring-receipts/1.0" or page.get("competition") != self.competition:
            raise Invalid("receipt_export_contract")
        rows, cases = page.get("receipts"), page.get("cases")
        if not isinstance(rows, list) or not isinstance(cases, list) or len(rows) > 1000 or len(cases) > 2000:
            raise Invalid("receipt_export_bounds")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            for case in cases:
                encoded = canonical(case)
                existing = self.db.execute("SELECT payload FROM cases WHERE id=?", (case["case_id"],)).fetchone()
                if existing and existing[0] != encoded:
                    before, after = decode(existing[0]), dict(case)
                    # These two fields are derived by the authenticated
                    # platform from reviewed findings and paired execution.
                    # Labels, ownership, assertions and issued sources freeze.
                    for key in ("no_valid_finding", "paired_build_verified"):
                        if type(after.get(key)) is not bool or type(before.get(key)) is not bool:
                            raise Invalid("invalid_case_authority")
                        before.pop(key)
                        after.pop(key)
                    if before != after:
                        raise Invalid("issued_case_changed")
                self.db.execute("INSERT INTO cases VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,bytes=excluded.bytes",
                                (case["case_id"], encoded, len(encoded)))
            for row in rows:
                if type(row.get("sequence")) is not int or row["sequence"] <= 0:
                    raise Invalid("invalid_source_sequence")
                encoded = canonical(row)
                identity = canonical([row.get("producer_id"), row["receipt_id"]]).decode()
                old = self.db.execute("SELECT payload FROM receipts WHERE id=?", (identity,)).fetchone()
                if old and old[0] != encoded:
                    raise Invalid("source_receipt_changed")
                sequence = self.db.execute("SELECT id FROM receipts WHERE sequence=?", (row["sequence"],)).fetchone()
                if sequence and sequence[0] != identity:
                    raise Invalid("source_sequence_conflict")
                self.db.execute("INSERT OR IGNORE INTO receipts VALUES(?,?,?,?,?,?,?)",
                                (identity, row["sequence"], row.get("case_id"), row["kind"],
                                 utc(timestamp(row["observed_at"])), encoded, len(encoded)))
            self._budget()
            for key in ("next_cursor", "cases_next_cursor"):
                value = page[key]
                if type(value) is not int or value < self.cursor(key):
                    raise Invalid("source_cursor_regressed")
                if key == "next_cursor" and any(row["sequence"] > value for row in rows):
                    raise Invalid("source_cursor_before_receipt")
                self.db.execute("INSERT INTO metadata VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))
            self.db.execute("COMMIT")
        except BaseException:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise

    def _budget(self):
        used = sum(self.db.execute("SELECT coalesce(sum(bytes),0) FROM " + table).fetchone()[0]
                   for table in ("cases", "receipts", "proofs"))
        if used > self.max_bytes:
            raise Invalid("source_cache_full")
        return used

    def retain_proof(self, receipt, *, family="ai", identifier=None):
        """Durable source proof before the producer cursor or archive advances."""
        identifier = identifier or receipt.get("receipt_id")
        if family not in {"ai", "application", "infrastructure", "scenario", "metrics"} or not isinstance(identifier, str):
            raise Invalid("invalid_proof_identity")
        entries = [(family, identifier, canonical(receipt))]

        def embedded(value, depth=0):
            if depth > 20:
                raise Invalid("embedded_proof_depth")
            if isinstance(value, list):
                for item in value:
                    embedded(item, depth + 1)
            elif isinstance(value, dict):
                if value.get("schema_version") == "ai-effect-evidence/1.0":
                    copy = dict(value)
                    integrity = copy.pop("integrity_hash", None)
                    encode = lambda item: json.dumps(item, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
                    if integrity != "sha256:" + hashlib.sha256(encode(copy)).hexdigest():
                        raise Invalid("embedded_proof_integrity")
                    native_id = copy.pop("receipt_id", None)
                    if (native_id != "air_" + hashlib.sha256(encode(copy)).hexdigest()
                            or value.get("competition") != self.competition
                            or value.get("target_id") != receipt.get("target_id")
                            or value.get("case_id") != receipt.get("case_id")):
                        raise Invalid("embedded_proof_identity")
                    entries.append(("ai", native_id, canonical(value)))
                for item in value.values():
                    embedded(item, depth + 1)

        if family == "ai":
            embedded(receipt)
        self.db.execute("BEGIN IMMEDIATE")
        try:
            for source_family, source_id, encoded in entries:
                previous = self.db.execute("SELECT payload FROM proofs WHERE family=? AND id=?", (source_family, source_id)).fetchone()
                if previous and previous[0] != encoded:
                    raise Invalid("source_proof_changed")
                self.db.execute("INSERT OR IGNORE INTO proofs VALUES(?,?,?,?)", (source_family, source_id, encoded, len(encoded)))
            self._budget()
            self.db.execute("COMMIT")
        except BaseException:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise

    def proof(self, family, identifier):
        value = self.db.execute("SELECT payload FROM proofs WHERE family=? AND id=?", (family, identifier)).fetchone()
        return decode(value[0]) if value else None

    def window(self, start, end):
        cases = {row[0]: decode(row[1]) for row in self.db.execute("SELECT id,payload FROM cases")}
        for case in cases.values():
            case["receipts"] = []
        probes, health = [], []
        # Source-health intervals may start before the score window.
        for encoded, in self.db.execute("SELECT payload FROM receipts WHERE observed_at<? OR kind IN ('source_health','finding_review') ORDER BY sequence", (utc(end),)):
            row = decode(encoded)
            kind = row["kind"]
            if kind == "source_health":
                if timestamp(row["measurements"]["end"]) > start:
                    health.append(row)
            elif kind == "probe" and _in_window(row, start, end):
                probes.append(row)
            elif row.get("case_id") in cases:
                cases[row["case_id"]]["receipts"].append(row)
        return list(cases.values()), probes, health


def _in_window(row, start, end):
    return start <= timestamp(row["observed_at"]) < end
