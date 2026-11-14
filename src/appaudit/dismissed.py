"""Things the user has looked at and decided are fine. They are hidden from the lists by default
and can be brought back at any time. Nothing on the PC changes; this is only a display choice.
"""

from __future__ import annotations

import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from .store import data_dir

KINDS = {"program", "actor"}
SCHEMA = """
CREATE TABLE IF NOT EXISTS dismissed (
    kind TEXT NOT NULL, key TEXT NOT NULL, label TEXT NOT NULL, added REAL NOT NULL,
    PRIMARY KEY (kind, key)) WITHOUT ROWID;
"""


@contextmanager
def _db(file: Path | None = None):
    conn = sqlite3.connect(file or (data_dir() / "appaudit.db"), timeout=10)
    try:
        conn.executescript(SCHEMA)
        conn.row_factory = sqlite3.Row
        yield conn
        conn.commit()
    finally:
        conn.close()


def listing(file: Path | None = None) -> list[dict]:
    with _db(file) as conn:
        return [dict(row) for row in conn.execute("SELECT * FROM dismissed ORDER BY added DESC")]


def add(kind: str, key: str, label: str, file: Path | None = None) -> None:
    if kind not in KINDS or not key:
        raise ValueError("unknown kind or empty key")
    with _db(file) as conn:
        conn.execute("INSERT OR REPLACE INTO dismissed VALUES (?,?,?,?)", (kind, key.lower(), label[:200], time.time()))


def remove(kind: str, key: str, file: Path | None = None) -> None:
    with _db(file) as conn:
        conn.execute("DELETE FROM dismissed WHERE kind = ? AND key = ?", (kind, key.lower()))
