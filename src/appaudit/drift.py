"""Drift: notice when a switch that was off is on again (updates are known to do this).

Every time the switch states are read they are compared with the last recorded state. A change
is written to a small log, so the dashboard can say what changed and when it was noticed.
"""

from __future__ import annotations

import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from .store import data_dir

SCHEMA = """
CREATE TABLE IF NOT EXISTS switch_state (id TEXT PRIMARY KEY, state TEXT NOT NULL, seen REAL NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS switch_drift (
    n INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL, before TEXT NOT NULL, after TEXT NOT NULL, noticed REAL NOT NULL);
"""
OFF, ON = {"private"}, {"exposed", "partly"}


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


def record(states: list[dict], file: Path | None = None, now: float | None = None) -> list[dict]:
    """Store the current states. Returns the changes noticed in this call."""
    now = now or time.time()
    changes = []
    with _db(file) as conn:
        known = {row["id"]: row["state"] for row in conn.execute("SELECT id, state FROM switch_state")}
        for entry in states:
            before = known.get(entry["id"])
            if before is not None and before != entry["state"]:
                changes.append({"id": entry["id"], "before": before, "after": entry["state"], "noticed": now})
                conn.execute("INSERT INTO switch_drift (id, before, after, noticed) VALUES (?,?,?,?)",
                             (entry["id"], before, entry["state"], now))
            conn.execute("INSERT INTO switch_state VALUES (?,?,?) ON CONFLICT(id) DO UPDATE SET state = excluded.state, "
                         "seen = excluded.seen", (entry["id"], entry["state"], now))
    return changes


def log(file: Path | None = None, limit: int = 100) -> list[dict]:
    with _db(file) as conn:
        rows = conn.execute("SELECT * FROM switch_drift ORDER BY n DESC LIMIT ?", (limit,)).fetchall()
    return [{**dict(row), "turned_back_on": row["before"] in OFF and row["after"] in ON} for row in rows]
