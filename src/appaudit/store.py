"""SQLite storage for scan results. A scan is stored whole so a saved database can
later be loaded as demo data."""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime
from pathlib import Path

KEEP_SCANS = 5

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started TEXT NOT NULL,
    finished TEXT NOT NULL,
    elevated INTEGER NOT NULL,
    unused_days INTEGER NOT NULL,
    sources TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS apps (
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    app_id TEXT NOT NULL,
    score INTEGER NOT NULL,
    doc TEXT NOT NULL,
    PRIMARY KEY (scan_id, app_id)
);
"""


def data_dir() -> Path:
    override = os.environ.get("APPAUDIT_DATA")
    folder = Path(override) if override else Path(__file__).resolve().parents[2] / "data"
    folder.mkdir(parents=True, exist_ok=True)
    return folder


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(data_dir() / "appaudit.db")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)
    return conn


def _json_default(value):
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(f"cannot serialise {type(value).__name__}")


def dumps(value) -> str:
    return json.dumps(value, default=_json_default)


def save_scan(started: datetime, finished: datetime, elevated: bool, unused_days: int,
              sources: list[dict], apps: list[dict]) -> int:
    with _connect() as conn:
        cursor = conn.execute(
            "INSERT INTO scans (started, finished, elevated, unused_days, sources) VALUES (?, ?, ?, ?, ?)",
            (started.isoformat(), finished.isoformat(), int(elevated), unused_days, dumps(sources)),
        )
        scan_id = cursor.lastrowid
        conn.executemany(
            "INSERT OR REPLACE INTO apps (scan_id, app_id, score, doc) VALUES (?, ?, ?, ?)",
            [(scan_id, app["id"], app["score"], dumps(app)) for app in apps],
        )
        conn.execute(
            "DELETE FROM scans WHERE id NOT IN (SELECT id FROM scans ORDER BY id DESC LIMIT ?)", (KEEP_SCANS,)
        )
        return scan_id


def latest_scan() -> dict | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT id, started, finished, elevated, unused_days, sources FROM scans ORDER BY id DESC LIMIT 1"
        ).fetchone()
    if row is None:
        return None
    return {
        "id": row[0], "started": row[1], "finished": row[2], "elevated": bool(row[3]),
        "unused_days": row[4], "sources": json.loads(row[5]),
    }


def load_apps(scan_id: int) -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT doc FROM apps WHERE scan_id = ? ORDER BY score DESC, app_id", (scan_id,)
        ).fetchall()
    return [json.loads(row[0]) for row in rows]
