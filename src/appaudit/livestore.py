"""The live activity database. The elevated helper writes it; the dashboard only reads it.

Times are Unix seconds (UTC). Flows are bucketed by hour so history stays small.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from .store import data_dir

SCHEMA = """
CREATE TABLE IF NOT EXISTS procs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pid INTEGER NOT NULL,
    started REAL NOT NULL,
    ended REAL,
    exe TEXT,
    name TEXT,
    parent_pid INTEGER,
    parent_exe TEXT,
    package TEXT,
    services TEXT,
    task TEXT,
    cmdline TEXT,
    seen_start INTEGER NOT NULL DEFAULT 0,
    UNIQUE (pid, started)
);
CREATE INDEX IF NOT EXISTS procs_exe ON procs (exe);
CREATE TABLE IF NOT EXISTS flows (
    proc_id INTEGER NOT NULL,
    remote TEXT NOT NULL,
    port INTEGER NOT NULL,
    proto TEXT NOT NULL,
    bucket INTEGER NOT NULL,
    sent INTEGER NOT NULL DEFAULT 0,
    received INTEGER NOT NULL DEFAULT 0,
    events INTEGER NOT NULL DEFAULT 0,
    first REAL NOT NULL,
    last REAL NOT NULL,
    PRIMARY KEY (proc_id, remote, port, proto, bucket)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS flows_bucket ON flows (bucket);
CREATE INDEX IF NOT EXISTS flows_remote ON flows (remote);
CREATE TABLE IF NOT EXISTS names (
    address TEXT NOT NULL,
    name TEXT NOT NULL,
    source TEXT NOT NULL,
    first REAL NOT NULL,
    last REAL NOT NULL,
    PRIMARY KEY (address, name)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS lookups (
    proc_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    first REAL NOT NULL,
    last REAL NOT NULL,
    count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (proc_id, name)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS requests (
    proc_id INTEGER NOT NULL,
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    first REAL NOT NULL,
    last REAL NOT NULL,
    count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (proc_id, method, url)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS payloads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    proc_id INTEGER NOT NULL,
    host TEXT NOT NULL,
    method TEXT,
    url TEXT,
    at REAL NOT NULL,
    request_headers TEXT,
    response_headers TEXT,
    body TEXT,
    body_size INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS payloads_host ON payloads (host, proc_id);
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
) WITHOUT ROWID;
"""

EPOCH_DELTA = 11644473600


def filetime_to_unix(filetime: int) -> float:
    return filetime / 1e7 - EPOCH_DELTA


def path() -> Path:
    return data_dir() / "live.db"


def connect(readonly: bool = False, file: Path | None = None) -> sqlite3.Connection:
    target = file or path()
    if readonly:
        if not target.exists():
            raise FileNotFoundError(target)
        conn = sqlite3.connect(f"file:{target.as_posix()}?mode=ro", uri=True, timeout=5)
    else:
        # The helper creates the connection on one thread and flushes from another, one at a time.
        conn = sqlite3.connect(target, timeout=10, check_same_thread=False)
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        conn.executescript(SCHEMA)
    conn.row_factory = sqlite3.Row
    return conn


def set_meta(conn: sqlite3.Connection, **values) -> None:
    conn.executemany("INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                     [(key, str(value)) for key, value in values.items()])


def get_meta(conn: sqlite3.Connection) -> dict:
    return {row["key"]: row["value"] for row in conn.execute("SELECT key, value FROM meta")}
