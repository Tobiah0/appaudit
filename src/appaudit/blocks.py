"""Per-app network block: one outbound Windows Firewall rule per program.

Rules are created in the group "App Audit" so they are easy to find in Windows' own firewall
console, and every rule this tool adds can be removed here. Windows components are refused:
they are controlled through switches, and blocking them by program breaks updates.
"""

from __future__ import annotations

import os
import sqlite3
import time
import zlib
from contextlib import contextmanager
from pathlib import Path

from .store import data_dir
from .winutil import WINDIR

GROUP = "App Audit"
PREFIX = "App Audit block: "

SCHEMA = """
CREATE TABLE IF NOT EXISTS blocks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    exe TEXT NOT NULL,
    rule TEXT NOT NULL,
    backend TEXT NOT NULL,
    created REAL NOT NULL,
    removed REAL
);
"""


class RealFirewall:
    name = "real"

    def _policy(self):
        import pythoncom
        import win32com.client

        pythoncom.CoInitialize()
        return win32com.client.Dispatch("HNetCfg.FwPolicy2")

    def add(self, rule: str, exe: str) -> None:
        import win32com.client

        item = win32com.client.Dispatch("HNetCfg.FWRule")
        item.Name = rule
        item.Description = "Added by App Audit. Blocks all outgoing connections from this program."
        item.ApplicationName = exe
        item.Direction = 2          # outbound
        item.Action = 0             # block
        item.Grouping = GROUP
        item.Profiles = 0x7FFFFFFF  # all profiles
        item.Enabled = True
        self._policy().Rules.Add(item)

    def remove(self, rule: str) -> None:
        self._policy().Rules.Remove(rule)

    def exists(self, rule: str) -> bool:
        try:
            self._policy().Rules.Item(rule)
            return True
        except Exception:  # noqa: BLE001 - COM raises when the rule is not there
            return False


class SandboxFirewall:
    name = "sandbox"

    def __init__(self) -> None:
        self.rules: dict[str, str] = {}

    def add(self, rule: str, exe: str) -> None:
        self.rules[rule] = exe

    def remove(self, rule: str) -> None:
        del self.rules[rule]

    def exists(self, rule: str) -> bool:
        return rule in self.rules


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


def validate(exe: str) -> str:
    """Return the normalised path, or raise ValueError saying why it cannot be blocked."""
    path = os.path.normpath(exe or "")
    if not os.path.isabs(path) or not path.lower().endswith(".exe"):
        raise ValueError("a block needs the full path of a program (.exe)")
    if not os.path.isfile(path):
        raise ValueError("that program is not on this PC")
    if os.path.normcase(path).startswith(os.path.normcase(WINDIR) + os.sep):
        raise ValueError("Windows components are not blocked by program; use the switches instead")
    return path


def active(file: Path | None = None, firewall=None) -> list[dict]:
    firewall = firewall or RealFirewall()
    with _db(file) as conn:
        rows = [dict(row) for row in conn.execute(
            "SELECT * FROM blocks WHERE removed IS NULL AND backend = ? ORDER BY id DESC", (firewall.name,))]
    for row in rows:
        row["in_firewall"] = firewall.exists(row["rule"])
    return rows


def add(exe: str, firewall=None, file: Path | None = None) -> dict:
    firewall = firewall or RealFirewall()
    path = validate(exe)
    rule = PREFIX + os.path.basename(path) + f" [{zlib.crc32(os.path.normcase(path).encode()) % 100000:05d}]"
    with _db(file) as conn:
        existing = conn.execute("SELECT * FROM blocks WHERE removed IS NULL AND backend = ? AND lower(exe) = ?",
                                (firewall.name, path.lower())).fetchone()
        if existing and firewall.exists(existing["rule"]):
            return {**dict(existing), "already": True}
        firewall.add(rule, path)
        entry_id = conn.execute("INSERT INTO blocks (exe, rule, backend, created) VALUES (?,?,?,?)",
                                (path, rule, firewall.name, time.time())).lastrowid
    return {"id": entry_id, "exe": path, "rule": rule, "already": False}


def remove(entry_id: int, firewall=None, file: Path | None = None) -> dict:
    firewall = firewall or RealFirewall()
    with _db(file) as conn:
        row = conn.execute("SELECT * FROM blocks WHERE id = ? AND backend = ?", (entry_id, firewall.name)).fetchone()
        if row is None:
            raise KeyError(f"no block {entry_id}")
        if firewall.exists(row["rule"]):
            firewall.remove(row["rule"])
        conn.execute("UPDATE blocks SET removed = ? WHERE id = ?", (time.time(), entry_id))
    return {"id": entry_id, "exe": row["exe"], "removed": True}
