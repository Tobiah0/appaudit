"""Presence: whether someone was at the keyboard, minute by minute.

The dashboard runs as the signed-in user, so it can ask Windows when the keyboard or mouse was
last used (GetLastInputInfo). Once a minute it stores one bit: someone was active in that minute
or not. Nothing else is recorded: no keys, no windows, no screen.

Minutes when the dashboard was not running have no record and count as unknown, never as away.
"""

from __future__ import annotations

import ctypes
import sqlite3
import threading
import time
from contextlib import contextmanager
from ctypes import wintypes
from pathlib import Path

from .store import data_dir

IDLE_LIMIT = 120            # seconds without input after which a minute counts as "away"
SAMPLE_EVERY = 30
KEEP_DAYS = 30
SCHEMA = "CREATE TABLE IF NOT EXISTS presence (minute INTEGER PRIMARY KEY, present INTEGER NOT NULL) WITHOUT ROWID;"


class _LastInput(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.UINT), ("dwTime", wintypes.DWORD)]


def idle_seconds() -> float | None:
    """Seconds since the last keyboard or mouse input in this session, or None if unavailable."""
    info = _LastInput()
    info.cbSize = ctypes.sizeof(info)
    try:
        if not ctypes.windll.user32.GetLastInputInfo(ctypes.byref(info)):
            return None
        return ((ctypes.windll.kernel32.GetTickCount() - info.dwTime) & 0xFFFFFFFF) / 1000.0
    except (AttributeError, OSError):
        return None


@contextmanager
def _db(file: Path | None = None):
    conn = sqlite3.connect(file or (data_dir() / "appaudit.db"), timeout=10)
    try:
        conn.execute(SCHEMA)
        yield conn
        conn.commit()
    finally:
        conn.close()


def record(present: bool, now: float | None = None, file: Path | None = None) -> None:
    """Mark the current minute. A minute with any presence stays present."""
    minute = int((now or time.time()) // 60)
    with _db(file) as conn:
        conn.execute("INSERT INTO presence VALUES (?, ?) ON CONFLICT(minute) DO UPDATE SET present = MAX(present, excluded.present)",
                     (minute, int(present)))


def sample(file: Path | None = None) -> bool | None:
    idle = idle_seconds()
    if idle is None:
        return None
    present = idle < IDLE_LIMIT
    record(present, file=file)
    return present


def _sampler() -> None:
    last_prune = 0.0
    while True:
        try:
            sample()
            if time.time() - last_prune > 3600:
                with _db() as conn:
                    conn.execute("DELETE FROM presence WHERE minute < ?", (int(time.time() // 60) - KEEP_DAYS * 1440,))
                last_prune = time.time()
        except Exception:  # noqa: BLE001 - presence is a convenience; never stop the dashboard
            pass
        time.sleep(SAMPLE_EVERY)


_started = False


def start() -> None:
    global _started
    if not _started:
        _started = True
        threading.Thread(target=_sampler, name="presence", daemon=True).start()


def minutes(since: float, until: float, file: Path | None = None) -> dict[int, bool]:
    with _db(file) as conn:
        return {minute: bool(present) for minute, present in
                conn.execute("SELECT minute, present FROM presence WHERE minute BETWEEN ? AND ?", (int(since // 60), int(until // 60)))}


def split(first: float, last: float, known: dict[int, bool]) -> tuple[float, float, float]:
    """(share while present, share while away, share unknown) of an activity between two times,
    assuming it was spread evenly over the minutes it covers."""
    span = range(int(first // 60), int(last // 60) + 1)
    total = len(span)
    present = sum(1 for minute in span if known.get(minute) is True)
    away = sum(1 for minute in span if known.get(minute) is False)
    return present / total, away / total, (total - present - away) / total


def summarise(flows, known: dict[int, bool]) -> dict:
    """Bytes sent while present, while away and at unknown times, over rows with sent/first/last."""
    totals = {"present": 0.0, "away": 0.0, "unknown": 0.0}
    for row in flows:
        here, gone, unknown = split(row["first"], row["last"], known)
        totals["present"] += row["sent"] * here
        totals["away"] += row["sent"] * gone
        totals["unknown"] += row["sent"] * unknown
    known_bytes = totals["present"] + totals["away"]
    return {**{key: int(value) for key, value in totals.items()},
            "away_share": totals["away"] / known_bytes if known_bytes else None,
            "coverage": known_bytes / (known_bytes + totals["unknown"]) if known_bytes + totals["unknown"] else 0.0}
