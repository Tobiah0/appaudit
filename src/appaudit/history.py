"""History from before the watcher ran: Windows' own usage database (SRUM).

SRUM records, per app and hour, the bytes sent and received and how long the app was in focus.
It reaches back about 60 days. The file is locked and admin-only, so the elevated helper copies
it; this module then reads the copy without special rights.
"""

from __future__ import annotations

import re
import shutil
import sqlite3
import time
from collections import defaultdict
from pathlib import Path

from .capture.aggregate import _device_path_to_dos
from .store import data_dir

SOURCE = Path(r"C:\Windows\System32\sru\SRUDB.dat")
SCHEMA = """
CREATE TABLE IF NOT EXISTS history (
    app TEXT NOT NULL,
    exe TEXT,
    day TEXT NOT NULL,
    sent INTEGER NOT NULL DEFAULT 0,
    received INTEGER NOT NULL DEFAULT 0,
    focus_seconds INTEGER NOT NULL DEFAULT 0,
    input_seconds INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (app, day)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS history_meta (key TEXT PRIMARY KEY, value TEXT) WITHOUT ROWID;
"""
_SERVICE = re.compile(r"^!!(.+?)!.*\[([^\]]+)\]\s*$")


def path() -> Path:
    return data_dir() / "history.db"


def normalise(app_id: str) -> tuple[str, str | None]:
    """Return (label, executable path or None) for a SRUM application id."""
    text = str(app_id or "").strip()
    match = _SERVICE.match(text)
    if match:
        return f"{match.group(1)} [{match.group(2)}]", None
    if text.startswith("!!"):
        return text.split("!")[2] if text.count("!") >= 3 else text, None
    if text.lower().startswith("\\device\\"):
        exe = _device_path_to_dos(text)
        return exe.lower(), exe
    return text, None


def import_copy(srudb: Path, target: Path | None = None) -> dict:
    """Aggregate a copy of SRUDB.dat into per-app, per-day rows."""
    from dissect.esedb.tools.sru import SRU

    rows: dict[tuple[str, str], list] = defaultdict(lambda: [None, 0, 0, 0, 0])
    counts = {"network": 0, "timeline": 0}
    with open(srudb, "rb") as handle:
        sru = SRU(handle)
        table = sru.get_table(table_name="network_data")
        if table is not None:
            for entry in sru.get_table_entries(table=table):
                stamp = entry["TimeStamp"]
                if stamp is None:
                    continue
                label, exe = normalise(entry["AppId"])
                row = rows[(label, stamp.strftime("%Y-%m-%d"))]
                row[0] = exe
                row[1] += int(entry["BytesSent"] or 0)
                row[2] += int(entry["BytesRecvd"] or 0)
                counts["network"] += 1
        table = sru.get_table(table_name="application_timeline")
        if table is not None:
            for entry in sru.get_table_entries(table=table):
                stamp = entry["TimeStamp"]
                if stamp is None:
                    continue
                label, exe = normalise(entry["AppId"])
                row = rows[(label, stamp.strftime("%Y-%m-%d"))]
                row[0] = row[0] or exe
                row[3] += int(entry["InFocusS"] or 0)
                row[4] += int(entry["KeyboardInputS"] or 0) + int(entry["MouseInputS"] or 0)
                counts["timeline"] += 1
    # The focus table names desktop apps by file name only ("firefox.exe"); the network table uses
    # the full path. Fold a bare name into the path row when exactly one path has that file name.
    by_name: dict[str, set[str]] = defaultdict(set)
    for label, _day in rows:
        if "\\" in label:
            by_name[label.rsplit("\\", 1)[-1]].add(label)
    for (label, day) in [key for key in rows if "\\" not in key[0]]:
        targets = by_name.get(label.lower())
        if targets and len(targets) == 1:
            source = rows.pop((label, day))
            merged = rows[(next(iter(targets)), day)]
            merged[0] = merged[0] or _device_path_to_dos(next(iter(targets)))
            for index in (1, 2, 3, 4):
                merged[index] += source[index]
    if ("", "") not in rows:
        for (label, day) in [key for key in rows if not key[0]]:
            rows[("(not attributed to an app)", day)] = rows.pop((label, day))

    conn = sqlite3.connect(target or path())
    try:
        conn.executescript(SCHEMA)
        conn.execute("DELETE FROM history")
        conn.executemany("INSERT INTO history VALUES (?,?,?,?,?,?,?)",
                         [(key[0], row[0], key[1], row[1], row[2], row[3], row[4]) for key, row in rows.items()])
        conn.execute("INSERT OR REPLACE INTO history_meta VALUES ('imported', ?)", (str(time.time()),))
        conn.commit()
    finally:
        conn.close()
    return {"rows": len(rows), **counts}


def refresh() -> dict:
    """Run in the elevated helper: copy the live database, then import the copy."""
    copy = data_dir() / "SRUDB.copy.dat"
    shutil.copyfile(SOURCE, copy)
    try:
        return import_copy(copy)
    finally:
        copy.unlink(missing_ok=True)


def summary(days: int = 60, target: Path | None = None) -> dict:
    file = target or path()
    if not file.exists():
        return {"available": False, "apps": []}
    conn = sqlite3.connect(f"file:{file.as_posix()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        cutoff = time.strftime("%Y-%m-%d", time.gmtime(time.time() - days * 86400))
        rows = conn.execute(
            "SELECT app, MAX(exe) exe, SUM(sent) sent, SUM(received) received, SUM(focus_seconds) focus, "
            "SUM(input_seconds) input, SUM(CASE WHEN sent + received > 0 THEN 1 ELSE 0 END) net_days, "
            "SUM(CASE WHEN focus_seconds > 0 THEN 1 ELSE 0 END) focus_days, MIN(day) first, MAX(day) last "
            "FROM history WHERE day >= ? GROUP BY app HAVING SUM(sent) + SUM(received) > 0 "
            "ORDER BY SUM(sent) DESC", (cutoff,)).fetchall()
        meta = dict(conn.execute("SELECT key, value FROM history_meta").fetchall())
        span = conn.execute("SELECT MIN(day), MAX(day) FROM history WHERE sent + received > 0").fetchone()
    finally:
        conn.close()
    return {"available": True, "imported": float(meta.get("imported", 0)), "first_day": span[0], "last_day": span[1],
            "apps": [dict(row) for row in rows]}
