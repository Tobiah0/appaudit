"""Read-only inspections that need administrator rights: who is tracing on this PC, and the
state of Windows' own telemetry machinery. Nothing here writes to the system."""

from __future__ import annotations

import json
import os
import re
import sqlite3
import subprocess
import time
import winreg
from pathlib import Path

DIAGNOSIS = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "Microsoft" / "Diagnosis"
UQI = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "ServiceProfiles" / "LocalService" / "AppData" / "Local" / "UsageAndQualityInsights"
TRANSCRIPT_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\EventTranscriptKey"
_cache: dict[str, tuple[float, dict]] = {}


def _run(args: list[str], timeout: int = 60) -> str:
    try:
        out = subprocess.run(args, capture_output=True, text=True, timeout=timeout, errors="replace",
                             creationflags=subprocess.CREATE_NO_WINDOW)
        return (out.stdout or "") + (out.stderr or "")
    except Exception as error:  # noqa: BLE001
        return f"failed: {error}"


def _cached(key: str, seconds: float, build) -> dict:
    hit = _cache.get(key)
    if hit and time.time() - hit[0] < seconds:
        return hit[1]
    value = build()
    _cache[key] = (time.time(), value)
    return value


# --- trace sessions ---------------------------------------------------------------------------

def _provider_names() -> dict[str, str]:
    table = {}
    for line in _run(["logman", "query", "providers"]).splitlines():
        match = re.match(r"^(.*?)\s+(\{[0-9A-Fa-f-]{36}\})\s*$", line)
        if match:
            table[match.group(2).lower()] = match.group(1).strip()
    return table


def trace_sessions() -> dict:
    def build() -> dict:
        names = _provider_names()
        listing = _run(["logman", "query", "-ets"])
        sessions = []
        for line in listing.splitlines():
            match = re.match(r"^(.*?)\s+Trace\s+Running\s*$", line)
            if not match:
                continue
            name = match.group(1).strip()
            detail = _run(["logman", "query", name, "-ets"])
            providers, mode, output = [], "", ""
            current = None
            for row in detail.splitlines():
                text = row.strip()
                if text.startswith("File Mode"):
                    mode = text.split(":", 1)[1].strip()
                elif text.startswith("Output Location"):
                    output = text.split(":", 1)[1].strip()
                elif text.startswith("Name:"):
                    current = text.split(":", 1)[1].strip()
                elif text.startswith("Provider Guid:"):
                    guid = text.split(":", 1)[1].strip().lower()
                    label = names.get(guid) or (current if current and not current.startswith("{") else None)
                    providers.append({"guid": guid, "name": label})
            sessions.append({"name": name, "mode": mode, "output": output, "providers": providers})
        return {"sessions": sessions, "read_at": time.time()}

    return _cached("sessions", 300, build)


# --- Windows telemetry state ----------------------------------------------------------------

def _folder_stats(path: Path) -> dict | None:
    if not path.exists():
        return None
    size = count = 0
    newest = 0.0
    for root, _dirs, files in os.walk(path):
        for file in files:
            try:
                stat = os.stat(os.path.join(root, file))
            except OSError:
                continue
            size += stat.st_size
            count += 1
            newest = max(newest, stat.st_mtime)
    return {"bytes": size, "files": count, "newest": newest or None}


def _rule_files() -> dict:
    result: dict = {"folder": str(DIAGNOSIS / "DownloadedSettings"), "files": [], "providers": 0, "endpoints": []}
    folder = DIAGNOSIS / "DownloadedSettings"
    if not folder.exists():
        return result
    endpoints = set()
    for path in sorted(folder.glob("*.json")):
        stat = path.stat()
        result["files"].append({"name": path.name, "bytes": stat.st_size, "modified": stat.st_mtime})
        if path.name.lower() == "utc.app.json":
            try:
                settings = json.loads(path.read_text(encoding="utf-8-sig", errors="replace")).get("settings", {})
            except (ValueError, OSError):
                continue
            for key, value in settings.items():
                upper = key.upper()
                if "PROVIDERDEFINITION" in upper:
                    result["providers"] += 1
                elif "ENDPOINT" in upper and isinstance(value, str):
                    for host in re.findall(r"https?://([A-Za-z0-9.-]+)", value):
                        endpoints.add(host.lower())
            result["refreshed"] = stat.st_mtime
    result["endpoints"] = sorted(endpoints)
    return result


def _autologger() -> dict | None:
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SYSTEM\CurrentControlSet\Control\WMI\Autologger\Diagtrack-Listener") as key:
            try:
                start = winreg.QueryValueEx(key, "Start")[0]
            except OSError:
                start = None
            return {"start": start, "providers": winreg.QueryInfoKey(key)[0]}
    except OSError:
        return None


def transcript(limit: int = 200, database: Path | None = None) -> dict:
    """Read the Diagnostic Data Viewer database, if Windows is keeping one."""
    database = database or (DIAGNOSIS / "EventTranscript" / "EventTranscript.db")
    enabled = None
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, TRANSCRIPT_KEY) as key:
            enabled = bool(winreg.QueryValueEx(key, "EnableEventTranscript")[0])
    except OSError:
        pass
    result: dict = {"enabled": enabled, "present": database.exists(), "events": [], "by_name": [], "total": 0}
    if not database.exists():
        return result
    result["bytes"] = database.stat().st_size
    try:
        conn = sqlite3.connect(f"file:{database.as_posix()}?mode=ro", uri=True, timeout=3)
        conn.row_factory = sqlite3.Row
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        if "events_persisted" not in tables:
            result["note"] = f"unexpected layout; tables: {sorted(tables)[:8]}"
            return result
        columns = {row[1] for row in conn.execute("PRAGMA table_info(events_persisted)")}
        name_column = "full_event_name" if "full_event_name" in columns else None
        if name_column is None:
            result["note"] = "unexpected layout: no event name column"
            return result
        result["total"] = conn.execute("SELECT COUNT(*) FROM events_persisted").fetchone()[0]
        result["by_name"] = [{"name": row[0], "count": row[1]} for row in conn.execute(
            f"SELECT {name_column}, COUNT(*) FROM events_persisted GROUP BY 1 ORDER BY 2 DESC LIMIT 40")]
        wanted = [column for column in ("timestamp", name_column, "logging_binary_name", "payload") if column in columns]
        order = "timestamp DESC" if "timestamp" in columns else "rowid DESC"
        for row in conn.execute(f"SELECT {', '.join(wanted)} FROM events_persisted ORDER BY {order} LIMIT ?", (limit,)):
            item = dict(row)
            payload = item.get("payload")
            if isinstance(payload, bytes):
                payload = payload.decode("utf-8", "replace")
            item["payload"] = (payload or "")[:1500]
            result["events"].append(item)
        conn.close()
    except sqlite3.Error as error:
        result["note"] = f"could not read: {error}"
    return result


def windows_telemetry() -> dict:
    def build() -> dict:
        return {
            "rules": _rule_files(),
            "autologger": _autologger(),
            "event_store": _folder_stats(DIAGNOSIS),
            "usage_insights": _folder_stats(UQI),
            "transcript": {key: value for key, value in transcript(0).items() if key not in ("events",)},
            "read_at": time.time(),
        }

    return _cached("telemetry", 120, build)
