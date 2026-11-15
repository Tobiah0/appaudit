"""Everything already recorded about one app, for the collapsed detail sections of its view.

Nothing here collects anything new. It gathers, for one actor (an app or Windows component as the
Activity page groups them), what the watcher, the history import and the inventory scan stored:
every destination, an hour-by-hour timeline, the request addresses Windows' own web libraries
reported, DNS lookups, the programs and how they were started, the 60-day history and the
inventory facts. Captured request content, when it was switched on, is included too.

All reads; runs in the unprivileged dashboard process.
"""

from __future__ import annotations

import os
import re
import sqlite3
import time
from collections import defaultdict

from . import activity, livestore
from .naming import labels

_SECRET_ARG = re.compile(r"((?:--?|/)[\w.-]*(?:token|secret|password|passwd|key|auth|session|cookie|credential)[\w.-]*[=: ]+)(\"[^\"]*\"|\S+)",
                         re.IGNORECASE)


def hide_secrets(command: str) -> str:
    """A command line with the values of token, key and password arguments replaced."""
    return _SECRET_ARG.sub(lambda match: f"{match.group(1)}[hidden]", command or "")[:600]


def _chunks(items: list, size: int = 500):
    for start in range(0, len(items), size):
        yield items[start:start + size]


def _actor_procs(conn: sqlite3.Connection, actor_id: str, since: float) -> dict[int, dict]:
    """Processes of this actor that ran or sent anything since `since`."""
    who = activity.attributor()
    candidates = conn.execute(
        "SELECT * FROM procs WHERE (ended IS NULL OR ended >= ?) OR id IN (SELECT proc_id FROM flows WHERE last >= ?)",
        (since, since)).fetchall()
    return {row["id"]: dict(row) for row in candidates if who.actor(dict(row))["id"] == actor_id}


def details(actor_id: str, hours: float = 168) -> dict:
    since = time.time() - hours * 3600
    try:
        conn = livestore.connect(readonly=True)
    except (FileNotFoundError, sqlite3.Error):
        return {"available": False}
    try:
        procs = _actor_procs(conn, actor_id, since)
        ids = sorted(procs)
        flows, requests, lookups, payloads = [], [], [], []
        for chunk in _chunks(ids):
            marks = ",".join("?" * len(chunk))
            flows += conn.execute(f"SELECT * FROM flows WHERE proc_id IN ({marks}) AND last >= ?", (*chunk, since)).fetchall()
            requests += conn.execute(f"SELECT * FROM requests WHERE proc_id IN ({marks})", chunk).fetchall()
            lookups += conn.execute(f"SELECT * FROM lookups WHERE proc_id IN ({marks})", chunk).fetchall()
            payloads += conn.execute(f"SELECT * FROM payloads WHERE proc_id IN ({marks}) ORDER BY at DESC LIMIT 200",
                                     chunk).fetchall()
        names = defaultdict(list)
        addresses = sorted({row["remote"] for row in flows})
        for chunk in _chunks(addresses):
            marks = ",".join("?" * len(chunk))
            for row in conn.execute(f"SELECT address, name FROM names WHERE address IN ({marks}) ORDER BY last DESC", chunk):
                names[row["address"]].append(row["name"])
    finally:
        conn.close()

    exes = sorted({proc["exe"] for proc in procs.values() if proc.get("exe")})
    return {
        "available": True, "hours": hours,
        "destinations": _destinations(flows, names, procs),
        "timeline": _timeline(flows, names),
        "requests": _requests(requests, procs),
        "lookups": _lookups(lookups, procs),
        "programs": _programs(procs),
        "payloads": [_payload(row, procs) for row in payloads],
        "history": _history(exes),
        "inventory": _inventory(exes),
    }


def _destinations(flows, names, procs) -> list[dict]:
    found: dict[str, dict] = {}
    for row in flows:
        label = labels.for_destination(row["remote"], names.get(row["remote"], []))
        key = label["name"] or label["address"]
        entry = found.setdefault(key, {
            "name": label["name"], "company": label["company"] or label["owner"], "category": label["category"],
            "purpose": label["purpose"], "country": label["country"], "sent": 0, "received": 0, "contacts": 0,
            "first": row["first"], "last": row["last"], "addresses": set(), "ports": set(), "programs": set()})
        entry["sent"] += row["sent"]
        entry["received"] += row["received"]
        entry["contacts"] += row["events"]
        entry["first"] = min(entry["first"], row["first"])
        entry["last"] = max(entry["last"], row["last"])
        entry["addresses"].add(row["remote"])
        entry["ports"].add(f"{row['proto']}/{row['port']}")
        entry["programs"].add(procs[row["proc_id"]]["name"])
    result = []
    for key, entry in found.items():
        result.append({**entry, "key": key, "addresses": sorted(entry["addresses"])[:6], "ports": sorted(entry["ports"]),
                       "programs": sorted(entry["programs"])})
    return sorted(result, key=lambda item: -(item["sent"] + item["received"]))


def _timeline(flows, names) -> list[dict]:
    hours: dict[int, dict] = {}
    for row in flows:
        bucket = int(row["bucket"])
        hour = hours.setdefault(bucket, {"hour": bucket, "sent": 0, "received": 0, "reporting": 0})
        hour["sent"] += row["sent"]
        hour["received"] += row["received"]
        label = labels.for_destination(row["remote"], names.get(row["remote"], []))
        if label["category"] in labels.REPORTING:
            hour["reporting"] += row["sent"]
    return [hours[key] for key in sorted(hours)]


def _requests(rows, procs) -> list[dict]:
    merged: dict[tuple, dict] = {}
    for row in rows:
        key = (row["method"] or "", row["url"])
        entry = merged.setdefault(key, {"method": row["method"] or "", "url": row["url"], "count": 0,
                                        "first": row["first"], "last": row["last"], "programs": set()})
        entry["count"] += row["count"]
        entry["first"] = min(entry["first"], row["first"])
        entry["last"] = max(entry["last"], row["last"])
        entry["programs"].add(procs[row["proc_id"]]["name"])
    return sorted(({**entry, "programs": sorted(entry["programs"])} for entry in merged.values()),
                  key=lambda item: -item["count"])


def _lookups(rows, procs) -> list[dict]:
    merged: dict[str, dict] = {}
    for row in rows:
        entry = merged.setdefault(row["name"].lower(), {"name": row["name"], "count": 0, "last": row["last"], "programs": set()})
        entry["count"] += row["count"]
        entry["last"] = max(entry["last"], row["last"])
        entry["programs"].add(procs[row["proc_id"]]["name"])
    return sorted(({**entry, "programs": sorted(entry["programs"])} for entry in merged.values()),
                  key=lambda item: -item["count"])


def _programs(procs) -> list[dict]:
    """One entry per program file: how often it ran, what started it, and how."""
    merged: dict[str, dict] = {}
    for proc in procs.values():
        key = (proc.get("exe") or proc.get("name") or "").lower()
        entry = merged.setdefault(key, {"exe": proc.get("exe") or proc.get("name"), "name": proc.get("name"), "runs": 0,
                                        "started_seen": 0, "parents": set(), "tasks": set(), "services": set(),
                                        "package": proc.get("package"), "commands": set(), "first": proc["started"],
                                        "last": proc.get("ended") or time.time()})
        entry["runs"] += 1
        entry["started_seen"] += 1 if proc.get("seen_start") else 0
        entry["first"] = min(entry["first"], proc["started"])
        if proc.get("parent_exe"):
            entry["parents"].add(proc["parent_exe"].rsplit("\\", 1)[-1])
        if proc.get("task"):
            entry["tasks"].add(proc["task"])
        for service in (proc.get("services") or "").split(","):
            if service:
                entry["services"].add(service)
        if proc.get("cmdline") and len(entry["commands"]) < 8:
            entry["commands"].add(hide_secrets(proc["cmdline"]))
    return sorted(({**entry, "parents": sorted(entry["parents"]), "tasks": sorted(entry["tasks"]),
                    "services": sorted(entry["services"]), "commands": sorted(entry["commands"])}
                   for entry in merged.values()), key=lambda item: -item["runs"])


def _payload(row, procs) -> dict:
    return {"program": procs[row["proc_id"]]["name"], "host": row["host"], "method": row["method"], "url": row["url"],
            "at": row["at"], "request_headers": row["request_headers"], "response_headers": row["response_headers"],
            "body": row["body"], "body_size": row["body_size"]}


def _history(exes: list[str]) -> list[dict]:
    """Windows' own per-day record for these programs: data used, and time in front and typed into."""
    from . import history

    if not exes:
        return []
    wanted = {os.path.normcase(exe) for exe in exes} | {exe.rsplit("\\", 1)[-1].lower() for exe in exes}
    try:
        conn = sqlite3.connect(f"file:{history.path()}?mode=ro", uri=True)
    except sqlite3.Error:
        return []
    days: dict[str, dict] = {}
    try:
        for app, exe, day, sent, received, focus, typed in conn.execute(
                "SELECT app, exe, day, sent, received, focus_seconds, input_seconds FROM history"):
            candidates = {os.path.normcase(exe or ""), (exe or "").rsplit("\\", 1)[-1].lower(), (app or "").rsplit("\\", 1)[-1].lower()}
            if not candidates & wanted:
                continue
            entry = days.setdefault(day, {"day": day, "sent": 0, "received": 0, "focus_seconds": 0, "input_seconds": 0})
            entry["sent"] += sent
            entry["received"] += received
            entry["focus_seconds"] += focus
            entry["input_seconds"] += typed
    except sqlite3.Error:
        return []
    finally:
        conn.close()
    return [days[key] for key in sorted(days)]


def _inventory(exes: list[str]) -> dict | None:
    """The inventory scan's record for the installed app these programs belong to."""
    from . import store

    latest = store.latest_scan()
    if latest is None or not exes:
        return None
    paths = [os.path.normcase(exe) for exe in exes]
    best, best_length = None, 0
    for app in store.load_apps(latest["id"]):
        folder = os.path.normcase(app.get("install_dir") or "")
        if len(folder) > 3 and any(path.startswith(folder.rstrip("\\") + "\\") for path in paths) and len(folder) > best_length:
            best, best_length = app, len(folder)
    if best is None:
        return None
    keep = ("name", "publisher", "install_dir", "usage", "days_unused", "autostart", "running", "sensors", "findings",
            "last_self_run")
    return {key: best.get(key) for key in keep}
