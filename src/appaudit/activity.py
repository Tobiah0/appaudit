"""Read model over the live database: who talked to whom, grouped the way people ask about it.

Everything here is read-only and runs in the unprivileged dashboard process.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from collections import defaultdict

from . import livestore
from .attribution import Attributor
from .naming import labels
from .naming.owners import OWNERS

_attributor: Attributor | None = None
_attributor_lock = threading.Lock()


def attributor() -> Attributor:
    global _attributor
    with _attributor_lock:
        if _attributor is None:
            _attributor = Attributor()
            OWNERS.load_in_background()
        return _attributor


def _connect() -> sqlite3.Connection | None:
    try:
        return livestore.connect(readonly=True)
    except (FileNotFoundError, sqlite3.Error):
        return None


def helper_state() -> dict:
    conn = _connect()
    if conn is None:
        return {"running": False, "ever_ran": False}
    try:
        meta = livestore.get_meta(conn)
    finally:
        conn.close()
    heartbeat = float(meta.get("heartbeat", 0) or 0)
    return {
        "running": meta.get("session_alive") == "1" and time.time() - heartbeat < 30,
        "ever_ran": bool(meta), "since": float(meta.get("started", 0) or 0), "heartbeat": heartbeat,
        "events": int(meta.get("events", 0) or 0), "lost": int(meta.get("lost", 0) or 0),
        "packets": meta.get("packets"), "last_error": meta.get("last_error"),
    }


def _names_for(conn: sqlite3.Connection, addresses: set[str]) -> dict[str, list[str]]:
    found: dict[str, list[str]] = defaultdict(list)
    items = list(addresses)
    for start in range(0, len(items), 500):
        chunk = items[start:start + 500]
        marks = ",".join("?" * len(chunk))
        for row in conn.execute(f"SELECT address, name FROM names WHERE address IN ({marks}) ORDER BY last DESC", chunk):
            found[row["address"]].append(row["name"])
    return found


def _url_hosts(conn: sqlite3.Connection, proc_ids: list[int]) -> dict[int, set[str]]:
    hosts: dict[int, set[str]] = defaultdict(set)
    for start in range(0, len(proc_ids), 500):
        chunk = proc_ids[start:start + 500]
        marks = ",".join("?" * len(chunk))
        for row in conn.execute(f"SELECT proc_id, url FROM requests WHERE proc_id IN ({marks})", chunk):
            host = row["url"].split("://", 1)[-1].split("/", 1)[0].split(":")[0].lower()
            if host:
                hosts[row["proc_id"]].add(host)
    return hosts


def snapshot(since: float | None = None, until: float | None = None) -> dict:
    """Everything the dashboard needs for one time window, grouped by actor and by company."""
    conn = _connect()
    if conn is None:
        return {"actors": [], "companies": [], "window": None, "totals": {}}
    since = since if since is not None else time.time() - 24 * 3600
    until = until if until is not None else time.time() + 60
    who = attributor()
    try:
        flows = conn.execute(
            "SELECT f.proc_id, f.remote, f.port, f.proto, SUM(f.sent) sent, SUM(f.received) received, "
            "SUM(f.events) events, MIN(f.first) first, MAX(f.last) last FROM flows f "
            "WHERE f.last >= ? AND f.first <= ? GROUP BY f.proc_id, f.remote, f.port, f.proto", (since, until)).fetchall()
        proc_ids = sorted({row["proc_id"] for row in flows})
        procs = {}
        for start in range(0, len(proc_ids), 500):
            chunk = proc_ids[start:start + 500]
            marks = ",".join("?" * len(chunk))
            for row in conn.execute(f"SELECT * FROM procs WHERE id IN ({marks})", chunk):
                procs[row["id"]] = dict(row)
        names = _names_for(conn, {row["remote"] for row in flows})
        lookups: dict[int, list[str]] = defaultdict(list)
        for start in range(0, len(proc_ids), 500):
            chunk = proc_ids[start:start + 500]
            marks = ",".join("?" * len(chunk))
            for row in conn.execute(f"SELECT proc_id, name FROM lookups WHERE proc_id IN ({marks})", chunk):
                lookups[row["proc_id"]].append(row["name"])
    finally:
        conn.close()

    actors: dict[str, dict] = {}
    companies: dict[str, dict] = {}
    destination_cache: dict[str, dict] = {}
    totals = {"sent": 0, "received": 0, "destinations": set(), "named": set(), "reporting_bytes": 0}
    for row in flows:
        proc = procs.get(row["proc_id"])
        if proc is None:
            continue
        actor_info = who.actor(proc)
        actor = actors.get(actor_info["id"])
        if actor is None:
            actor = actors[actor_info["id"]] = {
                **actor_info, "sent": 0, "received": 0, "first": row["first"], "last": row["last"],
                "destinations": {}, "processes": set(), "runs": set(), "tasks": set(), "exes": set(),
                "categories": defaultdict(int)}
        destination = destination_cache.get(row["remote"])
        if destination is None:
            destination = destination_cache[row["remote"]] = labels.for_destination(row["remote"], names.get(row["remote"], []))
        volume = row["sent"] + row["received"]
        actor["sent"] += row["sent"]
        actor["received"] += row["received"]
        actor["first"] = min(actor["first"], row["first"])
        actor["last"] = max(actor["last"], row["last"])
        actor["processes"].add(proc["name"])
        if proc.get("exe"):
            actor["exes"].add(proc["exe"])
        actor["runs"].add(proc["id"])
        if proc.get("task"):
            actor["tasks"].add(proc["task"])
        category = destination["category"] or "unknown"
        actor["categories"][category] += volume
        key = destination["name"] or destination["address"]
        entry = actor["destinations"].get(key)
        if entry is None:
            entry = actor["destinations"][key] = {
                "name": destination["name"], "address": destination["address"], "company": destination["company"],
                "category": destination["category"], "purpose": destination["purpose"], "tracker": destination["tracker"],
                "owner": destination["owner"], "country": destination["country"], "breaks": destination["breaks"],
                "ports": set(), "sent": 0, "received": 0, "last": row["last"], "addresses": set()}
        entry["sent"] += row["sent"]
        entry["received"] += row["received"]
        entry["last"] = max(entry["last"], row["last"])
        entry["ports"].add(f"{row['proto']}/{row['port']}")
        entry["addresses"].add(row["remote"])

        company_name = destination["company"] or "Unknown"
        company = companies.get(company_name)
        if company is None:
            company = companies[company_name] = {"company": company_name, "sent": 0, "received": 0,
                                                 "actors": set(), "categories": defaultdict(int), "destinations": set()}
        company["sent"] += row["sent"]
        company["received"] += row["received"]
        company["actors"].add(actor_info["name"])
        company["categories"][category] += volume
        company["destinations"].add(key)

        totals["sent"] += row["sent"]
        totals["received"] += row["received"]
        totals["destinations"].add(row["remote"])
        if destination["name"]:
            totals["named"].add(row["remote"])
        if category in labels.REPORTING:
            totals["reporting_bytes"] += row["sent"]

    actor_list = []
    for actor in actors.values():
        destinations = sorted(actor["destinations"].values(), key=lambda item: -(item["sent"] + item["received"]))
        for item in destinations:
            item["ports"] = sorted(item["ports"])
            item["addresses"] = sorted(item["addresses"])[:4]
        actor.update(destinations=destinations[:60], destination_count=len(destinations),
                     processes=sorted(actor["processes"]), exes=sorted(actor["exes"])[:8], runs=len(actor["runs"]), tasks=sorted(actor["tasks"]),
                     categories=dict(actor["categories"]),
                     reporting_sent=sum(item["sent"] for item in destinations if item["category"] in labels.REPORTING))
        actor_list.append(actor)
    actor_list.sort(key=lambda item: -(item["sent"] + item["received"]))
    company_list = [{**company, "actors": sorted(company["actors"]), "categories": dict(company["categories"]),
                     "destinations": len(company["destinations"])} for company in companies.values()]
    company_list.sort(key=lambda item: -(item["sent"] + item["received"]))
    return {
        "window": {"since": since, "until": until}, "actors": actor_list, "companies": company_list,
        "totals": {"sent": totals["sent"], "received": totals["received"], "destinations": len(totals["destinations"]),
                   "named": len(totals["named"]), "reporting_sent": totals["reporting_bytes"],
                   "actors": len(actor_list)},
    }


def recent_processes(limit: int = 200, system_only: bool = False) -> list[dict]:
    """Processes that started while the helper was watching, newest first."""
    conn = _connect()
    if conn is None:
        return []
    who = attributor()
    try:
        rows = conn.execute("SELECT * FROM procs WHERE seen_start = 1 ORDER BY started DESC LIMIT ?", (limit * 3,)).fetchall()
    finally:
        conn.close()
    result = []
    for row in rows:
        proc = dict(row)
        actor = who.actor(proc)
        if system_only and not actor["is_system"]:
            continue
        result.append({"when": proc["started"], "ended": proc["ended"], "process": proc["name"], "actor": actor["name"],
                       "role": actor["role"] or actor["host"], "is_system": actor["is_system"], "task": proc["task"],
                       "parent": (proc["parent_exe"] or "").rsplit("\\", 1)[-1] or None, "exe": proc["exe"]})
        if len(result) >= limit:
            break
    return result
