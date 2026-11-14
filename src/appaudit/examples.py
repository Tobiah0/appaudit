"""What one message to a destination looks like.

Two sources, never mixed up:
  captured    a real request recorded on this PC while content capture was switched on
  documented  an illustration built from the format the service publishes (knowledge/examples.yaml)
"""

from __future__ import annotations

import sqlite3
from functools import lru_cache
from pathlib import Path

import yaml

from . import activity, livestore
from .naming import labels

KNOWLEDGE = Path(__file__).resolve().parent / "knowledge"


@lru_cache(maxsize=1)
def _documented() -> tuple[dict[str, dict], dict[str, dict]]:
    entries = yaml.safe_load((KNOWLEDGE / "examples.yaml").read_text(encoding="utf-8"))
    by_id, by_suffix = {}, {}
    for entry in entries:
        item = {"id": entry["id"], "title": entry["title"], "company": entry["company"], "source": entry["source"],
                "url": entry["url"], "note": entry.get("note"), "sample": entry["sample"].rstrip(),
                "fields": [{"name": name, "meaning": meaning} for name, meaning in entry.get("fields") or []]}
        by_id[entry["id"]] = item
        for suffix in entry.get("suffixes") or []:
            by_suffix[suffix.lower()] = item
    return by_id, by_suffix


def documented(host: str | None = None, example_id: str | None = None) -> dict | None:
    by_id, by_suffix = _documented()
    if example_id:
        return by_id.get(example_id)
    parts = (host or "").lower().rstrip(".").split(".")
    for index in range(len(parts)):
        found = by_suffix.get(".".join(parts[index:]))
        if found:
            return found
    return None


def captured(actor_id: str, host: str, addresses: list[str] | None = None, limit: int = 3,
             conn: sqlite3.Connection | None = None) -> list[dict]:
    """Real requests this app sent to this destination.

    One address often answers to several names, and the list shows only one of them. So a request
    matches when its host is the shown name, another host of the same site, or any other name the
    destination's addresses are known by.
    """
    own = conn is None
    try:
        conn = conn or livestore.connect(readonly=True)
    except (FileNotFoundError, sqlite3.Error):
        return []
    hosts = {host.lower()}
    try:
        for address in (addresses or [])[:8]:
            hosts.update(row["name"] for row in conn.execute("SELECT name FROM names WHERE address = ?", (address,)))
        marks = ",".join("?" * len(hosts))
        clauses, values = [f"p.host IN ({marks})"], list(hosts)
        if "." in host and not host.replace(".", "").isdigit() and ":" not in host:
            clauses.append("p.host LIKE ?")
            values.append(f"%.{labels.registrable(host)}")
        rows = conn.execute(
            "SELECT p.*, pr.pid, pr.started, pr.exe, pr.name, pr.package, pr.services, pr.task, pr.cmdline, "
            "pr.parent_exe FROM payloads p JOIN procs pr ON pr.id = p.proc_id "
            f"WHERE {' OR '.join(clauses)} ORDER BY p.at DESC LIMIT 200", values).fetchall()
    except sqlite3.Error:                    # a database written before content capture existed
        return []
    finally:
        if own:
            conn.close()
    who = activity.attributor()
    found = []
    for row in rows:
        proc = {key: row[key] for key in ("pid", "started", "exe", "name", "package", "services", "task", "cmdline",
                                          "parent_exe")}
        if who.actor(proc)["id"] != actor_id:
            continue
        found.append({"at": row["at"], "host": row["host"], "method": row["method"], "url": row["url"],
                      "request_headers": row["request_headers"], "response_headers": row["response_headers"],
                      "body": row["body"], "body_size": row["body_size"]})
        if len(found) >= limit:
            break
    return found


def captured_count() -> int:
    try:
        conn = livestore.connect(readonly=True)
    except (FileNotFoundError, sqlite3.Error):
        return 0
    try:
        return conn.execute("SELECT COUNT(*) FROM payloads").fetchone()[0]
    except sqlite3.Error:
        return 0
    finally:
        conn.close()


def for_destination(actor_id: str, host: str, addresses: list[str] | None = None) -> dict:
    return {"host": host, "captured": captured(actor_id, host, addresses) if actor_id and host else [],
            "documented": documented(host)}
