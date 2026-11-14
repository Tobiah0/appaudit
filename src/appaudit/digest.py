"""The summary: what happened on this PC in a window, in a handful of plain findings.

Joins three things the rest of the product gathers separately: live activity, the app inventory
(do you actually open this app?), and the proof report (is a switched-off setting still active?).
"""

from __future__ import annotations

import sqlite3
import time
from collections import Counter

from . import activity, livestore, proof, store
from .explain import components
from .naming import labels

UNUSED_DAYS = 30


def _apps_by_id() -> dict[str, dict]:
    latest = store.latest_scan()
    if latest is None:
        return {}
    return {app["id"]: app for app in store.load_apps(latest["id"])}


def _reporting_runs(since: float) -> list[dict]:
    """Programs whose main job is reporting, and how often they started."""
    try:
        conn = livestore.connect(readonly=True)
    except (FileNotFoundError, sqlite3.Error):
        return []
    try:
        counts: Counter = Counter()
        tasks: dict[str, str] = {}
        names = components.reporting_names()
        for row in conn.execute("SELECT name, task FROM procs WHERE seen_start = 1 AND started >= ?", (since,)):
            name = (row["name"] or "").lower()
            if name in names:
                counts[row["name"]] += 1
                if row["task"]:
                    tasks[row["name"]] = row["task"]
    finally:
        conn.close()
    return [{"process": name, "runs": runs, "task": tasks.get(name), "what": (components.note(name) or {}).get("what")}
            for name, runs in counts.most_common()]


def build(hours: float = 12) -> dict:
    since = time.time() - hours * 3600
    snapshot = activity.snapshot(since=since)
    apps = _apps_by_id()
    helper = activity.helper_state()

    reporters = []
    idle_but_active = []
    for actor in snapshot["actors"]:
        if actor["reporting_sent"]:
            targets = [d["name"] or d["address"] for d in actor["destinations"] if d["category"] in labels.REPORTING][:4]
            reporters.append({"name": actor["name"], "is_system": actor["is_system"], "sent": actor["reporting_sent"],
                              "to": targets})
        app = apps.get(actor["id"])
        if app and not actor["is_system"]:
            days = app.get("days_unused")
            never = app.get("usage") is None and not app.get("used_undated")
            starts_itself = bool(app.get("autostart_enabled"))
            if (days is not None and days >= UNUSED_DAYS) or (never and (app.get("launchable") or starts_itself)):
                idle_but_active.append({
                    "name": actor["name"], "days_unused": days, "never_recorded": never,
                    "sent": actor["sent"], "received": actor["received"], "launchable": app.get("launchable"),
                    "companies": sorted({d["company"] for d in actor["destinations"] if d["company"]})[:4],
                    "starts_itself": bool(app.get("autostart_enabled"))})
    reporters.sort(key=lambda item: -item["sent"])
    idle_but_active.sort(key=lambda item: -(item["sent"] + item["received"]))

    report = proof.report(hours)
    contradictions = [{"title": item["title"], "seen": item["window"], "text": item["text"]}
                      for item in report["items"] if item["verdict"] == "off_but_active"]
    return {
        "hours": hours, "watching": helper,
        "totals": snapshot["totals"],
        "top": [{"name": actor["name"], "sent": actor["sent"], "received": actor["received"], "is_system": actor["is_system"],
                 "destinations": actor["destination_count"]} for actor in snapshot["actors"][:6]],
        "companies": [{"company": c["company"], "sent": c["sent"], "received": c["received"], "actors": c["actors"][:5]}
                      for c in snapshot["companies"][:8]],
        "reporters": reporters[:12], "idle_but_active": idle_but_active[:12],
        "reporting_runs": _reporting_runs(since), "contradictions": contradictions,
        "counters": report.get("counters"),
    }
