"""Proof: compare what a switch claims with what the PC actually did.

Each catalogue switch may carry an `expect` block saying what should go quiet when it is off:

  processes, services, tasks   programs the switch stops outright. Their runs and all their
                               traffic count.
  domains                      addresses the switch stops traffic to. Traffic to them counts only
                               when one of the programs above, or one named under `senders`, sent
                               it. Many collection addresses are shared: Defender and OneDrive use
                               the same Microsoft endpoint as the telemetry service, and a browser
                               reaches Bing or Adobe's analytics because of the pages you open.
  senders                      {processes: [...], services: [...]}: programs whose traffic counts
                               only when it goes to `domains`. Their runs do not count.

A *footprint* is how much of that was observed in a time window. Comparing the footprint before
and after a switch was applied gives a verdict.
"""

from __future__ import annotations

import os
import sqlite3
import time
from collections import defaultdict

from . import livestore, switches
from .naming import labels

MIN_HOURS = 1.0          # observation needed on each side before a before/after verdict is given
NAME_VALID = 24 * 3600   # an address counts as a name for this long after the name was last resolved


def _suffix_match(name: str, suffixes: list[str]) -> bool:
    name = name.lower()
    return any(name == suffix or name.endswith("." + suffix) for suffix in suffixes)


def _lower(items) -> list[str]:
    return [item.lower() for item in items or []]


def validate_expect(expect: dict, switch_id: str) -> None:
    """Domains alone are not evidence: someone the switch controls must have sent the traffic."""
    unknown = set(expect) - {"processes", "services", "tasks", "domains", "senders", "reporting_from"}
    if unknown:
        raise ValueError(f"{switch_id}: unknown expect keys {sorted(unknown)}")
    senders = expect.get("senders") or {}
    if set(senders) - {"processes", "services"}:
        raise ValueError(f"{switch_id}: senders takes only processes and services")
    owners = expect.get("processes") or expect.get("services") or expect.get("tasks")
    if expect.get("domains") and not (owners or senders.get("processes") or senders.get("services")):
        raise ValueError(f"{switch_id}: domains need the programs that send to them (processes, services or senders)")
    if senders and not expect.get("domains"):
        raise ValueError(f"{switch_id}: senders only count traffic to domains, and none are listed")
    reporting = expect.get("reporting_from") or {}
    if reporting and (set(reporting) - {"processes"} or not reporting.get("processes")):
        raise ValueError(f"{switch_id}: reporting_from takes a list of processes")


def _names(conn: sqlite3.Connection) -> dict[str, list[tuple[str, float, float]]]:
    """Every name each address was resolved to, with when it was first and last resolved."""
    found: dict[str, list[tuple[str, float, float]]] = defaultdict(list)
    for row in conn.execute("SELECT address, name, first, last FROM names"):
        found[row["address"]].append((row["name"], row["first"], row["last"]))
    return found


def _names_at(entries: list[tuple[str, float, float]], first: float, last: float) -> list[str]:
    """Names an address had while a flow ran. Addresses are reused by CDNs and cloud hosts, so a
    name resolved long before the flow is not taken as the flow's destination."""
    return [name for name, seen_first, seen_last in entries
            if seen_first <= last and seen_last >= first - NAME_VALID]


def footprint(conn: sqlite3.Connection, expect: dict, since: float, until: float) -> dict:
    """Observed activity matching `expect` between two times."""
    processes = set(_lower(expect.get("processes")))
    services = set(_lower(expect.get("services")))
    tasks = _lower(expect.get("tasks"))
    domains = _lower(expect.get("domains"))
    sender_spec = expect.get("senders") or {}
    sender_processes = set(_lower(sender_spec.get("processes")))
    sender_services = set(_lower(sender_spec.get("services")))
    # reporting_from: these programs' traffic counts when it goes to a destination the knowledge base
    # calls reporting (telemetry or advertising). Used where no list of hosts is known, e.g. switches
    # imported from toptout.
    reporting_processes = set(_lower((expect.get("reporting_from") or {}).get("processes")))

    owned: set[int] = set()          # the switch stops these outright: runs and all traffic count
    senders_only: set[int] = set()   # only their traffic to `domains` counts
    reporting_only: set[int] = set()  # only their traffic to reporting destinations counts
    runs = defaultdict(int)
    for row in conn.execute("SELECT id, name, services, task, started, ended, seen_start, cmdline FROM procs "
                            "WHERE started <= ? AND (ended IS NULL OR ended >= ?)", (until, since)):
        name = (row["name"] or "").lower()
        hosted = {item.lower() for item in (row["services"] or "").split(",") if item}
        task = (row["task"] or "").lower()
        if name in processes or hosted & services or (task and any(task.startswith(prefix) for prefix in tasks)):
            owned.add(row["id"])
            if row["seen_start"] and since <= row["started"] <= until:
                runs[row["name"]] += 1
        elif name in sender_processes or hosted & sender_services:
            senders_only.add(row["id"])
        elif name in reporting_processes and "--user-data-dir=" not in (row["cmdline"] or "").lower():
            # A run with its own profile (--user-data-dir) is not governed by the user's settings,
            # so it is no evidence for or against a setting in the user's profile.
            reporting_only.add(row["id"])

    names = _names(conn) if (owned or senders_only or reporting_only) else {}

    sent = received = contacts = 0
    destinations: dict[str, int] = defaultdict(int)
    senders: dict[str, int] = defaultdict(int)
    buckets = set()
    for row in conn.execute("SELECT f.proc_id, f.remote, f.sent, f.received, f.events, f.bucket, f.first, f.last, "
                            "p.name FROM flows f JOIN procs p ON p.id = f.proc_id "
                            "WHERE f.last >= ? AND f.first <= ?", (since, until)):
        buckets.add(row["bucket"])
        if row["proc_id"] not in owned and row["proc_id"] not in senders_only and row["proc_id"] not in reporting_only:
            continue
        current = _names_at(names.get(row["remote"], []), row["first"], row["last"])
        expected = [name for name in current if _suffix_match(name, domains)]
        if row["proc_id"] in senders_only and not expected:
            continue
        if row["proc_id"] in reporting_only:
            expected = [name for name in current if labels.for_name(name)["category"] in labels.REPORTING]
            if not expected:
                continue
        sent += row["sent"]
        received += row["received"]
        contacts += row["events"]
        label = (expected or current or [row["remote"]])[0]
        destinations[label] += row["sent"] + row["received"]
        senders[row["name"]] += row["sent"]
    return {
        "runs": sum(runs.values()), "run_names": dict(runs), "sent": sent, "received": received,
        "contacts": contacts, "hours_observed": len(buckets),
        "destinations": sorted(destinations.items(), key=lambda item: -item[1])[:6],
        "senders": sorted(senders.items(), key=lambda item: -item[1])[:6],
        "active": bool(sum(runs.values()) or sent or received),
    }


def _rate(mark: dict) -> float:
    """Activity per observed hour: runs count most, then bytes sent."""
    hours = max(mark["hours_observed"], 1)
    return (mark["runs"] * 1000 + mark["sent"]) / hours


def compare(before: dict, after: dict) -> dict:
    if before["hours_observed"] < MIN_HOURS or after["hours_observed"] < MIN_HOURS:
        return {"verdict": "waiting", "text": "Not enough observation yet on both sides of the change."}
    if not before["active"] and not after["active"]:
        return {"verdict": "nothing_seen", "text": "Nothing matching this switch was seen before or after."}
    if not after["active"]:
        return {"verdict": "stopped", "text": "The activity stopped after the switch was turned off."}
    if not before["active"]:
        return {"verdict": "unchanged", "text": "Activity was seen after the change that was not seen before it."}
    ratio = _rate(after) / _rate(before) if _rate(before) else 1.0
    if ratio < 0.5:
        return {"verdict": "reduced", "text": f"Activity fell to about {round(ratio * 100)}% of what it was.", "ratio": ratio}
    return {"verdict": "unchanged", "text": "The activity continued at a similar level.", "ratio": ratio}


def now_verdict(state: str, mark: dict) -> dict:
    """What can be said without a before/after: the setting against the observed activity."""
    off = state == "private"
    if mark["hours_observed"] < MIN_HOURS:
        return {"verdict": "waiting", "text": "Less than an hour of observation so far."}
    if off and mark["active"]:
        return {"verdict": "off_but_active", "text": "The setting is off, but matching activity was still seen."}
    if off:
        return {"verdict": "off_and_quiet", "text": "The setting is off and nothing matching it was seen."}
    if mark["active"]:
        return {"verdict": "on_and_active", "text": "The setting is on and it is in use."}
    return {"verdict": "on_but_quiet", "text": "The setting is on, but nothing matching it was seen in this window."}


def _expect_programs(expect: dict) -> set[str]:
    names = set(_lower(expect.get("processes")))
    names |= set(_lower((expect.get("senders") or {}).get("processes")))
    names |= set(_lower((expect.get("reporting_from") or {}).get("processes")))
    return names


def _matches_expect(host: str, expect: dict) -> bool:
    """Whether a request to `host` is the kind of traffic the switch should stop."""
    from .naming import labels

    domains = _lower(expect.get("domains"))
    if domains and _suffix_match(host, domains):
        return True
    if expect.get("reporting_from") or expect.get("processes"):
        return labels.for_name(host)["category"] in labels.REPORTING
    return False


def inspection_evidence(expect: dict, applied: float | None = None, listing=None, load_report=None) -> list[dict]:
    """Inspections of the switch's programs, newest first, with how many requests matched what it
    should stop. An inspection records every request the app made while it ran, so it is direct
    evidence: after a switch, "0 of 68 requests" means the switch held during that run."""
    from . import inspection

    programs = _expect_programs(expect)
    if not programs:
        return []
    listing = listing if listing is not None else inspection.listing()
    load_report = load_report or inspection.report
    found = []
    for meta in listing:
        if meta.get("status") != "done" or os.path.basename(meta.get("exe") or "").lower() not in programs:
            continue
        report = (load_report(meta["id"]) or {}).get("report") or {}
        requests = report.get("requests") or []
        matching = [item for item in requests if _matches_expect(item.get("host") or "", expect)]
        found.append({"id": meta["id"], "started": meta["started"], "app": meta.get("app"), "requests": len(requests),
                      "matching": len(matching), "hosts": sorted({item["host"] for item in matching})[:6],
                      "after_change": applied is not None and meta["started"] >= applied,
                      "verdict": "quiet" if requests and not matching else ("active" if matching else "empty")})
    return sorted(found, key=lambda item: -item["started"])


def upload_counters() -> dict | None:
    """Windows' own record of its telemetry uploads: a second witness for the telemetry service."""
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack") as key:
            def read(name):
                try:
                    return winreg.QueryValueEx(key, name)[0]
                except OSError:
                    return None
            last = read("LastSuccessfulUploadTime")
            return {"last_upload": livestore.filetime_to_unix(last) if last else None,
                    "uploads": read("HttpRequestCount"), "triggers": read("TriggerCount")}
    except OSError:
        return None


def report(hours: float = 24, conn: sqlite3.Connection | None = None, backend=None, journal_file=None) -> dict:
    own = conn is None
    if own:
        try:
            conn = livestore.connect(readonly=True)
        except (FileNotFoundError, sqlite3.Error):
            return {"items": [], "watching": False, "counters": upload_counters()}
    now = time.time()
    since = now - hours * 3600
    applied: dict[str, dict] = {}
    for entry in switches.journal_entries(journal_file, (backend.name if backend else "real")):
        if not entry["undone"]:
            applied.setdefault(entry["switch_id"], entry)
    items = []
    try:
        for switch in switches.load_catalogue().values():
            if not switch.expect:
                continue
            state = switches.state(switch, backend)
            if state["state"] == "not_installed":
                continue
            mark = footprint(conn, switch.expect, since, now)
            item = {"id": switch.id, "title": switch.title, "group": switch.group, "state": state["state"],
                    "expect": switch.expect, "window": mark, **now_verdict(state["state"], mark)}
            entry = applied.get(switch.id)
            inspections = inspection_evidence(switch.expect, entry["applied"] if entry else None)
            if inspections:
                item["inspections"] = inspections[:5]
            if entry:
                changed = entry["applied"]
                before = footprint(conn, switch.expect, changed - 24 * 3600, changed)
                after = footprint(conn, switch.expect, changed, now)
                item["change"] = {"applied": changed, "before": before, "after": after, **compare(before, after)}
            items.append(item)
    finally:
        if own:
            conn.close()
    order = {"off_but_active": 0, "on_and_active": 1, "waiting": 2, "on_but_quiet": 3, "off_and_quiet": 4}
    items.sort(key=lambda item: (order.get(item["verdict"], 5), -item["window"]["sent"]))
    return {"items": items, "watching": True, "hours": hours, "counters": upload_counters()}
