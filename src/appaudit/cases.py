"""Cases: the short list of things a person would actually want to know, each with an action.

A case is one sentence a person can agree or disagree with, the evidence for it, and what can be
done about it (PRODUCT.md). Cases come from contrasts between things the tool already measures:

  says against does     a switch is off, yet what it should stop was seen (proof: off_but_active)
  can be switched off   a switch is on, what it controls was seen, and the switch exists
  third party           an app sent data to a reporting or advertising company other than its maker
  used against active   an app you never or rarely open starts by itself and uses the network
  new company           an app contacted a company it had not contacted before in the recorded data

Every case has a stable id, so a person's decision sticks: "accepted" hides it until its evidence
changes (a new company, or a much larger amount), "fixed" is only shown once proof agrees. The
statement says what was observed, never what anyone intended.
"""

from __future__ import annotations

import hashlib
import re
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from .store import data_dir

SCHEMA = """
CREATE TABLE IF NOT EXISTS case_state (
    id TEXT PRIMARY KEY, state TEXT NOT NULL, fingerprint TEXT NOT NULL, changed REAL NOT NULL, note TEXT
) WITHOUT ROWID;
"""
STATES = {"open", "accepted", "testing"}
MIN_THIRD_PARTY = 10 * 1024                 # below this, a contact is noise rather than a case
SMALL_UNUSED = 100 * 1024                   # rarely used apps below this are grouped into one case
UPDATER = re.compile(r"update|updater", re.IGNORECASE)
SEVERITY = {"high": 3, "medium": 2, "low": 1}
_COMPANY_NOISE = re.compile(r"\b(inc|llc|ltd|limited|corp|corporation|co|company|gmbh|ab|pbc|plc|sa|ag|bv|labs?|"
                            r"technologies|technology|software|systems|games|studios?|the)\b|[.,()]")


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


def _norm_company(name: str | None) -> str:
    return " ".join(_COMPANY_NOISE.sub(" ", (name or "").lower()).split())


def same_company(publisher: str | None, company: str | None) -> bool:
    """Whether a destination's company is the app's own maker (first party)."""
    left, right = _norm_company(publisher), _norm_company(company)
    if not left or not right:
        return False
    return left == right or left.split()[0] == right.split()[0]


def _fingerprint(*parts) -> str:
    return hashlib.sha1("|".join(str(part) for part in parts).encode()).hexdigest()[:12]


def _size_band(value: int) -> int:
    """Amounts within a factor of four count as the same, so an accepted case reopens only on a big change."""
    band = 0
    while value >= 4 ** (band + 1) * 1024:
        band += 1
    return band


def _bytes(value: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}".replace(".0 ", " ")
        value /= 1024
    return f"{value:.1f} GB"


# --- building cases ---------------------------------------------------------------------------

def _switch_actions(switches_for_app: list[dict]) -> list[dict]:
    return [{"type": "switch", "id": item["id"], "title": item["title"], "state": item["state"]}
            for item in switches_for_app if item["state"] in ("exposed", "partly", "manual")]


def build(hours: float = 24, now: float | None = None) -> list[dict]:
    """All cases for the window, before people's decisions are applied."""
    from . import activity, digest, proof, switches

    now = now or time.time()
    snapshot = activity.snapshot(since=now - hours * 3600)
    found: list[dict] = []

    # says against does / can be switched off
    report = proof.report(hours)
    catalogue = switches.load_catalogue()
    quiet_runs: dict[str, list[dict]] = {}
    for item in report["items"]:
        window = item["window"]
        senders = [name for name, _ in window["senders"]]
        where = [name for name, _ in window["destinations"]]
        seen = []
        if window["sent"]:
            seen.append(f"sent {_bytes(window['sent'])}" + (f" to {', '.join(where[:2])}" if where else ""))
        if window["runs"]:
            seen.append(f"ran {window['runs']} time{'s' if window['runs'] != 1 else ''}")
        what = " and ".join(seen)
        by = f" ({', '.join(senders[:2])})" if senders else ""
        if item["verdict"] == "off_but_active":
            quiet = not window["sent"]
            found.append({
                "id": f"off-but-active:{item['id']}", "kind": "says_vs_does", "severity": "medium" if quiet else "high",
                "app": item["title"], "title": f"{item['title']} is switched off, but what it controls still {what}{by}"
                + ("; nothing was sent." if quiet else "."),
                "evidence": {"switch": item["id"], "window": window},
                "actions": [{"type": "proof", "id": item["id"]}, {"type": "inspect_switch", "id": item["id"]}],
                "fingerprint": _fingerprint(sorted(where), sorted(senders)),
            })
        elif item["verdict"] == "on_and_active" and item["id"] in catalogue and not window["sent"]:
            quiet_runs.setdefault(item["group"], []).append(item)
        elif item["verdict"] == "on_and_active" and item["id"] in catalogue:
            found.append({
                "id": f"can-switch-off:{item['id']}", "kind": "switchable", "severity": "medium",
                "app": item["title"], "title": f"{item['title']} is on and in use: it {what}{by}. A switch turns it off.",
                "evidence": {"switch": item["id"], "window": window},
                "actions": [{"type": "switch", "id": item["id"], "title": item["title"], "state": item["state"]}],
                "fingerprint": _fingerprint(sorted(where), _size_band(window["sent"])),
            })

    # Reporting programs that only ran (nothing sent): one case per group of switches.
    for group, items in quiet_runs.items():
        runs = sum(item["window"]["runs"] for item in items)
        titles = [item["title"] for item in items]
        found.append({
            "id": f"can-switch-off-group:{group}", "kind": "switchable", "severity": "low",
            "app": group, "title": (f"{titles[0]} ran {runs} time{'s' if runs != 1 else ''} by itself. A switch turns it off."
                                    if len(items) == 1 else
                                    f"{len(items)} reporting programs in {group} ran {runs} times by themselves ({', '.join(titles[:4])}"
                                    + (f" and {len(titles) - 4} more" if len(titles) > 4 else "") + f"). {len(items)} switches turn them off."),
            "evidence": {"switches": [item["id"] for item in items], "runs": runs},
            "actions": [{"type": "switch", "id": item["id"], "title": item["title"], "state": item["state"]} for item in items],
            "fingerprint": _fingerprint(sorted(item["id"] for item in items)),
        })

    # third-party reporting, per app
    for actor in snapshot["actors"]:
        if actor.get("kind") == "self":
            continue
        third = {}
        for destination in actor["destinations"]:
            if destination["category"] not in ("telemetry", "advertising") or destination.get("via_websites"):
                continue
            company = destination["company"] or destination["owner"] or destination["name"]
            if same_company(actor.get("publisher"), company):
                continue
            entry = third.setdefault(company, {"company": company, "sent": 0, "hosts": [], "purpose": destination["purpose"],
                                               "addresses": set()})
            entry["sent"] += destination["sent"]
            entry["addresses"] |= set(destination.get("addresses") or [])
            if destination["name"] and destination["name"] not in entry["hosts"]:
                entry["hosts"].append(destination["name"])
        third = {key: value for key, value in third.items() if value["sent"] >= MIN_THIRD_PARTY}
        if not third:
            continue
        total = sum(item["sent"] for item in third.values())
        companies = sorted(third.values(), key=lambda item: -item["sent"])
        names = ", ".join(item["company"] for item in companies[:3])
        purposes = sorted({(item["purpose"] or "").lower() for item in companies if item["purpose"]})
        note, away = _presence_note(actor, now - hours * 3600, now, set().union(*(item["addresses"] for item in companies)))
        for item in companies:
            item["addresses"] = sorted(item["addresses"])
        found.append({
            "id": f"third-party:{actor['id']}", "kind": "third_party", "severity": "high" if total >= 1024 * 1024 else "medium",
            "app": actor["name"], "actor": actor["id"],
            "title": f"{actor['name']} sent {_bytes(total)} to {names}"
                     + (f" ({purposes[0]})" if len(purposes) == 1 else "") + f", not to {actor.get('publisher') or 'its maker'}." + note,
            "evidence": {"companies": companies, "presence": away},
            "actions": [{"type": "open_app", "actor": actor["id"]}],
            "fingerprint": _fingerprint(sorted(third), _size_band(total)),
        })

    # used against active
    built = digest.build(hours, report=report, snapshot=snapshot)
    by_name = {actor["name"]: actor for actor in snapshot["actors"]}
    small = []
    for item in built["idle_but_active"]:
        actor = by_name.get(item["name"]) or {}
        if UPDATER.search(item["name"]) or any(UPDATER.search(p) for p in actor.get("processes", [])):
            continue                                     # updating by itself is what an updater is for
        if item["sent"] + item["received"] < SMALL_UNUSED:
            small.append(item)
            continue
        last = "you have never opened it" if item["never_recorded"] else f"you last opened it {item['days_unused']} days ago"
        note, away = _presence_note(actor, now - hours * 3600, now) if actor else ("", None)
        found.append({
            "id": f"unused:{actor.get('id', item['name'])}", "kind": "unused_active", "severity": "medium" if item["starts_itself"] else "low",
            "app": item["name"], "actor": actor.get("id"),
            "title": f"{item['name']} " + ("starts by itself and " if item["starts_itself"] else "")
                     + f"used the network ({_bytes(item['sent'] + item['received'])}), though {last}." + note,
            "evidence": {"companies": item["companies"], "starts_itself": item["starts_itself"], "days_unused": item["days_unused"],
                         "presence": away},
            "actions": [{"type": "open_app", "actor": actor.get("id")}] if actor else [],
            "fingerprint": _fingerprint(item["starts_itself"], sorted(item["companies"])),
        })

    if small:
        names = [item["name"] for item in small]
        found.append({
            "id": "unused-small", "kind": "unused_active", "severity": "low", "app": "Rarely used apps",
            "title": f"{len(small)} apps you rarely or never open used a little network by themselves: {', '.join(names[:5])}"
                     + (f" and {len(names) - 5} more" if len(names) > 5 else "") + ".",
            "evidence": {"apps": names}, "actions": [], "fingerprint": _fingerprint(sorted(names)),
        })

    found += _new_companies(hours, now, snapshot)

    # attach switches to app cases
    for case in found:
        if case.get("actor"):
            actor = next((a for a in snapshot["actors"] if a["id"] == case["actor"]), None)
            if actor:
                matches = [switches.state(item) for item in switches.for_app(set(actor.get("exes") or []),
                           {service["name"] for service in actor.get("services") or [] if service.get("name")})]
                case["actions"] = _switch_actions(matches) + case["actions"]
        case["actionable"] = any(action["type"] in ("switch", "proof") for action in case["actions"])
    return found


def _new_companies(hours: float, now: float, snapshot: dict) -> list[dict]:
    """Companies an app contacted in the window that it had not contacted before it, when the app
    has at least a day of history before the window (otherwise everything would look new)."""
    from . import activity

    since = now - hours * 3600
    earlier = activity.snapshot(since=since - 7 * 24 * 3600, until=since)
    before = {actor["id"]: {d["company"] for d in actor["destinations"] if d["company"]} for actor in earlier["actors"]}
    first_seen = {actor["id"]: actor["first"] for actor in earlier["actors"]}
    cases = []
    for actor in snapshot["actors"]:
        if actor.get("kind") == "self" or actor["id"] not in before or since - first_seen[actor["id"]] < 24 * 3600:
            continue
        new = sorted({d["company"] for d in actor["destinations"]
                      if d["company"] and d["company"] not in before[actor["id"]] and not d.get("via_websites")
                      and d["company"] != "Your local network"})
        if not new:
            continue
        cases.append({
            "id": f"new-company:{actor['id']}", "kind": "new_company", "severity": "low", "app": actor["name"], "actor": actor["id"],
            "title": f"{actor['name']} contacted {', '.join(new[:3])}" + (f" and {len(new) - 3} more" if len(new) > 3 else "")
                     + " for the first time in the recorded data.",
            "evidence": {"companies": new}, "actions": [{"type": "open_app", "actor": actor["id"]}],
            "fingerprint": _fingerprint(new),
        })
    return cases


def _presence_note(actor: dict, since: float, now: float, addresses: set[str] | None = None) -> tuple[str, dict | None]:
    """" 80% of it went out while nobody was at the keyboard.", when presence covers enough of it."""
    from . import livestore, presence

    ids = actor.get("proc_ids") or []
    if not ids:
        return "", None
    known = presence.minutes(since, now)
    if not known:
        return "", None
    try:
        conn = livestore.connect(readonly=True)
    except (FileNotFoundError, sqlite3.Error):
        return "", None
    try:
        rows = []
        for start in range(0, len(ids), 500):
            chunk = ids[start:start + 500]
            marks = ",".join("?" * len(chunk))
            rows += conn.execute(f"SELECT remote, sent, first, last FROM flows WHERE proc_id IN ({marks}) AND last >= ?",
                                 (*chunk, since)).fetchall()
    finally:
        conn.close()
    rows = [row for row in rows if addresses is None or row[0] in addresses]
    summary = presence.summarise([{"sent": row[1], "first": row[2], "last": row[3]} for row in rows], known)
    if summary["away_share"] is None or summary["coverage"] < 0.5:
        return "", summary
    share = round(summary["away_share"] * 100)
    return f" {share}% of it went out while nobody was at the keyboard.", summary


# --- decisions --------------------------------------------------------------------------------

def decisions(file: Path | None = None) -> dict[str, dict]:
    with _db(file) as conn:
        return {row["id"]: dict(row) for row in conn.execute("SELECT * FROM case_state")}


def decide(case_id: str, state: str, fingerprint: str, note: str | None = None, file: Path | None = None) -> None:
    if state not in STATES:
        raise ValueError(f"unknown state {state!r}")
    with _db(file) as conn:
        conn.execute("INSERT INTO case_state VALUES (?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET state = excluded.state, "
                     "fingerprint = excluded.fingerprint, changed = excluded.changed, note = excluded.note",
                     (case_id, state, fingerprint, time.time(), note))


def listing(hours: float = 24, file: Path | None = None, built: list[dict] | None = None) -> dict:
    """Cases with people's decisions applied, most important first.

    An accepted case stays hidden while its evidence is the same; it opens again when the
    fingerprint changes. A "says against does" case that no longer appears is reported as fixed
    when it had been open.
    """
    from . import dismissed

    cases = built if built is not None else build(hours)
    decided = decisions(file)
    hidden_actors = {item["key"] for item in dismissed.listing() if item["kind"] == "actor"}
    for case in cases:
        decision = decided.get(case["id"])
        case["state"] = "open"
        case["reopened"] = False
        if decision:
            if decision["fingerprint"] == case["fingerprint"]:
                case["state"] = decision["state"]
            elif decision["state"] == "accepted":
                case["reopened"] = True                  # it changed since it was accepted
        if case["state"] == "open" and case.get("actor") in hidden_actors and not decision:
            case["state"] = "accepted"                   # dismissed on the Activity page earlier
    current = {case["id"] for case in cases}
    fixed = [{"id": case_id, **decision} for case_id, decision in decided.items()
             if case_id not in current and case_id.startswith(("off-but-active:", "can-switch-off:")) and decision["state"] != "accepted"]
    cases.sort(key=lambda case: (case["state"] != "open", not case["reopened"], -SEVERITY[case["severity"]],
                                 not case["actionable"], case["app"]))
    return {"cases": cases, "fixed": fixed,
            "counts": {state: sum(1 for case in cases if case["state"] == state) for state in ("open", "accepted", "testing")}}
