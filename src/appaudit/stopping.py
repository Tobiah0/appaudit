"""Choose how to stop one app's reporting to one destination without breaking the app (STOPPING.md).

For each reporting destination of an app, the first method that applies wins:

  switch         a catalogue switch covers this sender and destination, and it is still on
  stop_program   the program that sends is almost only a reporter (at least 90% of what it sends
                 goes to reporting destinations), so stopping that program costs nothing
  address_block  the destination's addresses carry nothing else: a firewall rule for this program
                 and these addresses stops only this
  name_block     a third-party tracker (not the app's maker, not Microsoft): blocking the name for
                 the whole PC is what ad blockers do
  nothing_safe   with the reason: on the never-block list, addresses shared with something that must
                 keep working, or reporting that travels with the app's own traffic

Every choice carries its reasons, so the page can say why.
"""

from __future__ import annotations

import sqlite3
from collections import defaultdict

from . import blocking, cases
from .naming import labels

REPORTER_SHARE = 0.9


def _covers(switch, sender: str, host: str | None) -> bool:
    expect = switch.expect or {}
    sender = sender.lower()
    processes = {name.lower() for name in expect.get("processes") or []}
    senders = {name.lower() for name in (expect.get("senders") or {}).get("processes") or []}
    reporting = {name.lower() for name in (expect.get("reporting_from") or {}).get("processes") or []}
    domains = [name.lower() for name in expect.get("domains") or []]
    on_domain = bool(host) and any(host.lower() == d or host.lower().endswith("." + d) for d in domains)
    if sender in processes:
        return True
    if sender in senders and on_domain:
        return True
    return sender in reporting and bool(host) and labels.for_name(host)["category"] in labels.REPORTING


def program_shares(conn: sqlite3.Connection, proc_ids: list[int], names: dict[str, list[str]]) -> dict[str, dict]:
    """Per program name: bytes sent in total and to reporting destinations."""
    shares: dict[str, dict] = defaultdict(lambda: {"sent": 0, "reporting": 0, "exe": None})
    for start in range(0, len(proc_ids), 500):
        chunk = proc_ids[start:start + 500]
        marks = ",".join("?" * len(chunk))
        for name, exe, remote, sent in conn.execute(
                f"SELECT p.name, p.exe, f.remote, f.sent FROM flows f JOIN procs p ON p.id = f.proc_id WHERE f.proc_id IN ({marks})", chunk):
            entry = shares[name]
            entry["sent"] += sent
            entry["exe"] = entry["exe"] or exe
            if any(labels.for_name(host)["category"] in labels.REPORTING for host in names.get(remote, [])):
                entry["reporting"] += sent
    return dict(shares)


def choose(*, sender: str, sender_share: dict | None, destination: dict, publisher: str | None,
           switches: list, switch_states: dict[str, str], shared: dict) -> dict:
    """The method for one (sending program, destination) pair, with the reasons."""
    host = destination.get("name")
    reasons: list[str] = []
    for switch in switches:
        if switch_states.get(switch.id) in ("exposed", "partly") and _covers(switch, sender, host):
            return {"method": "switch", "switch": switch.id, "title": switch.title,
                    "reasons": [f"The setting \"{switch.title}\" covers {sender} sending to {host or 'this destination'}."]}
    never = blocking.never_block(host)
    if never:
        return {"method": "nothing_safe", "reasons": [f"{host} must keep working: {never['reason']}."]}
    protected = blocking.never_stop(sender)
    if protected:
        return {"method": "nothing_safe", "reasons": [f"{sender} is left alone: {protected}."]}
    label = labels.for_name(host) if host else {}
    if label.get("blockable") == "careful" and label.get("breaks"):
        reasons.append(f"Careful: {label['breaks']}")
    if sender_share and sender_share["sent"] and sender_share["reporting"] / sender_share["sent"] >= REPORTER_SHARE:
        share = round(100 * sender_share["reporting"] / sender_share["sent"])
        return {"method": "stop_program", "program": sender, "exe": sender_share.get("exe"),
                "reasons": reasons + [f"{share}% of what {sender} sends goes to reporting services, so it can be stopped without losing anything else."]}
    if shared.get("clean"):
        return {"method": "address_block", "program": sender, "addresses": shared["addresses"],
                "reasons": reasons + [f"{host}'s addresses ({len(shared['addresses'])}) carry nothing else, so a rule for {sender} and these addresses stops only this."]}
    if shared.get("would_break"):
        reasons.append(f"Its addresses are shared with {', '.join(shared['would_break'][:3])}, which must keep working.")
    elif shared.get("would_also_block"):
        reasons.append(f"Its addresses also serve {', '.join(shared['would_also_block'][:3])}.")
    third_party = not cases.same_company(publisher, destination.get("company")) and destination.get("company") not in (None, "Microsoft")
    if host and third_party and labels.for_name(host).get("blockable") in ("yes", None):
        return {"method": "name_block", "name": host,
                "reasons": reasons + [f"{host} belongs to {destination.get('company')}, not to the app's maker; blocking the name stops it for every program."]}
    if not third_party:
        reasons.append(f"It is the app maker's own service ({destination.get('company') or 'unknown'}); blocking it may stop the app working.")
    if not host:
        reasons.append("Its name is not known, so it cannot be blocked by name.")
    return {"method": "nothing_safe", "reasons": reasons or ["No method was found that would not risk breaking something."]}


def plan_for_actor(actor: dict) -> list[dict]:
    """A method for every reporting destination of an app (from activity.snapshot)."""
    from . import livestore, switches as switch_engine

    reporting = [d for d in actor["destinations"] if d["category"] in labels.REPORTING and not d.get("via_websites")]
    if not reporting:
        return []
    candidates = switch_engine.for_app(set(actor.get("exes") or []), {s["name"] for s in actor.get("services") or [] if s.get("name")})
    states = {switch.id: switch_engine.state(switch)["state"] for switch in candidates}
    try:
        conn = livestore.connect(readonly=True)
    except (FileNotFoundError, sqlite3.Error):
        return []
    try:
        names: dict[str, list[str]] = defaultdict(list)
        for address, name in conn.execute("SELECT address, name FROM names"):
            names[address].append(name)
        shares = program_shares(conn, actor.get("proc_ids") or [], names)
        senders_by_host = _senders(conn, actor.get("proc_ids") or [], names)
        plans = []
        for destination in reporting:
            host = destination.get("name")
            shared = blocking.shared(conn, host) if host else {"clean": False}
            for sender in senders_by_host.get(host, [actor.get("process") or ""])[:3]:
                plans.append({"destination": host or destination["address"], "company": destination.get("company"),
                              "sent": destination["sent"], "sender": sender,
                              **choose(sender=sender, sender_share=shares.get(sender), destination=destination,
                                       publisher=actor.get("publisher"), switches=candidates, switch_states=states, shared=shared)})
        return plans
    finally:
        conn.close()


def _senders(conn: sqlite3.Connection, proc_ids: list[int], names: dict[str, list[str]]) -> dict[str, list[str]]:
    """Which programs sent to each host name, the biggest sender first."""
    totals: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for start in range(0, len(proc_ids), 500):
        chunk = proc_ids[start:start + 500]
        marks = ",".join("?" * len(chunk))
        for name, remote, sent in conn.execute(
                f"SELECT p.name, f.remote, f.sent FROM flows f JOIN procs p ON p.id = f.proc_id WHERE f.proc_id IN ({marks})", chunk):
            for host in names.get(remote, []):
                totals[host][name] += sent
    return {host: sorted(by, key=lambda n: -by[n]) for host, by in totals.items()}
