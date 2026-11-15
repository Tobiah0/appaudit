"""Stopping one destination: a firewall rule for one program and some addresses, or a name block.

The two mechanisms from STOPPING.md, each with a real and a sandbox backend, a journal and undo.

  address block  one outbound Windows Firewall rule: this program, these remote addresses. The
                 addresses come from the names this PC resolved, read here, never from the caller,
                 and they are refreshed as the name moves.
  name block     a line in a marked section of the hosts file ("0.0.0.0 name"), for third-party
                 trackers. Microsoft names never go there: Defender treats that as tampering.

Every request names a program that already ran and a host this PC already contacted; everything
else is looked up and checked again here (never-block list, shared addresses), because the elevated
helper must not trust the dashboard.

Real changes stay off until Tobiah turns them on by setting REAL_ENABLED in this file. The sandbox
backends are used by the tests and by previews.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import time
import zlib
from contextlib import contextmanager
from pathlib import Path

from . import blocking
from .store import data_dir

REAL_ENABLED = False                       # off until the person decides; see STOPPING.md
GROUP = "App Audit"
RULE_PREFIX = "App Audit stop: "
HOSTS = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"
BEGIN = "# >>> App Audit name blocks (managed by App Audit; edit in the app) >>>"
END = "# <<< App Audit name blocks <<<"
MICROSOFT = re.compile(r"(^|\.)(microsoft|msn|live|office|office365|windows|windowsupdate|bing|skype|xbox|azure|msftncsi|"
                       r"msedge|microsoftonline|sharepoint|onedrive|visualstudio|outlook|hotmail)\.(com|net)$", re.IGNORECASE)
NAME = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")

SCHEMA = """
CREATE TABLE IF NOT EXISTS stops (
    id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, program TEXT, name TEXT NOT NULL,
    addresses TEXT NOT NULL DEFAULT '[]', rule TEXT, backend TEXT NOT NULL, created REAL NOT NULL, removed REAL
);
"""


class Refused(ValueError):
    """The stop would be unsafe or the request is not about something this PC did."""


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


# --- backends -----------------------------------------------------------------------------------

class SandboxBackend:
    name = "sandbox"

    def __init__(self, hosts_text: str = "") -> None:
        self.rules: dict[str, dict] = {}
        self.hosts = hosts_text

    def rule_add(self, rule: str, exe: str, addresses: list[str]) -> None:
        self.rules[rule] = {"exe": exe, "addresses": list(addresses)}

    def rule_update(self, rule: str, addresses: list[str]) -> None:
        self.rules[rule]["addresses"] = list(addresses)

    def rule_remove(self, rule: str) -> None:
        self.rules.pop(rule, None)

    def hosts_read(self) -> str:
        return self.hosts

    def hosts_write(self, text: str) -> None:
        self.hosts = text


class RealBackend:
    """Windows Firewall through its COM interface, and the hosts file. Not used while REAL_ENABLED is off."""

    name = "real"

    def _policy(self):
        import pythoncom
        import win32com.client

        pythoncom.CoInitialize()
        return win32com.client.Dispatch("HNetCfg.FwPolicy2")

    def rule_add(self, rule: str, exe: str, addresses: list[str]) -> None:
        import win32com.client

        item = win32com.client.Dispatch("HNetCfg.FWRule")
        item.Name = rule
        item.Description = "Added by App Audit. Blocks this program's connections to one reporting service only."
        item.ApplicationName = exe
        item.Direction = 2              # outbound
        item.Action = 0                 # block
        item.Grouping = GROUP
        item.Profiles = 0x7FFFFFFF
        item.RemoteAddresses = ",".join(addresses)
        item.Enabled = True
        self._policy().Rules.Add(item)

    def rule_update(self, rule: str, addresses: list[str]) -> None:
        self._policy().Rules.Item(rule).RemoteAddresses = ",".join(addresses)

    def rule_remove(self, rule: str) -> None:
        self._policy().Rules.Remove(rule)

    def hosts_read(self) -> str:
        return HOSTS.read_text(encoding="utf-8", errors="replace")

    def hosts_write(self, text: str) -> None:
        temporary = HOSTS.with_name("hosts.appaudit-new")
        temporary.write_text(text, encoding="utf-8", newline="")
        os.replace(temporary, HOSTS)


def backend_for_real():
    if not REAL_ENABLED:
        raise Refused("Real blocking is switched off in this version. Preview only.")
    return RealBackend()


# --- checks -------------------------------------------------------------------------------------

def _observed(conn_live: sqlite3.Connection, name: str) -> list[str]:
    return [row[0] for row in conn_live.execute("SELECT DISTINCT address FROM names WHERE lower(name) = ?", (name.lower(),))]


def check_address_block(conn_live: sqlite3.Connection, exe: str, name: str) -> dict:
    """The addresses to block, after every safety check; raises Refused with the reason."""
    from .blocks import validate

    path = validate(exe)
    if blocking.never_stop(os.path.basename(path)):
        raise Refused(f"{os.path.basename(path)} is never blocked: {blocking.never_stop(os.path.basename(path))}")
    never = blocking.never_block(name)
    if never:
        raise Refused(f"{name} must keep working: {never['reason']}")
    if not _observed(conn_live, name):
        raise Refused(f"{name} was not seen on this PC")
    shared = blocking.shared(conn_live, name)
    if not shared["clean"]:
        raise Refused(f"{name}'s addresses also serve {', '.join(shared['would_also_block'][:3]) or 'other services'}")
    return {"exe": path, "addresses": shared["addresses"]}


def check_name_block(conn_live: sqlite3.Connection, name: str) -> str:
    name = (name or "").lower().rstrip(".")
    if not NAME.match(name):
        raise Refused("not a host name")
    if MICROSOFT.search(name):
        raise Refused("Microsoft names are not put in the hosts file (Microsoft Defender treats that as tampering); use the switches")
    never = blocking.never_block(name)
    if never:
        raise Refused(f"{name} must keep working: {never['reason']}")
    if not _observed(conn_live, name):
        raise Refused(f"{name} was not seen on this PC")
    from .naming import labels

    if labels.for_name(name)["category"] not in labels.REPORTING:
        raise Refused(f"{name} is not known as a reporting or advertising service")
    return name


# --- the hosts file section ---------------------------------------------------------------------

def hosts_names(text: str) -> list[str]:
    inside, names = False, []
    for line in text.splitlines():
        if line.strip() == BEGIN:
            inside = True
        elif line.strip() == END:
            inside = False
        elif inside and line.strip() and not line.lstrip().startswith("#"):
            parts = line.split()
            if len(parts) >= 2:
                names.append(parts[1].lower())
    return names


def hosts_with(text: str, names: list[str]) -> str:
    """The hosts file with App Audit's section set to `names`; every other line stays as it was."""
    newline = "\r\n" if "\r\n" in text else "\n"
    lines, skipping = [], False
    for line in text.splitlines():
        if line.strip() == BEGIN:
            skipping = True
            continue
        if line.strip() == END:
            skipping = False
            continue
        if not skipping:
            lines.append(line)
    while lines and not lines[-1].strip():
        lines.pop()
    if names:
        lines += ["", BEGIN, *[f"0.0.0.0 {name}" for name in sorted(set(names))], END]
    return newline.join(lines) + newline


# --- add, refresh, remove -----------------------------------------------------------------------

def _rule_name(exe: str, name: str) -> str:
    return f"{RULE_PREFIX}{os.path.basename(exe)} to {name} [{zlib.crc32((exe.lower() + name).encode()) % 100000:05d}]"


def add_address_block(conn_live, exe: str, name: str, backend, file: Path | None = None) -> dict:
    checked = check_address_block(conn_live, exe, name)
    rule = _rule_name(checked["exe"], name)
    with _db(file) as conn:
        existing = conn.execute("SELECT * FROM stops WHERE kind = 'address' AND rule = ? AND removed IS NULL AND backend = ?",
                                (rule, backend.name)).fetchone()
        if existing:
            return {**dict(existing), "already": True}
        backend.rule_add(rule, checked["exe"], checked["addresses"])
        entry = conn.execute("INSERT INTO stops (kind, program, name, addresses, rule, backend, created) VALUES (?,?,?,?,?,?,?)",
                             ("address", checked["exe"], name, json.dumps(checked["addresses"]), rule, backend.name, time.time())).lastrowid
    return {"id": entry, "kind": "address", "rule": rule, "addresses": checked["addresses"], "already": False}


def refresh_addresses(conn_live, backend, file: Path | None = None) -> int:
    """Follow names that moved: add newly resolved addresses to their rules, if they are still clean."""
    changed = 0
    with _db(file) as conn:
        for row in conn.execute("SELECT * FROM stops WHERE kind = 'address' AND removed IS NULL AND backend = ?", (backend.name,)).fetchall():
            shared = blocking.shared(conn_live, row["name"])
            current = sorted(set(json.loads(row["addresses"])) | (set(shared["addresses"]) if shared["clean"] else set()))
            if current != sorted(json.loads(row["addresses"])):
                backend.rule_update(row["rule"], current)
                conn.execute("UPDATE stops SET addresses = ? WHERE id = ?", (json.dumps(current), row["id"]))
                changed += 1
    return changed


def add_name_block(conn_live, name: str, backend, file: Path | None = None) -> dict:
    name = check_name_block(conn_live, name)
    with _db(file) as conn:
        existing = conn.execute("SELECT * FROM stops WHERE kind = 'name' AND name = ? AND removed IS NULL AND backend = ?",
                                (name, backend.name)).fetchone()
        if existing:
            return {**dict(existing), "already": True}
        active = [row["name"] for row in conn.execute("SELECT name FROM stops WHERE kind = 'name' AND removed IS NULL AND backend = ?",
                                                      (backend.name,))]
        backend.hosts_write(hosts_with(backend.hosts_read(), active + [name]))
        entry = conn.execute("INSERT INTO stops (kind, name, backend, created) VALUES ('name', ?, ?, ?)",
                             (name, backend.name, time.time())).lastrowid
    return {"id": entry, "kind": "name", "name": name, "already": False}


def remove(entry_id: int, backend, file: Path | None = None) -> dict:
    with _db(file) as conn:
        row = conn.execute("SELECT * FROM stops WHERE id = ? AND backend = ?", (entry_id, backend.name)).fetchone()
        if row is None:
            raise KeyError(f"no stop {entry_id}")
        if row["removed"] is None:
            if row["kind"] == "address":
                if not str(row["rule"] or "").startswith(RULE_PREFIX):
                    raise Refused("that rule was not made by App Audit")      # the record is user-writable
                backend.rule_remove(row["rule"])
            conn.execute("UPDATE stops SET removed = ? WHERE id = ?", (time.time(), entry_id))
            if row["kind"] == "name":
                active = [r["name"] for r in conn.execute("SELECT name FROM stops WHERE kind = 'name' AND removed IS NULL AND backend = ?",
                                                          (backend.name,))]
                backend.hosts_write(hosts_with(backend.hosts_read(), active))
    return {"id": entry_id, "removed": True}


def listing(backend_name: str = "real", file: Path | None = None) -> list[dict]:
    with _db(file) as conn:
        return [{**dict(row), "addresses": json.loads(row["addresses"])}
                for row in conn.execute("SELECT * FROM stops WHERE backend = ? ORDER BY id DESC", (backend_name,))]
