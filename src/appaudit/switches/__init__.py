"""The switch catalogue and the engine that reads, applies and undoes switches.

A switch is a named privacy setting made of one or more checks. Each check knows the value that
means "private". Applying a switch writes that value for every check that is not already private
and records the previous value, so undo restores exactly what was there.

Only changes described in the catalogue can be applied: the engine never takes a registry path
or a command from the caller.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import yaml

from ..store import data_dir
from .backends import RealBackend

CATALOGUE = Path(__file__).resolve().parent.parent / "catalogue"
ADMIN_TYPES = {"service", "task"}


@dataclass
class Switch:
    id: str
    title: str
    group: str
    explain: str
    checks: list[dict]
    breaks: str = ""
    risk: str = "low"                  # low | medium | high
    source: str = ""
    detect: dict | None = None         # when present, the switch only applies if this is found
    expect: dict = field(default_factory=dict)   # what should go quiet; used by the proof engine
    note: str = ""

    @property
    def needs_admin(self) -> bool:
        return any(check["type"] in ADMIN_TYPES or check.get("hive") == "HKLM" for check in self.checks)

    def public(self) -> dict:
        return {"id": self.id, "title": self.title, "group": self.group, "explain": self.explain,
                "breaks": self.breaks, "risk": self.risk, "source": self.source, "note": self.note,
                "needs_admin": self.needs_admin, "expect": self.expect}


@lru_cache(maxsize=1)
def load_catalogue() -> dict[str, Switch]:
    switches: dict[str, Switch] = {}
    for path in sorted(CATALOGUE.glob("*.yaml")):
        document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        group = document.get("group", path.stem)
        defaults = document.get("defaults", {})
        for entry in document.get("switches", []):
            merged = {**defaults, **entry}
            switch = Switch(
                id=merged["id"], title=merged["title"], group=merged.get("group", group),
                explain=merged.get("explain", "").strip(), checks=merged["checks"],
                breaks=merged.get("breaks", "").strip(), risk=merged.get("risk", "low"),
                source=merged.get("source", ""), detect=merged.get("detect"), expect=merged.get("expect", {}),
                note=merged.get("note", "").strip())
            if switch.id in switches:
                raise ValueError(f"duplicate switch id {switch.id} in {path.name}")
            for check in switch.checks:
                _validate(check, switch.id)
            if switch.expect:
                from ..proof import validate_expect

                validate_expect(switch.expect, switch.id)
            switches[switch.id] = switch
    return switches


def _validate(check: dict, switch_id: str) -> None:
    kind = check.get("type")
    required = {"registry": ("hive", "key", "value", "private"), "service": ("name", "private"),
                "task": ("path", "private"), "env": ("name", "private")}.get(kind)
    if required is None:
        raise ValueError(f"{switch_id}: unknown check type {kind!r}")
    missing = [name for name in required if name not in check]
    if missing:
        raise ValueError(f"{switch_id}: {kind} check is missing {missing}")
    if kind == "registry" and check["hive"] not in ("HKCU", "HKLM"):
        raise ValueError(f"{switch_id}: hive must be HKCU or HKLM")


# --- reading -----------------------------------------------------------------------------

def read_check(check: dict, backend) -> object:
    kind = check["type"]
    if kind == "registry":
        return backend.registry_get(check["hive"], check["key"], check["value"])
    if kind == "service":
        return backend.service_get(check["name"])
    if kind == "task":
        return backend.task_get(check["path"])
    return backend.env_get(check["name"])


def check_state(check: dict, current) -> str:
    """private | exposed | absent. `absent` means the thing does not exist on this PC."""
    if current is None:
        if check["type"] in ("service", "task"):
            return "absent"
        if "default" not in check:
            return "exposed"                         # value not set, and the Windows default is "on"
        current = check["default"]
    private = check["private"]
    accepted = private if isinstance(private, list) else [private]
    return "private" if any(_same(current, item) for item in accepted) else "exposed"


def _same(left, right) -> bool:
    if isinstance(left, str) or isinstance(right, str):
        return str(left).strip().lower() == str(right).strip().lower()
    return left == right


def present(switch: Switch, backend) -> bool:
    detect = switch.detect
    if not detect:
        return True
    if "command" in detect:
        commands = detect["command"] if isinstance(detect["command"], list) else [detect["command"]]
        return any(shutil.which(item) for item in commands)
    if "path" in detect:
        paths = detect["path"] if isinstance(detect["path"], list) else [detect["path"]]
        return any(backend.path_exists(item) for item in paths)
    if "registry_key" in detect:
        hive, _, key = detect["registry_key"].partition("\\")
        return backend.registry_key_exists(hive, key)
    if "service" in detect:
        return backend.service_get(detect["service"]) is not None
    if "task" in detect:
        return backend.task_get(detect["task"]) is not None
    return True


def state(switch: Switch, backend=None) -> dict:
    backend = backend or RealBackend()
    if not present(switch, backend):
        return {**switch.public(), "state": "not_installed", "checks": []}
    details = []
    for check in switch.checks:
        try:
            current = read_check(check, backend)
            status = check_state(check, current)
        except PermissionError:
            current, status = None, "unreadable"
        except Exception as error:  # noqa: BLE001 - one unreadable check must not hide the others
            current, status = f"{type(error).__name__}", "unreadable"
        details.append({"what": describe_check(check), "current": current, "state": status})
    states = {item["state"] for item in details}
    if states <= {"absent"}:
        overall = "not_installed"
    elif "exposed" in states:
        overall = "exposed" if "private" not in states else "partly"
    elif "unreadable" in states and "private" not in states:
        overall = "unknown"
    else:
        overall = "private"
    return {**switch.public(), "state": overall, "checks": details}


def describe_check(check: dict) -> str:
    kind = check["type"]
    if kind == "registry":
        return f"{check['hive']}\\{check['key']} : {check['value']} = {_first(check['private'])}"
    if kind == "service":
        return f"Service {check['name']} start type = {_first(check['private'])}"
    if kind == "task":
        return f"Scheduled task {check['path']} = {_first(check['private'])}"
    return f"Environment variable {check['name']} = {_first(check['private'])}"


def _first(value):
    return value[0] if isinstance(value, list) else value


# --- journal -------------------------------------------------------------------------------

JOURNAL_SCHEMA = """
CREATE TABLE IF NOT EXISTS switch_journal (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    switch_id TEXT NOT NULL,
    applied REAL NOT NULL,
    backend TEXT NOT NULL,
    changes TEXT NOT NULL,
    undone REAL
);
"""


@contextmanager
def _journal(file: Path | None = None):
    conn = sqlite3.connect(file or (data_dir() / "appaudit.db"), timeout=10)
    try:
        conn.executescript(JOURNAL_SCHEMA)
        conn.row_factory = sqlite3.Row
        yield conn
        conn.commit()
    finally:
        conn.close()


def journal_entries(file: Path | None = None, backend_name: str = "real") -> list[dict]:
    with _journal(file) as conn:
        rows = conn.execute("SELECT * FROM switch_journal WHERE backend = ? ORDER BY id DESC", (backend_name,)).fetchall()
    return [{**dict(row), "changes": json.loads(row["changes"])} for row in rows]


# --- applying ------------------------------------------------------------------------------

def write_check(check: dict, value, backend) -> None:
    kind = check["type"]
    if kind == "registry":
        backend.registry_set(check["hive"], check["key"], check["value"], value, check.get("kind", "dword"))
    elif kind == "service":
        backend.service_set(check["name"], value)
    elif kind == "task":
        backend.task_set(check["path"], value)
    else:
        backend.env_set(check["name"], value)


def plan(switch: Switch, backend=None) -> list[dict]:
    """The exact changes apply() would make right now."""
    backend = backend or RealBackend()
    changes = []
    for index, check in enumerate(switch.checks):
        current = read_check(check, backend)
        status = check_state(check, current)
        if status == "exposed":
            changes.append({"check": index, "what": describe_check(check), "before": current,
                            "after": _first(check["private"]), "admin": check["type"] in ADMIN_TYPES
                            or check.get("hive") == "HKLM"})
    return changes


def apply(switch: Switch, backend=None, journal_file: Path | None = None, only_admin: bool | None = None) -> dict:
    """Apply the switch. `only_admin` limits the run to the admin half (True) or the user half (False)."""
    backend = backend or RealBackend()
    done, failed = [], []
    for change in plan(switch, backend):
        if only_admin is not None and change["admin"] != only_admin:
            continue
        check = switch.checks[change["check"]]
        try:
            write_check(check, change["after"], backend)
            done.append(change)
        except Exception as error:  # noqa: BLE001 - report and continue with the other checks
            failed.append({**change, "error": f"{type(error).__name__}: {error}"})
    entry_id = None
    if done:
        with _journal(journal_file) as conn:
            entry_id = conn.execute(
                "INSERT INTO switch_journal (switch_id, applied, backend, changes) VALUES (?,?,?,?)",
                (switch.id, time.time(), backend.name, json.dumps(done))).lastrowid
    return {"switch": switch.id, "changed": done, "failed": failed, "journal_id": entry_id}


def undo(entry_id: int, backend=None, journal_file: Path | None = None, only_admin: bool | None = None) -> dict:
    """Restore the values recorded in one journal entry."""
    backend = backend or RealBackend()
    with _journal(journal_file) as conn:
        row = conn.execute("SELECT * FROM switch_journal WHERE id = ?", (entry_id,)).fetchone()
    if row is None:
        raise KeyError(f"no journal entry {entry_id}")
    switch = load_catalogue().get(row["switch_id"])
    if switch is None:
        raise KeyError(f"switch {row['switch_id']} is no longer in the catalogue")
    restored, failed = [], []
    for change in json.loads(row["changes"]):
        if only_admin is not None and change["admin"] != only_admin:
            continue
        check = switch.checks[change["check"]]
        try:
            write_check(check, change["before"], backend)
            restored.append(change)
        except Exception as error:  # noqa: BLE001
            failed.append({**change, "error": f"{type(error).__name__}: {error}"})
    if not failed:
        with _journal(journal_file) as conn:
            conn.execute("UPDATE switch_journal SET undone = ? WHERE id = ?", (time.time(), entry_id))
    return {"switch": switch.id, "restored": restored, "failed": failed}
