"""The switch catalogue and the engine that reads, applies and undoes switches.

A switch is a named privacy setting made of one or more checks. Each check knows the value that
means "private". Applying a switch writes that value for every check that is not already private
and records the previous value, so undo restores exactly what was there.

Only changes described in the catalogue can be applied: the engine never takes a registry path
or a command from the caller.

Check types: registry, service, task, env, and file (one setting in an app's own JSON or INI
file, edited in place; the whole file is backed up first). A switch without checks carries
`steps` instead: instructions for a setting only the app itself or the vendor's website can change.

Switches come from the hand-written catalogue and from imported opt-out databases
(see `toptout.py`); imported entries never replace a hand-written one.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import os
import shutil
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import yaml

from ..store import data_dir
from . import configfile
from .backends import RealBackend

CATALOGUE = Path(__file__).resolve().parent.parent / "catalogue"
ADMIN_TYPES = {"service", "task"}
# File checks may only touch the signed-in user's own files; they never need administrator rights.
USER_FOLDERS = ("%APPDATA%", "%LOCALAPPDATA%", "%USERPROFILE%")
DIFF_LINES = 60


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
    steps: list[dict] = field(default_factory=list)   # manual instructions: {name, description, link}
    origin: str = "catalogue"                          # catalogue | toptout

    @property
    def needs_admin(self) -> bool:
        return any(check["type"] in ADMIN_TYPES or check.get("hive") == "HKLM" for check in self.checks)

    def public(self) -> dict:
        return {"id": self.id, "title": self.title, "group": self.group, "explain": self.explain,
                "breaks": self.breaks, "risk": self.risk, "source": self.source, "note": self.note,
                "needs_admin": self.needs_admin, "expect": self.expect, "steps": self.steps,
                "origin": self.origin}


def build_switch(merged: dict, group: str, origin: str = "catalogue") -> Switch:
    """A validated Switch from one catalogue entry (defaults already merged in)."""
    switch = Switch(
        id=merged["id"], title=merged["title"], group=merged.get("group", group),
        explain=merged.get("explain", "").strip(), checks=merged.get("checks") or [],
        breaks=merged.get("breaks", "").strip(), risk=merged.get("risk", "low"),
        source=merged.get("source", ""), detect=merged.get("detect"), expect=merged.get("expect", {}),
        note=merged.get("note", "").strip(), steps=merged.get("steps") or [], origin=origin)
    if not switch.checks and not switch.steps:
        raise ValueError(f"{switch.id}: a switch needs checks or steps")
    for check in switch.checks:
        _validate(check, switch.id)
    for step in switch.steps:
        if not step.get("name") or not step.get("description"):
            raise ValueError(f"{switch.id}: every step needs a name and a description")
    if switch.expect:
        from ..proof import validate_expect

        validate_expect(switch.expect, switch.id)
    return switch


def check_identity(check: dict) -> tuple:
    """What a check changes, so two sources describing the same setting are recognised."""
    kind = check["type"]
    if kind == "registry":     # the same policy for the user (HKCU) or the machine (HKLM) is one setting
        return (kind, check["key"].lower().strip("\\"), check["value"].lower())
    if kind == "file":
        return (kind, check["path"].lower(), json.dumps(check.get("keys") or [check.get("section"), check.get("key")]).lower())
    return (kind, str(check.get("name") or check.get("path")).lower())


@lru_cache(maxsize=1)
def load_catalogue() -> dict[str, Switch]:
    switches: dict[str, Switch] = {}
    for path in sorted(CATALOGUE.glob("*.yaml")):
        document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        group = document.get("group", path.stem)
        defaults = document.get("defaults", {})
        for entry in document.get("switches", []):
            switch = build_switch({**defaults, **entry}, group)
            if switch.id in switches:
                raise ValueError(f"duplicate switch id {switch.id} in {path.name}")
            switches[switch.id] = switch
    covered = {check_identity(check) for switch in switches.values() for check in switch.checks}
    from . import toptout

    for switch in toptout.load(covered):
        switches.setdefault(switch.id, switch)
    from . import startup

    for switch in startup.load():
        switches.setdefault(switch.id, switch)
    return switches


def _detect_programs(detect: dict | None) -> set[str]:
    if not detect:
        return set()
    found: set[str] = set()
    for item in detect.get("any") or []:
        found |= _detect_programs(item)
    for key in ("process", "path"):
        values = detect.get(key) or []
        for value in values if isinstance(values, list) else [values]:
            name = str(value).replace("/", "\\").rsplit("\\", 1)[-1].lower()
            if name.endswith(".exe"):
                found.add(name)
    # A command is identified by the file it runs, not its name: the Claude desktop app and the
    # Claude Code command are both claude.exe.
    commands = detect.get("command") or []
    for command in commands if isinstance(commands, list) else [commands]:
        resolved = shutil.which(str(command))
        if resolved:
            found.add("path:" + os.path.normcase(os.path.realpath(resolved)))
    return found


def programs_of(switch: Switch, shared_hosts: set[str] = frozenset()) -> set[str]:
    """The programs a switch is about, from everything the catalogue says: how it is detected,
    the programs a file check belongs to, and what the proof engine watches. Names are lower case;
    "path:..." entries are exact program files."""
    found = _detect_programs(switch.detect)
    for check in switch.checks:
        found |= {name.lower() for name in check.get("apps") or []}
    expect = switch.expect or {}
    found |= {name.lower() for name in expect.get("processes") or []}
    found |= {name.lower() for name in (expect.get("senders") or {}).get("processes") or []} - shared_hosts
    found |= {name.lower() for name in (expect.get("reporting_from") or {}).get("processes") or []}
    return found


def _shared_hosts() -> set[str]:
    """Programs named as a sender by several switches (the WebView2 runtime hosts both the
    Widgets board and Copilot): they do not tie an app to any one switch."""
    counts: dict[str, int] = {}
    for switch in load_catalogue().values():
        for name in (switch.expect.get("senders") or {}).get("processes") or []:
            counts[name.lower()] = counts.get(name.lower(), 0) + 1
    return {name for name, count in counts.items() if count > 1}


def for_app(programs: set[str], services: set[str] = frozenset()) -> list[Switch]:
    """Catalogue switches that concern an app, given its program files (full paths or names)
    and the services it hosts."""
    names = {program.replace("/", "\\").rsplit("\\", 1)[-1].lower() for program in programs}
    paths = {"path:" + os.path.normcase(os.path.realpath(program)) for program in programs if "\\" in program or "/" in program}
    programs = names | paths
    services = {name.lower() for name in services}
    shared = _shared_hosts()
    matched = []
    for switch in load_catalogue().values():
        expect = switch.expect or {}
        own_services = {name.lower() for name in expect.get("services") or []} \
            | {name.lower() for name in (expect.get("senders") or {}).get("services") or []} \
            | {check["name"].lower() for check in switch.checks if check["type"] == "service"}
        if programs_of(switch, shared) & programs or own_services & services:
            matched.append(switch)
    return matched


def _validate(check: dict, switch_id: str) -> None:
    kind = check.get("type")
    required = {"registry": ("hive", "key", "value", "private"), "service": ("name", "private"),
                "task": ("path", "private"), "env": ("name", "private"),
                "file": ("path", "format", "private"),
                "startup_approved": ("hive", "approved", "value", "private")}.get(kind)
    if required is None:
        raise ValueError(f"{switch_id}: unknown check type {kind!r}")
    missing = [name for name in required if name not in check]
    if missing:
        raise ValueError(f"{switch_id}: {kind} check is missing {missing}")
    if kind == "startup_approved" and (check["hive"] not in ("HKCU", "HKLM") or check["approved"] not in ("Run", "Run32", "StartupFolder")):
        raise ValueError(f"{switch_id}: startup_approved needs hive HKCU/HKLM and approved Run, Run32 or StartupFolder")
    if kind == "registry" and check["hive"] not in ("HKCU", "HKLM"):
        raise ValueError(f"{switch_id}: hive must be HKCU or HKLM")
    if kind == "file":
        if not check["path"].upper().startswith(USER_FOLDERS):
            raise ValueError(f"{switch_id}: a file check must be in the user's own folders {USER_FOLDERS}")
        if ".." in check["path"].replace("\\", "/").split("/"):
            raise ValueError(f"{switch_id}: a file path may not contain '..'")
        if check["format"] == "json":
            if not isinstance(check.get("keys"), list) or not check["keys"]:
                raise ValueError(f"{switch_id}: a JSON file check needs a list of keys")
        elif check["format"] == "ini":
            if not check.get("key"):
                raise ValueError(f"{switch_id}: an INI file check needs a key")
        else:
            raise ValueError(f"{switch_id}: file format must be json or ini")


# --- reading -----------------------------------------------------------------------------

def read_check(check: dict, backend) -> object:
    kind = check["type"]
    if kind == "registry":
        return backend.registry_get(check["hive"], check["key"], check["value"])
    if kind == "service":
        return backend.service_get(check["name"])
    if kind == "task":
        return backend.task_get(check["path"])
    if kind == "file":
        return configfile.read(backend.file_read(backend.expand(check["path"])), check)
    if kind == "startup_approved":
        return backend.startup_get(check["hive"], check["approved"], check["value"])
    return backend.env_get(check["name"])


def check_state(check: dict, current) -> str:
    """private | exposed | absent. `absent` means the thing does not exist on this PC."""
    if current is None:
        if check["type"] in ("service", "task"):
            return "absent"
        if "default" not in check:
            return "exposed"                         # value not set, and the Windows default is "on"
        current = check["default"]
    if check["type"] == "startup_approved":          # Task Manager's flag: an odd first byte means disabled
        return "private" if current and int(str(current)[:2], 16) % 2 == 1 else "exposed"
    if check.get("private_any"):                     # any non-empty value turns it off
        return "private" if str(current).strip() else "exposed"
    private = check["private"]
    accepted = private if isinstance(private, list) else [private]
    return "private" if any(_same(current, item) for item in accepted) else "exposed"


def _same(left, right) -> bool:
    if isinstance(left, str) or isinstance(right, str):
        return str(left).strip().lower() == str(right).strip().lower()
    return left == right


def present(switch: Switch, backend) -> bool:
    return _detected(switch.detect, backend)


def _detected(detect: dict | None, backend) -> bool:
    if not detect:
        return True
    if "any" in detect:
        return any(_detected(item, backend) for item in detect["any"])
    if "process" in detect:
        names = detect["process"] if isinstance(detect["process"], list) else [detect["process"]]
        return bool({name.lower() for name in names} & backend.known_processes())
    if "glob" in detect:
        return backend.glob_exists(detect["glob"])
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
    if not switch.checks:
        return {**switch.public(), "state": "manual", "checks": []}
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
    if kind == "startup_approved":
        return f"Startup entry \"{check['value']}\" ({check['hive']} {check['approved']}) = disabled, as Task Manager does it"
    if kind == "file":
        where = " > ".join(check["keys"]) if check["format"] == "json" else \
            (f"[{check['section']}] " if check.get("section") else "") + check["key"]
        return f"{check['path']} : {where} = {json.dumps(_first(check['private']))}"
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
    elif kind == "startup_approved":
        backend.startup_set(check["hive"], check["approved"], check["value"], value)
    elif kind == "file":
        path = backend.expand(check["path"])
        backend.file_write(path, configfile.edit(backend.file_read(path), check, value))
    else:
        backend.env_set(check["name"], value)


def _sha(text: str | None) -> str | None:
    return None if text is None else hashlib.sha256(text.encode("utf-8")).hexdigest()


def _diff(path: str, before: str, after: str) -> str:
    """The change as a unified diff, the form a person can check line by line."""
    lines = list(difflib.unified_diff(before.splitlines(keepends=True), after.splitlines(keepends=True),
                                      fromfile=path, tofile=path, n=2))
    text = "".join(line if line.endswith("\n") else line + "\n" for line in lines[:DIFF_LINES])
    return text + (f"… {len(lines) - DIFF_LINES} more lines\n" if len(lines) > DIFF_LINES else "")


def plan(switch: Switch, backend=None) -> list[dict]:
    """The exact changes apply() would make right now.

    File changes carry the file path, a diff of the file before and after, and the app's
    programs that are running now (a running app may write its old settings back on exit).
    """
    backend = backend or RealBackend()
    changes = []
    pending: dict[str, str] = {}                     # several checks in one file: diff them together
    for index, check in enumerate(switch.checks):
        current = read_check(check, backend)
        status = check_state(check, current)
        if status != "exposed":
            continue
        change = {"check": index, "what": describe_check(check), "before": current,
                  "after": _first(check["private"]), "admin": check["type"] in ADMIN_TYPES
                  or check.get("hive") == "HKLM", "check_def": check}
        if check["type"] == "file":
            path = backend.expand(check["path"])
            original = backend.file_read(path)
            start = pending.get(path, original or "")
            pending[path] = configfile.edit(start, check, change["after"])
            change.update(file=path, exists=original is not None, diff=_diff(path, original or "", pending[path]),
                          running=sorted(backend.running(check.get("apps") or [])), check_def=check)
        changes.append(change)
    return changes


def apply(switch: Switch, backend=None, journal_file: Path | None = None, only_admin: bool | None = None) -> dict:
    """Apply the switch. `only_admin` limits the run to the admin half (True) or the user half (False).

    Before a file is changed for the first time in this run, the whole file is copied to the
    backup folder; the journal records where, and a fingerprint of the file as written.
    """
    backend = backend or RealBackend()
    done, failed = [], []
    backups: dict[str, str | None] = {}
    for change in plan(switch, backend):
        if only_admin is not None and change["admin"] != only_admin:
            continue
        check = switch.checks[change["check"]]
        try:
            if check["type"] == "file":
                path = change["file"]
                if path not in backups:
                    backups[path] = backend.file_backup(path)
                write_check(check, change["after"], backend)
                change = {**change, "backup": backups[path], "after_sha": _sha(backend.file_read(path))}
                change.pop("diff", None)
            else:
                write_check(check, change["after"], backend)
            done.append(change)
        except Exception as error:  # noqa: BLE001 - report and continue with the other checks
            failed.append({**change, "error": f"{type(error).__name__}: {error}"})
    # A later write to the same file changes its fingerprint; record the final one on every change.
    for change in done:
        if "file" in change:
            change["after_sha"] = _sha(backend.file_read(change["file"]))
    entry_id = None
    if done:
        record = (switch.id, time.time(), backend.name, json.dumps(done, default=str))
        if only_admin and journal_file is None:
            # Administrator changes: the authoritative record is the helper's protected copy; the
            # user's journal gets a copy with the same id, for display only.
            from .. import protected

            with _journal(protected.journal_file()) as conn:
                entry_id = conn.execute("INSERT INTO switch_journal (switch_id, applied, backend, changes) VALUES (?,?,?,?)",
                                        record).lastrowid
            with _journal(None) as conn:
                conn.execute("INSERT OR REPLACE INTO switch_journal (id, switch_id, applied, backend, changes) VALUES (?,?,?,?,?)",
                             (entry_id, *record))
        else:
            with _journal(journal_file) as conn:
                entry_id = conn.execute("INSERT INTO switch_journal (switch_id, applied, backend, changes) VALUES (?,?,?,?)",
                                        record).lastrowid
    return {"switch": switch.id, "changed": done, "failed": failed, "journal_id": entry_id}


def undo(entry_id: int, backend=None, journal_file: Path | None = None, only_admin: bool | None = None) -> dict:
    """Restore the values recorded in one journal entry.

    A file that has not changed since the switch wrote it is restored from its backup, byte for
    byte. If the app or the person changed it since, only the one setting is put back, so their
    other changes survive.
    """
    backend = backend or RealBackend()
    source = journal_file
    if only_admin and journal_file is None:
        from .. import protected

        source = protected.journal_file()           # never the user-writable copy for administrator changes
    with _journal(source) as conn:
        row = conn.execute("SELECT * FROM switch_journal WHERE id = ?", (entry_id,)).fetchone()
    if row is None:
        raise KeyError(f"no journal entry {entry_id}" + (" in the protected record" if source is not journal_file else ""))
    changes = json.loads(row["changes"])
    switch = load_catalogue().get(row["switch_id"])
    # A switch generated from the inventory can leave the catalogue; its user-level changes are undone
    # from the journal's copy of the check. Administrator changes always come from the catalogue: the
    # journal sits in a file the user's programs can write.
    if switch is None and not all(change.get("check_def") and not change["admin"] for change in changes):
        raise KeyError(f"switch {row['switch_id']} is no longer in the catalogue")
    restored, failed = [], []
    files_restored: set[str] = set()
    for change in changes:
        if only_admin is not None and change["admin"] != only_admin:
            continue
        check = switch.checks[change["check"]] if switch is not None else change["check_def"]
        try:
            path = change.get("file")
            if path and path in files_restored:
                restored.append(change)
                continue
            if path and change.get("backup") is not None and _sha(backend.file_read(path)) == change.get("after_sha"):
                backend.file_restore(path, change["backup"])
                files_restored.add(path)
            elif path and change.get("backup") is None and not change.get("exists", True) \
                    and _sha(backend.file_read(path)) == change.get("after_sha"):
                backend.file_remove(path)                    # the switch created the file; remove it again
                files_restored.add(path)
            else:
                write_check(check, change["before"], backend)
            restored.append(change)
        except Exception as error:  # noqa: BLE001
            failed.append({**change, "error": f"{type(error).__name__}: {error}"})
    if not failed:
        for target in {source, journal_file} if source is not journal_file else {journal_file}:
            with _journal(target) as conn:
                conn.execute("UPDATE switch_journal SET undone = ? WHERE id = ?", (time.time(), entry_id))
    return {"switch": row["switch_id"], "restored": restored, "failed": failed}
