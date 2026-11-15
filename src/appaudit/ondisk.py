"""What an app keeps on disk to send: crash-reporter state, queued reports and crash dumps.

Many apps hold their reports locally before sending them. Reading those files shows what the app
collects in a form nobody has to decrypt:

  Sentry (JavaScript/Electron)  scope_v3.json: the user record, device details and the recent-
                                activity log ("breadcrumbs") attached to every error report;
                                session.json; queue/: reports waiting to be sent.
  sentry-native                 .sentry-native: envelopes and session files of native apps.
  Crashpad (Chromium, Electron) crash dumps waiting or uploaded, whether uploads are switched on,
                                and the install's crash-report ID (settings.dat).
  other crash folders           file counts, sizes and dates.

Only reads, in the user's own folders, with limits on file count and size. Values that identify
the person (user records, device and install IDs) are marked so the page can hide them until
asked. Nothing is copied or sent anywhere.
"""

from __future__ import annotations

import json
import os
import re
import struct
import time
import uuid
from pathlib import Path

MAX_FILE = 2_000_000
MAX_FILES = 400
MAX_SECONDS = 4.0
BREADCRUMBS = 60
QUEUED = 30
GENERIC = {"update", "updater", "setup", "launcher", "helper", "app", "service", "host", "container", "python",
           "pythonw", "uv", "svchost", "rundll32", "msedgewebview2", "node", "electron", "crashpad", "handler",
           "microsoft", "windows", "program", "files", "local", "roaming", "programs", "common"}
CRASH_DIRS = {"crash_reports", "crashreports", "crashdata", "crashes", "crashdumps", "minidumps", "dumps"}
CRASHPAD_MAGIC = 0x43506473          # 'CPds'
_VERSIONISH = re.compile(r"^(app-|v)?\d+([._]\d+)*$|^(application|bin|current|x64|x86)$", re.IGNORECASE)
SKIP_DIRS = {"cache", "code cache", "gpucache", "indexeddb", "local storage", "service worker", "blob_storage",
             "node_modules", "extensions", "resources", "locales", "cache_data", "shadercache", "dawncache", "grshadercache"}


def _norm(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (text or "").lower())


def keys_for(exes: list[str], name: str = "", publisher: str = "") -> set[str]:
    """Words that an app's data folder is likely to be named after."""
    found = set()
    bases = [os.path.normcase(os.environ.get(var, "")) for var in ("LOCALAPPDATA", "APPDATA", "ProgramFiles", "ProgramFiles(x86)")]
    for exe in exes:
        path = Path(exe)
        found.add(_norm(path.stem))
        normal = os.path.normcase(str(path.parent))
        for base in bases:
            if base and normal.startswith(base + os.sep):
                rest = [part for part in Path(str(path.parent)[len(base) + 1:]).parts if part.lower() != "programs"]
                if not rest:
                    continue
                # The app's own folder: "Discord" in Discord\app-1.0, "Chrome" in Google\Chrome\Application
                # (a vendor folder like "Google" also holds other apps' data, so it does not count).
                if len(rest) > 1 and not _VERSIONISH.match(rest[1]):
                    found.add(_norm(rest[1]))
                else:
                    found.add(_norm(rest[0]))
    if name:
        found.add(_norm(name))
        found.add(_norm(name.split(" (")[0]))
    return {key for key in found if len(key) >= 4 and key not in GENERIC}


def find_roots(exes: list[str], name: str = "", publisher: str = "") -> list[Path]:
    """The app's own data folders under Roaming and Local application data."""
    keys = keys_for(exes, name, publisher)
    roots = []
    for var in ("APPDATA", "LOCALAPPDATA"):
        base = os.environ.get(var)
        if not base or not os.path.isdir(base):
            continue
        for child in _listdir(Path(base)):
            if not child.is_dir() or child.name.lower() in ("temp", "tmp", "packages", "microsoft"):
                continue
            if _norm(child.name) in keys:
                roots.append(child)
            else:                                    # one level down: Google\Chrome, Microsoft\Edge
                for grandchild in _listdir(child):
                    if grandchild.is_dir() and _norm(grandchild.name) in keys:
                        roots.append(grandchild)
    return roots


def _listdir(path: Path) -> list[Path]:
    try:
        return list(path.iterdir())
    except OSError:
        return []


def _read_json(path: Path):
    try:
        if path.stat().st_size > MAX_FILE:
            return None
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None


def _stamp(path: Path) -> float | None:
    try:
        return path.stat().st_mtime
    except OSError:
        return None


# --- Sentry ---------------------------------------------------------------------------------

def _scalars(section: dict) -> dict:
    return {key: value for key, value in (section or {}).items() if isinstance(value, (str, int, float, bool))}


def _breadcrumb(item: dict) -> dict:
    data = item.get("data") if isinstance(item.get("data"), dict) else {}
    detail = item.get("message") or " ".join(f"{k}={v}" for k, v in list(_scalars(data).items())[:4])
    return {"time": item.get("timestamp"), "category": item.get("category") or item.get("type") or "",
            "level": item.get("level"), "text": str(detail)[:300]}


def parse_envelope(raw: bytes) -> dict:
    """A Sentry envelope: a header line, then pairs of item header and payload."""
    lines = raw.split(b"\n")
    try:
        header = json.loads(lines[0])
    except ValueError:
        return {"error": "not a readable report"}
    items, index = [], 1
    while index < len(lines):
        if not lines[index].strip():
            index += 1
            continue
        try:
            item_header = json.loads(lines[index])
        except ValueError:
            break
        length = item_header.get("length")
        if isinstance(length, int):                 # payload of known length, may contain newlines
            rest = b"\n".join(lines[index + 1:])
            payload, remainder = rest[:length], rest[length + 1:]
            lines = [b""] * (index + 1) + remainder.split(b"\n")
        else:
            payload = lines[index + 1] if index + 1 < len(lines) else b""
        index += 2 if not isinstance(length, int) else 1
        items.append(_summarise_item(item_header, payload))
    return {"sent_at": header.get("sent_at"), "sdk": (header.get("sdk") or {}).get("name"),
            "event_id": header.get("event_id"), "items": items}


def _summarise_item(item_header: dict, payload: bytes) -> dict:
    kind = item_header.get("type", "?")
    summary = {"type": kind, "size": len(payload)}
    try:
        body = json.loads(payload) if payload[:1] in (b"{", b"[") else None
    except ValueError:
        body = None
    if not isinstance(body, dict):
        summary["note"] = "binary" if payload and not payload[:1].isascii() else ""
        return summary
    if kind == "session":
        summary.update(status=body.get("status"), started=body.get("started"), errors=body.get("errors"),
                       release=(body.get("attrs") or {}).get("release"), device_id=body.get("did"))
    elif kind in ("event", "transaction"):
        exception = ((body.get("exception") or {}).get("values") or [{}])[-1]
        summary.update(level=body.get("level"), message=(body.get("message") or {}).get("formatted") if isinstance(body.get("message"), dict)
                       else body.get("message"), error=f"{exception.get('type', '')}: {exception.get('value', '')}".strip(": "),
                       release=body.get("release"), user=body.get("user"), tags=body.get("tags"),
                       breadcrumbs=len((body.get("breadcrumbs") or {}).get("values", []) if isinstance(body.get("breadcrumbs"), dict)
                                       else body.get("breadcrumbs") or []),
                       contexts=sorted((body.get("contexts") or {}).keys()))
    summary["fields"] = sorted(body.keys())[:30]
    summary["raw"] = json.dumps(body, ensure_ascii=False)[:20000]
    return summary


def read_sentry(folder: Path, budget: dict) -> dict:
    result = {"kind": "sentry", "path": str(folder), "title": "Sentry crash and error reporter"}
    scope = _read_json(folder / "scope_v3.json") or _read_json(folder / "scope.json")
    if isinstance(scope, dict):
        sc, ev = scope.get("scope") or {}, scope.get("event") or {}
        result["user"] = sc.get("user") or {}
        result["tags"] = {**(ev.get("tags") or {}), **(sc.get("tags") or {})}
        result["release"] = ev.get("release")
        result["environment"] = ev.get("environment")
        result["device"] = {name: _scalars(section) for name, section in (ev.get("contexts") or {}).items() if isinstance(section, dict)}
        crumbs = sc.get("breadcrumbs") or []
        result["breadcrumbs_total"] = len(crumbs)
        result["breadcrumbs"] = [_breadcrumb(item) for item in crumbs[-BREADCRUMBS:] if isinstance(item, dict)][::-1]
    session = _read_json(folder / "session.json")
    if isinstance(session, dict):
        result["session"] = {"device_id": session.get("did"), "status": session.get("status"), "started": session.get("started"),
                             "errors": session.get("errors"), "user_agent": session.get("userAgent")}
    queue = folder / "queue"
    files = sorted((path for path in _listdir(queue) if path.is_file() and not path.name.endswith(".json")),
                   key=lambda path: _stamp(path) or 0, reverse=True)
    result["queued_total"] = len(files)
    result["queued"] = []
    for path in files[:QUEUED]:
        if not _spend(budget):
            break
        try:
            raw = path.read_bytes()[:MAX_FILE]
        except OSError:
            continue
        result["queued"].append({"file": path.name, "modified": _stamp(path), **parse_envelope(raw)})
    return result


def read_sentry_native(folder: Path, budget: dict) -> dict:
    envelopes = []
    for path in sorted(folder.rglob("*.envelope"), key=lambda p: _stamp(p) or 0, reverse=True)[:QUEUED]:
        if not _spend(budget):
            break
        try:
            envelopes.append({"file": str(path.relative_to(folder)), "modified": _stamp(path), **parse_envelope(path.read_bytes()[:MAX_FILE])})
        except OSError:
            continue
    runs = [path for path in _listdir(folder) if path.name.endswith(".run")]
    return {"kind": "sentry-native", "path": str(folder), "title": "Sentry crash reporter (native)",
            "queued_total": len(envelopes), "queued": envelopes, "runs": len(runs)}


# --- Crashpad -------------------------------------------------------------------------------

def read_crashpad_settings(path: Path) -> dict | None:
    """Crashpad's settings.dat: whether uploads are on, when one was last tried, the install's ID."""
    try:
        data = path.read_bytes()[:64]
    except OSError:
        return None
    if len(data) < 40:
        return None
    magic, version, options, _pad, last_attempt = struct.unpack_from("<IIIIq", data, 0)
    if magic != CRASHPAD_MAGIC:
        return None
    client = uuid.UUID(bytes_le=data[24:40]) if len(data) >= 40 else None
    return {"uploads_enabled": bool(options & 1), "last_upload_attempt": last_attempt or None,
            "client_id": str(client) if client and client.int else None, "version": version}


def read_crashpad(folder: Path, budget: dict) -> dict:
    dumps = []
    for path in folder.rglob("*"):
        if not _spend(budget, cost=0.1):
            break
        if path.is_file() and path.suffix.lower() in (".dmp", ".meta") or (path.is_file() and path.parent.name in ("pending", "completed", "new")):
            if path.suffix.lower() == ".meta":
                continue
            dumps.append({"file": str(path.relative_to(folder)), "state": path.parent.name, "size": path.stat().st_size,
                          "modified": _stamp(path)})
    dumps.sort(key=lambda item: item["modified"] or 0, reverse=True)
    return {"kind": "crashpad", "path": str(folder), "title": "Crashpad crash reports (Chromium)",
            "settings": read_crashpad_settings(folder / "settings.dat"), "dumps_total": len(dumps), "dumps": dumps[:20]}


def read_generic(folder: Path, budget: dict) -> dict:
    files = []
    for path in folder.rglob("*"):
        if not _spend(budget, cost=0.1):
            break
        if path.is_file():
            files.append({"file": str(path.relative_to(folder)), "size": path.stat().st_size, "modified": _stamp(path)})
    files.sort(key=lambda item: item["modified"] or 0, reverse=True)
    return {"kind": "crash-folder", "path": str(folder), "title": "Crash folder",
            "files_total": len(files), "bytes_total": sum(item["size"] for item in files), "files": files[:20]}


# --- one app ----------------------------------------------------------------------------------

def _spend(budget: dict, cost: float = 1.0) -> bool:
    budget["files"] += cost
    return budget["files"] <= MAX_FILES and time.time() < budget["deadline"]


def _sources(root: Path, depth: int = 4):
    """Report folders inside an app's data folder, without walking into browser profiles' caches."""
    stack = [(root, 0)]
    while stack:
        folder, level = stack.pop()
        for child in _listdir(folder):
            if not child.is_dir():
                continue
            lower = child.name.lower()
            if lower == "sentry":
                yield "sentry", child
            elif lower == ".sentry-native":
                yield "sentry-native", child
            elif lower == "crashpad":
                yield "crashpad", child
            elif lower in CRASH_DIRS:
                yield "generic", child
            elif level < depth and lower not in SKIP_DIRS and not _VERSIONISH.match(child.name):
                stack.append((child, level + 1))


READERS = {"sentry": read_sentry, "sentry-native": read_sentry_native, "crashpad": read_crashpad, "generic": read_generic}


def for_app(exes: list[str], name: str = "", publisher: str = "") -> dict:
    budget = {"files": 0.0, "deadline": time.time() + MAX_SECONDS}
    roots = find_roots(exes, name, publisher)
    sources, seen = [], set()
    for root in roots:
        for kind, folder in _sources(root):
            key = os.path.normcase(str(folder))
            if key in seen:
                continue
            seen.add(key)
            try:
                source = READERS[kind](folder, budget)
            except Exception as error:  # noqa: BLE001 - one odd folder must not hide the others
                source = {"kind": kind, "path": str(folder), "title": "Unreadable", "error": f"{type(error).__name__}: {error}"}
            if source.get("kind") == "crash-folder" and not source.get("files_total"):
                continue                                 # an empty crash folder says nothing
            sources.append(source)
    return {"roots": [str(root) for root in roots], "sources": sources,
            "complete": time.time() < budget["deadline"] and budget["files"] <= MAX_FILES}
