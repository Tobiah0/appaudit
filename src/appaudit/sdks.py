"""Find reporting components built into an app by reading the app's own files.

This only reads files, in the unprivileged dashboard process. A hit shows what the app is built
to do; it does not show that the component is switched on or what it sent.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
import time
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path

import yaml

from .store import data_dir

KNOWLEDGE = Path(__file__).resolve().parent / "knowledge"
EXTENSIONS = {".exe", ".dll", ".asar", ".js", ".mjs", ".cjs", ".node", ".json", ".pak", ".bin", ".config", ".xml",
              ".jar", ".pyd", ".dat", ".html"}
SKIP_FOLDERS = {"steamapps", "userdata", "cache", "code cache", "gpucache", "logs", "locales", "crashpad",
                "dictionaries", "appcache", "depotcache", "htmlcache", "service worker", "indexeddb", "local storage"}
MAX_FILES = 8000
MAX_BYTES = 1_000_000_000
MAX_FILE = 400_000_000
MAX_SECONDS = 60
TRACKER_LIST_AT = 5
CODE_EXTENSIONS = {".exe", ".dll", ".asar", ".js", ".mjs", ".cjs", ".node", ".jar", ".pyd"}
CHUNK = 4 * 1024 * 1024
OVERLAP = 256

SCHEMA = """
CREATE TABLE IF NOT EXISTS sdk_scans (
    root TEXT PRIMARY KEY, scanned REAL NOT NULL, files INTEGER NOT NULL, bytes INTEGER NOT NULL,
    complete INTEGER NOT NULL, found TEXT NOT NULL) WITHOUT ROWID;
"""


@lru_cache(maxsize=1)
def catalogue() -> dict[str, dict]:
    entries = yaml.safe_load((KNOWLEDGE / "sdks.yaml").read_text(encoding="utf-8"))
    return {entry["id"]: entry for entry in entries}


@lru_cache(maxsize=1)
def _matcher() -> tuple[list[tuple[bytes, str]], dict[str, str]]:
    """Search strings (lower case) with the component each one identifies, plus a file-name table.

    Files are lower-cased and stripped of zero bytes before searching, which makes one plain search
    cover both ordinary and 16-bit text. A plain search per string is about 60 times faster here
    than one case-insensitive pattern.
    """
    needles: list[tuple[bytes, str]] = []
    names: dict[str, str] = {}
    for sdk in catalogue().values():
        for text in sdk.get("strings") or []:
            needles.append((text.lower().encode("ascii"), sdk["id"]))
        for name in sdk.get("files") or []:
            names[name.lower()] = sdk["id"]
    return needles, names


def _forbidden_roots() -> set[str]:
    home = Path.home()
    items = [os.environ.get("WINDIR", r"C:\Windows"), os.environ.get("ProgramFiles", ""), os.environ.get("ProgramFiles(x86)", ""),
             os.environ.get("ProgramData", ""), os.environ.get("LOCALAPPDATA", ""), os.environ.get("APPDATA", ""),
             os.environ.get("TEMP", ""), str(home), str(home / "Desktop"), str(home / "Downloads"),
             str(home / "Documents")]
    return {os.path.normcase(os.path.normpath(item)) for item in items if item}


_VERSION_FOLDER = re.compile(r"^(app-)?\d+(\.\d+)+$", re.IGNORECASE)


def _newness(folder: str) -> tuple:
    """Sort key for sibling version folders: a real install beats a leftover stub, then the higher version.

    The modified date is no guide: an updater can leave a nearly empty folder that is the most
    recently touched one.
    """
    try:
        filled = len(os.listdir(folder)) >= 5
    except OSError:
        filled = False
    return filled, tuple(int(part) for part in re.findall(r"\d+", os.path.basename(folder)))


def roots_for(exes: list[str]) -> list[str]:
    """The folders worth reading for an app: where its programs live, never a shared or system folder."""
    forbidden = _forbidden_roots()
    windows = os.path.normcase(os.path.normpath(os.environ.get("WINDIR", r"C:\Windows")))
    found: list[str] = []
    for exe in exes:
        folder = os.path.normpath(os.path.dirname(exe))
        key = os.path.normcase(folder)
        if not folder or len(Path(folder).parts) < 3 or key in forbidden or key.startswith(windows + os.sep):
            continue
        if not os.path.isdir(folder):
            continue
        found.append(folder)
    # Apps that update themselves keep old versions next to the new one (app-1.0.1, app-1.0.2).
    newest: dict[str, str] = {}
    for folder in set(found):
        versioned = _VERSION_FOLDER.match(os.path.basename(folder))
        key = os.path.normcase(os.path.dirname(folder)) + "|v" if versioned else os.path.normcase(folder)
        if key not in newest or _newness(folder) > _newness(newest[key]):
            newest[key] = folder
    kept: list[str] = []
    for folder in sorted(newest.values(), key=len):          # drop folders that sit inside one already kept
        if not any(os.path.normcase(folder).startswith(os.path.normcase(parent) + os.sep) for parent in kept):
            kept.append(folder)
    return kept[:3]


def scan_folder(root: str, deadline: float | None = None) -> dict:
    """Read the files under `root` and report which known components they mention."""
    needles, names = _matcher()
    deadline = deadline or time.time() + MAX_SECONDS
    found: dict[str, dict] = {}
    files = total = 0
    complete = True

    def hit(sdk_id: str, path: str, evidence: str) -> None:
        entry = found.setdefault(sdk_id, {"id": sdk_id, "evidence": [], "files": 0})
        entry["files"] += 1
        if len(entry["evidence"]) < 3:
            entry["evidence"].append({"file": os.path.relpath(path, root), "match": evidence})

    for folder, subfolders, filenames in os.walk(root):
        subfolders[:] = [name for name in subfolders if name.lower() not in SKIP_FOLDERS]
        versions = [name for name in subfolders if _VERSION_FOLDER.match(name)]
        if len(versions) > 1:                               # only the newest of several kept versions
            latest = max(versions, key=lambda name: _newness(os.path.join(folder, name)))
            subfolders[:] = [name for name in subfolders if name == latest or name not in versions]
        for filename in filenames:
            path = os.path.join(folder, filename)
            lowered = filename.lower()
            if lowered in names:
                hit(names[lowered], path, "file name")
            if os.path.splitext(lowered)[1] not in EXTENSIONS:
                continue
            try:
                size = os.path.getsize(path)
            except OSError:
                continue
            if size < 64 or size > MAX_FILE:
                continue
            if files >= MAX_FILES or total >= MAX_BYTES or time.time() > deadline:
                complete = False
                break
            files += 1
            total += size
            seen: set[str] = set()
            first: dict[str, str] = {}
            try:
                with open(path, "rb") as handle:
                    tail = b""
                    while True:
                        block = handle.read(CHUNK)
                        if not block:
                            break
                        text = (tail + block).lower().replace(b"\x00", b"")
                        for needle, sdk_id in needles:
                            if sdk_id not in seen and needle in text:
                                seen.add(sdk_id)
                                first[sdk_id] = needle.decode("ascii")
                        tail = block[-OVERLAP:]
            except OSError:
                continue
            # A file that names many different services is a list of trackers (browsers ship
            # such lists to block them), not a component that reports.
            # Program files are exempt: an app bundle can honestly contain that many components.
            if len(seen) < TRACKER_LIST_AT or os.path.splitext(lowered)[1] in CODE_EXTENSIONS:
                for sdk_id in seen:
                    hit(sdk_id, path, first[sdk_id])
        if not complete:
            break
    return {"root": root, "scanned": time.time(), "files": files, "bytes": total, "complete": complete,
            "found": sorted(found.values(), key=lambda item: item["id"])}


# --- stored results and background runs --------------------------------------------------------

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


def stored(root: str, file: Path | None = None) -> dict | None:
    with _db(file) as conn:
        row = conn.execute("SELECT * FROM sdk_scans WHERE root = ?", (os.path.normcase(root),)).fetchone()
    if row is None:
        return None
    return {"root": root, "scanned": row["scanned"], "files": row["files"], "bytes": row["bytes"],
            "complete": bool(row["complete"]), "found": json.loads(row["found"])}


def save(result: dict, file: Path | None = None) -> None:
    with _db(file) as conn:
        conn.execute("INSERT OR REPLACE INTO sdk_scans VALUES (?,?,?,?,?,?)",
                     (os.path.normcase(result["root"]), result["scanned"], result["files"], result["bytes"],
                      int(result["complete"]), json.dumps(result["found"])))


_running: set[str] = set()
_running_lock = threading.Lock()


def start(roots: list[str]) -> list[str]:
    """Scan folders in the background. Returns the ones that were started now."""
    started = []
    for root in roots:
        key = os.path.normcase(root)
        with _running_lock:
            if key in _running:
                continue
            _running.add(key)

        def work(folder: str = root, mark: str = key) -> None:
            try:
                save(scan_folder(folder))
            except Exception:  # noqa: BLE001 - record an empty, incomplete result instead of leaving it pending for ever
                save({"root": folder, "scanned": time.time(), "files": 0, "bytes": 0, "complete": False, "found": []})
            finally:
                with _running_lock:
                    _running.discard(mark)

        threading.Thread(target=work, name="appaudit-sdk-scan", daemon=True).start()
        started.append(root)
    return started


def describe(found: list[dict], destination_names: list[str]) -> list[dict]:
    """Join scan hits with the catalogue and with what the app was seen talking to."""
    items = []
    lowered = [name.lower() for name in destination_names if name]
    for entry in found:
        sdk = catalogue().get(entry["id"])
        if sdk is None:
            continue
        domains = sdk.get("domains") or []
        seen = sorted({name for name in lowered for domain in domains if name == domain or name.endswith("." + domain)})
        items.append({"id": sdk["id"], "name": sdk["name"], "company": sdk["company"], "kind": sdk["kind"],
                      "collects": sdk["collects"], "example": sdk.get("example"), "evidence": entry["evidence"],
                      "files": entry["files"], "seen_talking_to": seen[:4]})
    order = {"advertising": 0, "analytics": 1, "flags": 2, "messaging": 3, "monitoring": 4, "crash": 5, "platform": 6}
    return sorted(items, key=lambda item: (order.get(item["kind"], 9), item["name"]))


def report(exes: list[str], destination_names: list[str]) -> dict:
    roots = roots_for(exes)
    with _running_lock:
        running = [root for root in roots if os.path.normcase(root) in _running]
    results = [result for result in (stored(root) for root in roots) if result]
    merged: dict[str, dict] = {}
    for result in results:
        for entry in result["found"]:
            if entry["id"] not in merged:
                merged[entry["id"]] = entry
    return {
        "folders": roots, "scanning": bool(running), "scanned": min((r["scanned"] for r in results), default=None),
        "pending": [root for root in roots if not any(r["root"] == root for r in results)],
        "files": sum(r["files"] for r in results), "bytes": sum(r["bytes"] for r in results),
        "complete": all(r["complete"] for r in results) if results else False,
        "found": describe(list(merged.values()), destination_names),
    }
