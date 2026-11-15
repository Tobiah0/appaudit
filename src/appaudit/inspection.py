"""Inspect this app: run it with its own network log switched on and show what it sent.

Apps built on Chromium (Chrome, Edge, Brave) and on Electron (VS Code, Discord, Slack, Notion,
Teams and many more) can log their own requests, including the content, after their own
encryption. An inspection:

  1. checks the app is not running (a running app would only pass the request to its open window);
  2. starts it as the signed-in user with  --log-net-log=<file> --net-log-capture-mode=Everything
     --disable-quic  (QUIC would bypass the part of the log that holds request bodies);
  3. the person uses the app normally;
  4. ends: the app is closed, the log is read into a report with secrets replaced, and the raw
     log, which holds cookies and sign-in tokens, is deleted.

Nothing is intercepted and no certificate is installed: the app writes the log itself, and only
for this one run. Runs in the unprivileged dashboard process.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
import time
import uuid
from pathlib import Path

from .store import data_dir

FLAGS = ["--net-log-capture-mode=Everything", "--disable-quic"]
NOT_MAIN = ("update", "updater", "squirrel", "crashpad", "crash", "helper", "uninstall", "setup", "installer", "elevate")
CHROMIUM_MARKERS = ("chrome_100_percent.pak", "resources.pak", "v8_context_snapshot.bin", "libcef.dll", "icudtl.dat")
DETACHED = 0x00000008 | 0x00000200          # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP


class Running(Exception):
    def __init__(self, processes: list[dict]):
        super().__init__("the app is running")
        self.processes = processes


def folder() -> Path:
    target = data_dir() / "inspections"
    target.mkdir(parents=True, exist_ok=True)
    return target


def _same(left: str, right: str) -> bool:
    return os.path.normcase(os.path.realpath(left)) == os.path.normcase(os.path.realpath(right))


def running(exe: str) -> list[dict]:
    """Processes started from this program file."""
    import psutil

    found = []
    for process in psutil.process_iter(["pid", "exe", "name", "create_time"]):
        path = process.info.get("exe")
        if path and _same(path, exe):
            found.append({"pid": process.info["pid"], "name": process.info["name"], "since": process.info["create_time"]})
    return found


def chromium_based(exe: str) -> bool:
    """Chromium's runtime files sit next to the program, or one folder down in apps that keep each
    version in its own folder (VS Code: Code.exe beside 6d62b1d5da\\resources.pak)."""
    directory = Path(exe).parent
    if any((directory / marker).exists() for marker in CHROMIUM_MARKERS):
        return True
    try:
        subfolders = [child for child in directory.iterdir() if child.is_dir()][:40]
    except OSError:
        return False
    return any((child / marker).exists() for child in subfolders for marker in CHROMIUM_MARKERS[:3])


def candidates(exes: list[str]) -> list[dict]:
    """The programs of an app that could be inspected, the likely main program first."""
    windows = os.path.normcase(os.environ.get("WINDIR", r"C:\Windows"))
    found = []
    for exe in exes:
        if not exe or os.path.normcase(exe).startswith(windows + os.sep) or not os.path.isfile(exe):
            continue
        stem = Path(exe).stem.lower()
        found.append({"exe": exe, "name": Path(exe).name, "main": not any(word in stem for word in NOT_MAIN),
                      "chromium": chromium_based(exe), "running": running(exe)})
    found.sort(key=lambda item: (not item["main"], not item["chromium"], item["name"].lower()))
    return found


def close(exe: str) -> int:
    """End every process of this program. Only on the person's explicit request."""
    import psutil

    ended = 0
    for item in running(exe):
        try:
            process = psutil.Process(item["pid"])
            family = process.children(recursive=True) + [process]
        except psutil.Error:
            continue
        for member in family:                     # one that already exited must not spare the others
            try:
                member.terminate()
            except psutil.Error:
                continue
        ended += 1
    deadline = time.time() + 5
    while running(exe) and time.time() < deadline:
        time.sleep(0.2)
    return ended


def _meta_path(inspection_id: str) -> Path:
    if not inspection_id.isalnum():
        raise KeyError("unknown inspection")
    return folder() / inspection_id / "meta.json"


def _save(meta: dict) -> None:
    path = _meta_path(meta["id"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(meta), encoding="utf-8")


def load(inspection_id: str) -> dict:
    path = _meta_path(inspection_id)
    if not path.exists():
        raise KeyError("unknown inspection")
    return json.loads(path.read_text(encoding="utf-8"))


def start(actor_id: str, actor_name: str, exe: str) -> dict:
    if not os.path.isfile(exe) or not exe.lower().endswith(".exe"):
        raise ValueError("not a program file")
    already = running(exe)
    if already:
        raise Running(already)
    inspection_id = uuid.uuid4().hex[:16]
    directory = folder() / inspection_id
    directory.mkdir(parents=True)
    log = directory / "net.json"
    process = subprocess.Popen([exe, f"--log-net-log={log}", *FLAGS], cwd=str(Path(exe).parent),
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               creationflags=DETACHED, close_fds=True)
    meta = {"id": inspection_id, "actor": actor_id, "app": actor_name, "exe": exe, "pid": process.pid,
            "started": time.time(), "ended": None, "status": "running", "chromium": chromium_based(exe)}
    _save(meta)
    return meta


WARN_BYTES = 2 * 1024**3        # full capture logs every byte received too: a few minutes can be gigabytes
STOP_BYTES = 4 * 1024**3
PREVIEW_BYTES = 300 * 1024**2
_previews: dict[str, tuple[int, int]] = {}


def status(inspection_id: str) -> dict:
    meta = load(inspection_id)
    if meta["status"] != "running":
        return meta
    log = folder() / inspection_id / "net.json"
    size = log.stat().st_size if log.exists() else 0
    if size >= STOP_BYTES:                       # protect the disk: end it now
        finish(inspection_id, close_app=True, reason="The log reached 4 GB, so the inspection was ended automatically.")
        return load(inspection_id)
    alive = bool(running(meta["exe"]))
    preview = None
    if size and size <= PREVIEW_BYTES:
        cached = _previews.get(inspection_id)
        if cached and cached[0] == size:
            preview = cached[1]
        else:
            try:
                from . import netlog

                preview = sum(1 for event in netlog.load_file(log)["events"] if event.get("params", {}).get("url"))
                _previews[inspection_id] = (size, preview)
            except (OSError, ValueError):
                preview = None
    return {**meta, "log_bytes": size, "app_running": alive, "requests_so_far": preview,
            "large": size >= WARN_BYTES, "no_log": not size and time.time() - meta["started"] > 30}


def finish(inspection_id: str, close_app: bool = True, reason: str | None = None) -> dict:
    """End the inspection: close the app, then read the log in the background and delete it."""
    meta = load(inspection_id)
    if meta["status"] != "running":
        return meta
    if close_app:
        close(meta["exe"])
    meta.update(status="reading", ended=time.time(), note=reason)
    _save(meta)
    threading.Thread(target=_read, args=(inspection_id,), daemon=True).start()
    return meta


def _read(inspection_id: str) -> None:
    from . import netlog

    log = folder() / inspection_id / "net.json"
    report_path = folder() / inspection_id / "report.json"
    time.sleep(1.5)                                  # let the closed app finish writing its log
    try:
        result = netlog.report_file(log) if log.exists() and log.stat().st_size else {"requests": [], "hosts": [], "empty": True}
    except (OSError, ValueError, MemoryError) as error:
        result = {"requests": [], "hosts": [], "error": f"The log could not be read: {type(error).__name__}: {error}"}
    report_path.write_text(json.dumps(result), encoding="utf-8")
    for _attempt in range(20):                       # it holds cookies and sign-in tokens: it must go
        try:
            log.unlink(missing_ok=True)
            break
        except OSError:
            time.sleep(0.5)
    meta = load(inspection_id)
    meta.update(status="done", requests=len(result["requests"]), hosts=len(result["hosts"]),
                raw_log_deleted=not log.exists())
    _save(meta)


def report(inspection_id: str) -> dict:
    meta = load(inspection_id)
    path = folder() / inspection_id / "report.json"
    return {**meta, "report": json.loads(path.read_text(encoding="utf-8")) if path.exists() else None}


def listing(actor_id: str | None = None) -> list[dict]:
    items = []
    for path in folder().glob("*/meta.json"):
        try:
            meta = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if actor_id is None or meta.get("actor") == actor_id:
            items.append(meta)
    return sorted(items, key=lambda item: -item["started"])


def delete(inspection_id: str) -> None:
    meta = load(inspection_id)
    if meta["status"] in ("running", "reading"):
        raise ValueError("end the inspection first, and wait until its log has been read")
    shutil.rmtree(folder() / inspection_id, ignore_errors=True)
