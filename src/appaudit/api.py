"""Local JSON API and static dashboard.

The server listens on loopback only. Two checks keep other web pages out:
  - the Host header must be this server's own loopback address (defeats DNS rebinding);
  - anything that changes state needs the session token, which only a same-origin page can read.
"""

from __future__ import annotations

import secrets
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from . import activity, scan, store
from .winutil import is_admin

WEB_DIR = Path(__file__).parent / "web"
TOKEN = secrets.token_urlsafe(24)
ALLOWED_HOSTS = {"127.0.0.1", "localhost", "[::1]"}


@asynccontextmanager
async def lifespan(_app: FastAPI):
    if store.latest_scan() is None:
        scan.start_scan_in_background()
    threading.Thread(target=activity.attributor, daemon=True).start()   # warm the slow lookups
    yield


app = FastAPI(title="App Audit", lifespan=lifespan)


@app.middleware("http")
async def guard(request: Request, call_next):
    host = (request.headers.get("host") or "").rsplit(":", 1)[0].lower()
    if host not in ALLOWED_HOSTS:
        return JSONResponse({"detail": "unexpected Host header"}, status_code=403)
    site = request.headers.get("sec-fetch-site")
    if site not in (None, "same-origin", "none"):
        return JSONResponse({"detail": "cross-site requests are refused"}, status_code=403)
    if request.method not in ("GET", "HEAD") and request.headers.get("x-appaudit-token") != TOKEN:
        return JSONResponse({"detail": "missing or wrong session token"}, status_code=403)
    return await call_next(request)


@app.get("/api/session")
def get_session() -> dict:
    return {"token": TOKEN}


def _summary(apps: list[dict]) -> dict:
    visible = [a for a in apps if not a["is_system"]]
    codes = lambda a: {f["code"] for f in a["findings"]}  # noqa: E731
    return {
        "apps": len(visible),
        "system_hidden": len(apps) - len(visible),
        "flagged": sum(1 for a in visible if a["findings"]),
        "starts_unused": sum(1 for a in visible if "starts_unused" in codes(a)),
        "running_unused": sum(1 for a in visible if codes(a) & {"running_unused", "ran_unused"}),
        "sensor_apps": sum(1 for a in visible if a["sensors"]),
    }


@app.get("/api/state")
def get_state() -> dict:
    return {
        "scanning": scan.state["scanning"], "step": scan.state["step"], "error": scan.state["error"],
        "elevated": is_admin(), "scan": store.latest_scan(), "pending_sources": [],
        "helper": activity.helper_state(),
    }


@app.get("/api/apps")
def get_apps() -> dict:
    latest = store.latest_scan()
    if latest is None:
        return {"scan": None, "apps": [], "summary": None}
    apps = store.load_apps(latest["id"])
    return {"scan": latest, "apps": apps, "summary": _summary(apps)}


@app.post("/api/scan")
def post_scan() -> dict:
    return {"started": scan.start_scan_in_background()}


# --- live activity ---------------------------------------------------------------------

_cache: dict[tuple, tuple[float, dict]] = {}
_cache_lock = threading.Lock()


def cached(key: tuple, seconds: float, build):
    with _cache_lock:
        hit = _cache.get(key)
        if hit and time.time() - hit[0] < seconds:
            return hit[1]
    value = build()
    with _cache_lock:
        _cache[key] = (time.time(), value)
    return value


@app.get("/api/live")
def get_live(hours: float = 24) -> dict:
    hours = min(max(hours, 0.05), 24 * 90)
    return cached(("live", hours), 10, lambda: activity.snapshot(since=time.time() - hours * 3600))


@app.get("/api/live/processes")
def get_live_processes(system_only: bool = False) -> dict:
    return {"processes": cached(("procs", system_only), 10, lambda: activity.recent_processes(300, system_only))}


@app.post("/api/helper/start")
def post_helper_start() -> dict:
    """Ask Windows to start the helper elevated. Windows decides whether to prompt."""
    from .helper.__main__ import launch_elevated

    if activity.helper_state()["running"]:
        return {"started": False, "reason": "already running"}
    result = launch_elevated([])
    if result <= 32:
        raise HTTPException(500, f"Windows refused to start the helper (code {result})")
    return {"started": True}


@app.post("/api/helper/stop")
def post_helper_stop() -> dict:
    from .helper import pipe

    try:
        return pipe.send({"cmd": "stop"})
    except ConnectionError as error:
        raise HTTPException(409, str(error)) from error


# --- switches --------------------------------------------------------------------------------
# These endpoints change Windows settings. They run only when the person at the PC presses a
# button in the dashboard, and only for changes that the catalogue describes.

def _helper(command: dict) -> dict:
    from .helper import pipe

    try:
        reply = pipe.send(command, timeout_ms=8000)
    except ConnectionError as error:
        raise HTTPException(409, "This switch needs administrator rights. Start watching first, "
                                 "which starts the helper that applies it.") from error
    if not reply.get("ok"):
        raise HTTPException(500, reply.get("error", "the helper refused the command"))
    return reply


def _switch(switch_id: str):
    from . import switches

    switch = switches.load_catalogue().get(switch_id)
    if switch is None:
        raise HTTPException(404, "unknown switch")
    return switch


@app.get("/api/switches")
def get_switches() -> dict:
    from . import switches

    def build() -> dict:
        states = [switches.state(item) for item in switches.load_catalogue().values()]
        counts: dict[str, int] = {}
        for entry in states:
            counts[entry["state"]] = counts.get(entry["state"], 0) + 1
        return {"switches": states, "counts": counts, "journal": switches.journal_entries()[:50]}

    return cached(("switches",), 4, build)


@app.get("/api/switches/{switch_id}/plan")
def get_switch_plan(switch_id: str) -> dict:
    from . import switches

    return {"plan": switches.plan(_switch(switch_id))}


@app.post("/api/switches/{switch_id}/apply")
def post_switch_apply(switch_id: str) -> dict:
    from . import switches

    switch = _switch(switch_id)
    planned = switches.plan(switch)
    result = {"changed": [], "failed": [], "journal_ids": []}
    if any(change["admin"] for change in planned):
        reply = _helper({"cmd": "switch_apply", "id": switch_id})
        result["changed"] += reply["changed"]
        result["failed"] += reply["failed"]
        result["journal_ids"].append(reply.get("journal_id"))
    if any(not change["admin"] for change in planned):
        local = switches.apply(switch, only_admin=False)
        result["changed"] += local["changed"]
        result["failed"] += local["failed"]
        result["journal_ids"].append(local["journal_id"])
    _cache.pop(("switches",), None)
    result["state"] = switches.state(switch)
    return result


@app.post("/api/switches/undo/{entry_id}")
def post_switch_undo(entry_id: int) -> dict:
    from . import switches

    entry = next((item for item in switches.journal_entries() if item["id"] == entry_id), None)
    if entry is None:
        raise HTTPException(404, "unknown journal entry")
    if any(change["admin"] for change in entry["changes"]):
        result = _helper({"cmd": "switch_undo", "entry": entry_id})
    else:
        result = switches.undo(entry_id, only_admin=False)
    _cache.pop(("switches",), None)
    return result


@app.get("/api/digest")
def get_digest(hours: float = 12) -> dict:
    from . import digest

    return cached(("digest", hours), 20, lambda: digest.build(min(max(hours, 1), 24 * 30)))


# --- per-app network blocks -------------------------------------------------------------------

@app.get("/api/blocks")
def get_blocks() -> dict:
    from . import blocks

    return {"blocks": blocks.active()}


@app.post("/api/blocks")
async def post_block(request: Request) -> dict:
    from . import blocks

    body = await request.json()
    try:
        blocks.validate(str(body.get("exe", "")))
    except ValueError as error:
        raise HTTPException(400, str(error)) from error
    return _helper({"cmd": "block_add", "exe": body["exe"]})


@app.post("/api/blocks/{entry_id}/remove")
def post_block_remove(entry_id: int) -> dict:
    return _helper({"cmd": "block_remove", "id": entry_id})


# --- proof, Windows telemetry, trace sessions ---------------------------------------------------

@app.get("/api/proof")
def get_proof(hours: float = 24) -> dict:
    from . import proof

    return cached(("proof", hours), 20, lambda: proof.report(min(max(hours, 1), 24 * 30)))


def _helper_read(command: str, **extra) -> dict:
    from .helper import pipe

    try:
        reply = pipe.send({"cmd": command, **extra}, timeout_ms=60000)
    except ConnectionError:
        return {"available": False, "reason": "Start watching to read this; it needs administrator rights."}
    if not reply.get("ok"):
        return {"available": False, "reason": reply.get("error", "the helper refused")}
    return {"available": True, **reply}


@app.get("/api/windows-telemetry")
def get_windows_telemetry() -> dict:
    from . import proof, switches

    def build() -> dict:
        catalogue = switches.load_catalogue()
        services = [switches.state(catalogue[item]) for item in ("svc.diagtrack", "svc.whesvc", "svc.wer", "svc.inventory")]
        return {"counters": proof.upload_counters(), "services": services, "details": _helper_read("windows_telemetry")}

    return cached(("wintel",), 30, build)


@app.get("/api/windows-telemetry/events")
def get_transcript() -> dict:
    return _helper_read("transcript", limit=300)


@app.get("/api/listeners")
def get_listeners() -> dict:
    from .explain import sessions

    def build() -> dict:
        reply = _helper_read("trace_sessions")
        if reply.get("available"):
            reply["sessions"] = [sessions.describe(item) for item in reply["sessions"]]
        return reply

    return cached(("listeners",), 60, build)


def mount_static() -> None:
    app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")


mount_static()
