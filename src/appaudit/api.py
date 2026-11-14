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


def mount_static() -> None:
    app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")


mount_static()
