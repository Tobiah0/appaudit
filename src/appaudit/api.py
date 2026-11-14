"""Local JSON API and static dashboard."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from . import scan, store
from .winutil import is_admin

WEB_DIR = Path(__file__).parent / "web"

# Sources planned for the elevated build; listed so the dashboard can say what is missing.
PENDING_SOURCES = [
    {"name": "prefetch", "title": "Run history (Prefetch)"},
    {"name": "srum", "title": "30-day usage and network totals (SRUM)"},
    {"name": "dns", "title": "Domain names for connections"},
]


@asynccontextmanager
async def lifespan(_app: FastAPI):
    if store.latest_scan() is None:
        scan.start_scan_in_background()
    yield


app = FastAPI(title="App Audit", lifespan=lifespan)


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
    latest = store.latest_scan()
    return {
        "scanning": scan.state["scanning"],
        "step": scan.state["step"],
        "error": scan.state["error"],
        "elevated": is_admin(),
        "scan": latest,
        "pending_sources": PENDING_SOURCES,
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


app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")
