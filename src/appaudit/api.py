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


def refusal(method: str, headers) -> str | None:
    """Why a request must be refused, or None when it may proceed."""
    host = (headers.get("host") or "").rsplit(":", 1)[0].lower()
    if host not in ALLOWED_HOSTS:
        return "unexpected Host header"
    if headers.get("sec-fetch-site") not in (None, "same-origin", "none"):
        return "cross-site requests are refused"
    if method not in ("GET", "HEAD") and headers.get("x-appaudit-token") != TOKEN:
        return "missing or wrong session token"
    return None


@app.middleware("http")
async def guard(request: Request, call_next):
    reason = refusal(request.method, request.headers)
    if reason:
        return JSONResponse({"detail": reason}, status_code=403)
    response = await call_next(request)
    # Always revalidate: the dashboard's own files change with every update of the tool.
    response.headers["Cache-Control"] = "no-cache"
    return response


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
        from . import drift

        drift.record(states)
        titles = {entry["id"]: entry["title"] for entry in states}
        changes = [{**item, "title": titles.get(item["id"], item["id"])} for item in drift.log(limit=40)]
        return {"switches": states, "counts": counts, "journal": switches.journal_entries()[:50], "drift": changes}

    return cached(("switches",), 4, build)


def _plan(switch) -> list[dict]:
    from . import switches

    try:
        return switches.plan(switch)
    except ValueError as error:          # a settings file that cannot be changed safely
        raise HTTPException(409, f"Nothing was changed: {error}. The file is not in a form this tool "
                                 "can edit safely; use the steps or change it in the app.") from error


@app.get("/api/switches/for-app")
def get_switches_for_app(actor: str) -> dict:
    """The switches that concern one app on the Activity page, with their current state."""
    from . import switches

    found = _actor(actor)
    programs = set(found.get("exes") or [])
    services = {item["name"] for item in found.get("services") or [] if item.get("name")}
    states = [switches.state(item) for item in switches.for_app(programs, services)]
    order = {"exposed": 0, "partly": 0, "manual": 1, "unknown": 2, "private": 3}
    states = sorted((item for item in states if item["state"] != "not_installed"),
                    key=lambda item: (order.get(item["state"], 4), item["origin"] != "catalogue", item["title"]))
    return {"switches": states}


@app.get("/api/switches/{switch_id}/plan")
def get_switch_plan(switch_id: str) -> dict:
    return {"plan": _plan(_switch(switch_id))}


@app.post("/api/switches/{switch_id}/apply")
def post_switch_apply(switch_id: str) -> dict:
    from . import switches

    switch = _switch(switch_id)
    planned = _plan(switch)
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


@app.get("/api/history")
def get_history(days: int = 60) -> dict:
    from . import history

    def build() -> dict:
        data = history.summary(min(max(days, 1), 120))
        who = activity.attributor()
        for app in data["apps"]:
            ref = who.app_for_exe(app["exe"]) if app["exe"] else None
            app["name"] = ref.name if ref else app["app"]
            app["publisher"] = ref.publisher if ref else None
            app["is_system"] = ref.is_system if ref else app["exe"] is None
        return data

    return cached(("history", days), 120, build)


@app.post("/api/history/refresh")
def post_history_refresh() -> dict:
    result = _helper({"cmd": "history_refresh"})
    _cache.pop(("history", 60), None)
    return result


# --- dismissed items (a display choice; nothing on the PC changes) ------------------------------

@app.get("/api/dismissed")
def get_dismissed() -> dict:
    from . import dismissed

    return {"dismissed": dismissed.listing()}


@app.post("/api/dismissed")
async def post_dismissed(request: Request) -> dict:
    from . import dismissed

    body = await request.json()
    try:
        if body.get("remove"):
            dismissed.remove(str(body.get("kind")), str(body.get("key", "")))
        else:
            dismissed.add(str(body.get("kind")), str(body.get("key", "")), str(body.get("label", "")))
    except ValueError as error:
        raise HTTPException(400, str(error)) from error
    return {"dismissed": dismissed.listing()}


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


# --- what is inside: request content, built-in components, examples -----------------------------

def _actor(actor_id: str) -> dict:
    """An actor from the widest window that has it, so a row opened in any window resolves."""
    for hours in (24, 168):
        data = get_live(hours)
        for actor in data["actors"]:
            if actor["id"] == actor_id:
                return actor
    raise HTTPException(404, "unknown app")


@app.post("/api/content")
async def post_content(request: Request) -> dict:
    """Switch capture of request headers and bodies on or off. Off by default."""
    body = await request.json()
    return _helper({"cmd": "content", "on": bool(body.get("on"))})


@app.post("/api/content/clear")
def post_content_clear() -> dict:
    return _helper({"cmd": "content_clear"})


@app.get("/api/examples")
def get_examples(actor: str = "", host: str = "", example: str = "", addresses: str = "") -> dict:
    from . import examples

    if example:
        return {"host": host, "captured": [], "documented": examples.documented(example_id=example)}
    return examples.for_destination(actor, host, [item for item in addresses.split(",") if item])


def _sdk_report(actor: dict) -> dict:
    from . import sdks

    return sdks.report(actor.get("exes") or [], [item["name"] for item in actor["destinations"] if item.get("name")])


@app.get("/api/sdks")
def get_sdks(actor: str) -> dict:
    return _sdk_report(_actor(actor))


@app.post("/api/sdks/scan")
async def post_sdk_scan(request: Request) -> dict:
    """Read the app's own files to look for known reporting components. Reads only."""
    from . import sdks

    found = _actor(str((await request.json()).get("actor", "")))
    roots = sdks.roots_for(found.get("exes") or [])
    if not roots:
        raise HTTPException(400, "This app has no folder of its own to read (it is part of Windows or sits in a shared folder).")
    sdks.start(roots)
    return _sdk_report(found)


# --- asking a company what it holds --------------------------------------------------------------
# Nothing here sends anything. It drafts a letter and keeps a record of what the person did.

def _letter(body: dict) -> tuple[dict, list[str]]:
    from . import datarequests

    company = str(body.get("company", "")).strip()
    if not company:
        raise HTTPException(400, "no company named")
    evidence = datarequests.evidence_from(get_live(168)["actors"], company)
    letter = datarequests.draft(company, evidence, datarequests.profile(), body.get("law"))
    return letter, [item["app"] for item in evidence]


@app.get("/api/requests")
def get_requests() -> dict:
    from . import datarequests

    return {"profile": datarequests.profile(), "requests": datarequests.listing(),
            "laws": {key: {"title": law["title"], "days": law["days"]} for key, law in datarequests.LAWS.items()}}


@app.get("/api/requests/contact")
def get_request_contact(company: str = "", publisher: str = "") -> dict:
    from . import datarequests

    name = company or datarequests.company_for(publisher) or ""
    found = datarequests.contact(name) if name else {"known": False, "company": None, "role": "unknown"}
    # Companies that hold data on an app maker's behalf; the page uses this to word the letter note.
    return {**found, "processors": sorted(entry["company"] for entry in datarequests.directory().values()
                                          if entry.get("role") == "processor")}


@app.post("/api/requests/profile")
async def post_request_profile(request: Request) -> dict:
    from . import datarequests

    return {"profile": datarequests.save_profile(await request.json())}


@app.post("/api/requests/draft")
async def post_request_draft(request: Request) -> dict:
    letter, apps = _letter(await request.json())
    return {**letter, "apps": apps}


@app.post("/api/requests")
async def post_request(request: Request) -> dict:
    from . import datarequests

    letter, apps = _letter(await request.json())
    return {"id": datarequests.save(letter, apps), "requests": datarequests.listing()}


@app.post("/api/requests/{request_id}")
async def post_request_update(request_id: int, request: Request) -> dict:
    from . import datarequests

    try:
        datarequests.update(request_id, str((await request.json()).get("action")))
    except KeyError as error:
        raise HTTPException(404, "unknown request") from error
    except ValueError as error:
        raise HTTPException(400, str(error)) from error
    return {"requests": datarequests.listing()}


@app.get("/api/requests/{request_id}/reminder")
def get_request_reminder(request_id: int) -> dict:
    from . import datarequests

    item = next((entry for entry in datarequests.listing() if entry["id"] == request_id), None)
    if item is None or not item["sent"]:
        raise HTTPException(404, "no sent request with that number")
    return datarequests.reminder(item, datarequests.profile())


def mount_static() -> None:
    app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")


mount_static()
