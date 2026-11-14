"""Run every collector, group the evidence into apps and save the result."""

from __future__ import annotations

import threading
from datetime import datetime, timezone

from . import store
from .collectors import run_all
from .identity import Resolver
from .rules import build_apps
from .winutil import is_admin

UNUSED_DAYS = 90

_lock = threading.Lock()
state = {"scanning": False, "step": "", "error": None}


def run_scan(unused_days: int = UNUSED_DAYS) -> int | None:
    """Run one scan. Returns the scan id, or None if a scan is already in progress."""
    if not _lock.acquire(blocking=False):
        return None
    import pythoncom

    pythoncom.CoInitialize()
    state.update(scanning=True, step="Starting", error=None)
    try:
        started = datetime.now(timezone.utc)
        results = run_all(progress=lambda title: state.update(step=title))
        state.update(step="Grouping into apps")
        resolver = Resolver()
        evidence = [item for result in results for item in result.evidence]
        apps = build_apps(evidence, resolver, unused_days=unused_days)
        return store.save_scan(
            started, datetime.now(timezone.utc), is_admin(), unused_days,
            [result.summary() for result in results], apps,
        )
    except Exception as exc:  # noqa: BLE001 - surfaced to the dashboard
        state.update(error=f"{type(exc).__name__}: {exc}")
        raise
    finally:
        state.update(scanning=False, step="")
        pythoncom.CoUninitialize()
        _lock.release()


def start_scan_in_background() -> bool:
    if state["scanning"]:
        return False
    threading.Thread(target=run_scan, name="appaudit-scan", daemon=True).start()
    return True
