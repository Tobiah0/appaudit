"""Browsers: telling a browser's own reporting apart from the trackers of websites opened in it.

The list is in knowledge/browsers.yaml.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

KNOWLEDGE = Path(__file__).resolve().parent / "knowledge" / "browsers.yaml"


@lru_cache(maxsize=1)
def _browsers() -> list[dict]:
    entries = yaml.safe_load(KNOWLEDGE.read_text(encoding="utf-8")) or []
    return [{"name": entry["name"], "programs": {name.lower() for name in entry.get("programs", [])},
             "own": [suffix.lower() for suffix in entry.get("own", [])]} for entry in entries]


def browser_for(programs) -> dict | None:
    """The browser these process names belong to, if any."""
    names = {(name or "").lower() for name in programs}
    return next((browser for browser in _browsers() if browser["programs"] & names), None)


def is_own(browser: dict, host: str | None) -> bool:
    """Whether the browser itself reports to this host (as opposed to a website loading it)."""
    if not host:
        return False
    host = host.lower().rstrip(".")
    return any(host == suffix or host.endswith("." + suffix) for suffix in browser["own"])
