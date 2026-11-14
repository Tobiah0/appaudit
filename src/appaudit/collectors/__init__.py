"""Collectors: one module per Windows data source.

Each module exposes NAME, TITLE and collect() -> list[Evidence]. A collector that
needs elevation raises PermissionError; any other failure is reported, never raised.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Evidence:
    source: str                      # collector NAME
    kind: str                        # usage | autostart | sensor | process
    exe: str | None = None           # full executable path when known
    package: str | None = None       # package family name for Store apps
    label: str | None = None         # human-readable hint when nothing else identifies it
    ts: datetime | None = None       # the most relevant time for this evidence
    data: dict = field(default_factory=dict)


@dataclass
class SourceResult:
    name: str
    title: str
    status: str                      # ok | needs_admin | error
    detail: str = ""
    seconds: float = 0.0
    evidence: list[Evidence] = field(default_factory=list)

    def summary(self) -> dict:
        return {
            "name": self.name,
            "title": self.title,
            "status": self.status,
            "detail": self.detail,
            "seconds": round(self.seconds, 2),
            "count": len(self.evidence),
        }


def run_all(progress=None) -> list[SourceResult]:
    from . import autostart, consent, processes, services, tasks, userassist

    results = []
    for module in (userassist, consent, autostart, tasks, services, processes):
        if progress:
            progress(module.TITLE)
        started = time.time()
        result = SourceResult(name=module.NAME, title=module.TITLE, status="ok")
        try:
            result.evidence = module.collect()
        except PermissionError as exc:
            result.status, result.detail = "needs_admin", str(exc)
        except Exception as exc:  # noqa: BLE001 - one broken source must not stop the scan
            result.status, result.detail = "error", f"{type(exc).__name__}: {exc}"
        result.seconds = time.time() - started
        results.append(result)
    return results
