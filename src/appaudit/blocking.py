"""What can be blocked safely: shared addresses and the never-block list (STOPPING.md).

Two questions decide whether a destination can be blocked without breaking something:

  never_block(name)       is this host on the list of things that must keep working (sign-in,
                          licensing, updates, time, security), or marked blockable "no"?
  shared(conn, name, ...) the addresses this name resolved to while it was used, and the other
                          names those addresses carried at the same time. Blocking an address that
                          also serves Safe Browsing or an updater breaks that too.
"""

from __future__ import annotations

import sqlite3
from collections import defaultdict
from functools import lru_cache
from pathlib import Path

import yaml

from .naming import labels

KNOWLEDGE = Path(__file__).resolve().parent / "knowledge" / "neverblock.yaml"
OVERLAP_SLACK = 24 * 3600          # a name counts for an address this long around its last resolution
ALIAS_SECONDS = 2.0                # names first seen for an address this close together came in one answer


def _matches(name: str, suffix: str) -> bool:
    name = name.lower().rstrip(".")
    return name == suffix or name.endswith("." + suffix)


@lru_cache(maxsize=1)
def _never() -> list[tuple[str, str, str]]:
    entries = yaml.safe_load(KNOWLEDGE.read_text(encoding="utf-8")) or []
    return [(suffix.lower(), entry["reason"], entry.get("source", "")) for entry in entries for suffix in entry["suffixes"]]


def never_block(name: str | None) -> dict | None:
    """Why this host must not be blocked, or None."""
    if not name:
        return None
    for suffix, reason, source in _never():
        if _matches(name, suffix):
            return {"reason": reason, "source": source}
    label = labels.for_name(name)
    if label.get("blockable") == "no":
        return {"reason": label.get("breaks") or label.get("purpose") or "marked as needed", "source": "knowledge base"}
    return None


def shared(conn: sqlite3.Connection, name: str, since: float = 0.0, until: float | None = None) -> dict:
    """The addresses `name` resolved to, and for each the other names it carried at overlapping times.

    `clean` is true when no address of this name also served another name: blocking those
    addresses for one program then stops only this destination.
    """
    until = until if until is not None else float("inf")
    mine: dict[str, tuple[float, float]] = {}
    for address, first, last in conn.execute("SELECT address, first, last FROM names WHERE lower(name) = ?", (name.lower(),)):
        if last + OVERLAP_SLACK >= since and first - OVERLAP_SLACK <= until:
            mine[address] = (first, last)
    others: dict[str, list[str]] = defaultdict(list)
    if mine:
        marks = ",".join("?" * len(mine))
        for address, other, first, last in conn.execute(
                f"SELECT address, name, first, last FROM names WHERE address IN ({marks}) AND lower(name) != ?", (*mine, name.lower())):
            own_first, own_last = mine[address]
            same_answer = abs(first - own_first) < ALIAS_SECONDS     # a CNAME in the same DNS answer
            overlaps = first - OVERLAP_SLACK <= own_last and last + OVERLAP_SLACK >= own_first
            if overlaps and not same_answer and not _same_service(name, other):
                others[address].append(other)
    blocked_too = sorted({other for names in others.values() for other in names if never_block(other)})
    return {"name": name, "addresses": sorted(mine), "shared": {address: sorted(set(names)) for address, names in others.items()},
            "clean": bool(mine) and not others, "would_also_block": sorted({n for names in others.values() for n in names}),
            "would_break": blocked_too}


def _same_service(name: str, other: str) -> bool:
    """An alias in the same DNS chain (a CNAME such as x.example.com -> x.example.com.cdn.net) or the
    same registrable site is the same service, not a different one sharing the address."""
    return labels.registrable(name) == labels.registrable(other) or other.lower().startswith(name.lower())
