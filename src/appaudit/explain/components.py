"""Look up the plain-language note for a program name."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

KNOWLEDGE = Path(__file__).resolve().parent.parent / "knowledge"


@lru_cache(maxsize=1)
def _table() -> dict[str, dict]:
    raw = yaml.safe_load((KNOWLEDGE / "components.yaml").read_text(encoding="utf-8"))
    return {name.lower(): value for name, value in raw.items()}


def note(process_name: str | None) -> dict | None:
    if not process_name:
        return None
    return _table().get(process_name.lower())


def reporting_names() -> set[str]:
    return {name for name, value in _table().items() if value.get("reports")}
