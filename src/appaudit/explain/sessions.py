"""Explain a running trace session: who owns it and what it can see."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

KNOWLEDGE = Path(__file__).resolve().parent.parent / "knowledge"

# Providers that reveal what programs do. A session subscribed to one of these can observe it.
SENSITIVE = {
    "{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}": "every program that starts or stops",
    "{7dd42a49-5329-4832-8dfd-43d979153a88}": "network connections of every program",
    "{2f07e2ee-15db-40f1-90ef-9d7ba282188a}": "network connections of every program",
    "{edd08927-9cc4-4e65-b970-c2560fb5c289}": "files that programs open",
    "{70eb4f03-c1de-4f73-a051-33d13d5413bd}": "registry keys that programs read and write",
    "{1c95126e-7eea-49a9-a3fe-a378b03ddb4d}": "the names of sites that programs look up",
    "{43d1a55c-76d6-4f7e-995c-64c711e5cafe}": "web addresses requested through Windows' HTTP libraries",
    "{50b3e73c-9370-461d-bb9f-26f32d68887d}": "web addresses requested through Windows' HTTP libraries",
    "{4d4f80d9-c8bd-4d73-bb5b-19c90402c5ac}": "network packets",
    "{2ed6006e-4729-4609-b423-3ee7bcd678ef}": "network packets",
}


@lru_cache(maxsize=1)
def _known() -> list[dict]:
    entries = yaml.safe_load((KNOWLEDGE / "sessions.yaml").read_text(encoding="utf-8"))
    return sorted(entries, key=lambda item: -len(item["prefix"]))


def describe(session: dict) -> dict:
    name = session["name"]
    known = next((item for item in _known() if name.lower().startswith(item["prefix"].lower())), None)
    sees = []
    for provider in session.get("providers", []):
        what = SENSITIVE.get(provider["guid"])
        if what and what not in sees:
            sees.append(what)
    named = [provider["name"] for provider in session.get("providers", []) if provider.get("name")]
    return {
        "name": name, "mode": session.get("mode"), "output": session.get("output") or None,
        "provider_count": len(session.get("providers", [])), "providers": named[:12],
        "unnamed_providers": len(session.get("providers", [])) - len(named),
        "owner": known["owner"] if known else "Not identified", "kind": known["kind"] if known else "unknown",
        "what": known["what"] if known else "This session is not in the knowledge base yet.",
        "sees": sees,
    }
