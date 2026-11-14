"""Camera, microphone, location and screen-capture history from the ConsentStore.

Windows records the last start and stop of each capability per app. Desktop apps sit
under NonPackaged with '#' in place of '\\'; Store apps are keyed by package family.
"""

from __future__ import annotations

import os
import winreg

from ..winutil import filetime_to_dt, iter_subkeys, reg_value
from . import Evidence

NAME = "consent"
TITLE = "Camera, mic and location history"

BASE = r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"
CAPABILITIES = {
    "webcam": "Camera",
    "microphone": "Microphone",
    "location": "Location",
    "graphicsCaptureProgrammatic": "Screen capture",
}


def _read(key, capability: str, **target) -> Evidence | None:
    start = filetime_to_dt(reg_value(key, "LastUsedTimeStart", 0))
    if start is None:
        return None
    stop = filetime_to_dt(reg_value(key, "LastUsedTimeStop", 0))
    return Evidence(
        source=NAME,
        kind="sensor",
        ts=start,
        data={
            "capability": capability,
            "title": CAPABILITIES[capability],
            "allowed": reg_value(key, "Value"),
            "last_start": start,
            "last_stop": stop,
            "in_use": stop is None or stop < start,
        },
        **target,
    )


def collect() -> list[Evidence]:
    evidence: list[Evidence] = []
    for capability in CAPABILITIES:
        try:
            cap_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, f"{BASE}\\{capability}")
        except OSError:
            continue
        with cap_key:
            for sub in list(iter_subkeys(cap_key)):
                if sub == "NonPackaged":
                    with winreg.OpenKey(cap_key, sub) as desktop_key:
                        for encoded in list(iter_subkeys(desktop_key)):
                            with winreg.OpenKey(desktop_key, encoded) as app_key:
                                exe = os.path.normpath(encoded.replace("#", "\\"))
                                item = _read(app_key, capability, exe=exe)
                                if item:
                                    evidence.append(item)
                else:
                    with winreg.OpenKey(cap_key, sub) as app_key:
                        item = _read(app_key, capability, package=sub)
                        if item:
                            evidence.append(item)
    return evidence
