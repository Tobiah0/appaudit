"""UserAssist: programs the user launched through Explorer (Start menu, taskbar, double-click).

Value names are ROT13-encoded. Each 72-byte value holds a run count, the time the
window had focus, and the last launch time.
"""

from __future__ import annotations

import codecs
import os
import struct
import winreg

from ..winutil import expand_known_folder, filetime_to_dt, iter_subkeys, iter_values, resolve_shortcut
from . import Evidence

NAME = "userassist"
TITLE = "Launch history (UserAssist)"

KEY = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"


def _classify(decoded: str) -> dict | None:
    """Work out what a decoded value name points at."""
    path = expand_known_folder(decoded)
    if path.lower().endswith(".lnk"):
        if not os.path.isfile(path):
            return None
        target = resolve_shortcut(path)
        label = os.path.splitext(os.path.basename(path))[0]
        if target and target.lower().endswith(".exe") and os.path.isfile(target):
            return {"exe": target, "label": label, "via": "shortcut"}
        return {"label": label, "via": "shortcut"}
    if len(path) > 2 and (path[1:3] == ":\\" or path.startswith("\\\\")):
        if not os.path.isfile(path):
            return None  # the program has been removed since
        return {"exe": os.path.normpath(path), "via": "exe"}
    if "!" in decoded:
        family = decoded.split("!", 1)[0]
        if "_" in family:
            return {"package": family, "via": "exe", "aumid": decoded}
    return {"label": decoded, "via": "exe", "aumid": decoded}


def collect() -> list[Evidence]:
    evidence: list[Evidence] = []
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, KEY) as root:
        for guid in list(iter_subkeys(root)):
            try:
                count_key = winreg.OpenKey(root, guid + r"\Count")
            except OSError:
                continue
            with count_key:
                for name, value, value_type in iter_values(count_key):
                    if value_type != winreg.REG_BINARY or len(value) != 72:
                        continue
                    decoded = codecs.decode(name, "rot_13")
                    if decoded.startswith("UEME_"):
                        continue
                    run_count, _focus_count, focus_ms = struct.unpack_from("<III", value, 4)
                    last_run = filetime_to_dt(struct.unpack_from("<Q", value, 60)[0])
                    if last_run is None and run_count == 0 and focus_ms == 0:
                        continue
                    target = _classify(decoded)
                    if target is None:
                        continue
                    evidence.append(Evidence(
                        source=NAME,
                        kind="usage",
                        exe=target.get("exe"),
                        package=target.get("package"),
                        label=target.get("label"),
                        ts=last_run,
                        data={
                            "run_count": run_count,
                            "focus_ms": focus_ms,
                            "via": target["via"],
                            "aumid": target.get("aumid"),
                            "entry": decoded,
                        },
                    ))
    return evidence
