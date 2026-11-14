"""Autostart entries: Run keys, Startup folders and Store-app startup tasks.

Task Manager disables an entry by writing a flag to the StartupApproved key and
leaves the Run value in place, so both are read to learn the real state.
"""

from __future__ import annotations

import os
import struct
import winreg

from ..winutil import command_to_exe, filetime_to_dt, iter_subkeys, iter_values, reg_value, resolve_shortcut
from . import Evidence

NAME = "autostart"
TITLE = "Startup entries"

RUN = r"Software\Microsoft\Windows\CurrentVersion\Run"
APPROVED = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved"
PACKAGED = r"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData"

# (hive, hive label, key path, registry view, StartupApproved subkey, description)
RUN_KEYS = [
    (winreg.HKEY_CURRENT_USER, "HKCU", RUN, 0, "Run", "Run key (this user)"),
    (winreg.HKEY_LOCAL_MACHINE, "HKLM", RUN, winreg.KEY_WOW64_64KEY, "Run", "Run key (all users)"),
    (winreg.HKEY_LOCAL_MACHINE, "HKLM", RUN, winreg.KEY_WOW64_32KEY, "Run32", "Run key (all users, 32-bit)"),
    (winreg.HKEY_CURRENT_USER, "HKCU", RUN + "Once", 0, None, "RunOnce key (this user)"),
    (winreg.HKEY_LOCAL_MACHINE, "HKLM", RUN + "Once", winreg.KEY_WOW64_64KEY, None, "RunOnce key (all users)"),
]

# Packaged startup task states: 0 disabled, 1 disabled by user, 2 enabled,
# 3 disabled by policy, 4 enabled by policy.
PACKAGED_ENABLED = {2, 4}


def _approved(hive, subkey: str | None) -> dict[str, tuple[bool, object]]:
    """Map value name -> (enabled, time it was last switched)."""
    states: dict[str, tuple[bool, object]] = {}
    if subkey is None:
        return states
    try:
        key = winreg.OpenKey(hive, f"{APPROVED}\\{subkey}")
    except OSError:
        return states
    with key:
        for name, value, value_type in iter_values(key):
            if value_type != winreg.REG_BINARY or not value:
                continue
            changed = filetime_to_dt(struct.unpack_from("<Q", value, 4)[0]) if len(value) >= 12 else None
            states[name.lower()] = (value[0] % 2 == 0, changed)
    return states


def _run_keys() -> list[Evidence]:
    evidence = []
    for hive, hive_label, path, view, approved_subkey, description in RUN_KEYS:
        try:
            key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ | view)
        except OSError:
            continue
        states = _approved(hive, approved_subkey)
        with key:
            for name, value, value_type in iter_values(key):
                if value_type not in (winreg.REG_SZ, winreg.REG_EXPAND_SZ) or not name:
                    continue
                enabled, changed = states.get(name.lower(), (True, None))
                evidence.append(Evidence(
                    source=NAME,
                    kind="autostart",
                    exe=command_to_exe(str(value)),
                    label=name,
                    data={
                        "mechanism": "run_key",
                        "mechanism_title": description,
                        "name": name,
                        "command": str(value),
                        "enabled": enabled,
                        "state_changed": changed,
                        "location": {"hive": hive_label, "approved": approved_subkey, "value": name},
                    },
                ))
    return evidence


def _startup_folders() -> list[Evidence]:
    evidence = []
    folders = [
        (winreg.HKEY_CURRENT_USER, "HKCU", os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
         "Startup folder (this user)"),
        (winreg.HKEY_LOCAL_MACHINE, "HKLM", os.path.expandvars(r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup"),
         "Startup folder (all users)"),
    ]
    for hive, hive_label, folder, description in folders:
        if not os.path.isdir(folder):
            continue
        states = _approved(hive, "StartupFolder")
        for entry in os.scandir(folder):
            if not entry.is_file() or entry.name.lower() == "desktop.ini":
                continue
            target = resolve_shortcut(entry.path) if entry.name.lower().endswith(".lnk") else entry.path
            enabled, changed = states.get(entry.name.lower(), (True, None))
            evidence.append(Evidence(
                source=NAME,
                kind="autostart",
                exe=target if target and os.path.isfile(target) else None,
                label=os.path.splitext(entry.name)[0],
                data={
                    "mechanism": "startup_folder",
                    "mechanism_title": description,
                    "name": entry.name,
                    "command": target or entry.path,
                    "enabled": enabled,
                    "state_changed": changed,
                    "location": {"hive": hive_label, "approved": "StartupFolder", "value": entry.name},
                },
            ))
    return evidence


def _packaged_tasks() -> list[Evidence]:
    evidence = []
    try:
        root = winreg.OpenKey(winreg.HKEY_CURRENT_USER, PACKAGED)
    except OSError:
        return evidence
    with root:
        for family in list(iter_subkeys(root)):
            try:
                family_key = winreg.OpenKey(root, family)
            except OSError:
                continue
            with family_key:
                for task_id in list(iter_subkeys(family_key)):
                    try:
                        task_key = winreg.OpenKey(family_key, task_id)
                    except OSError:
                        continue
                    with task_key:
                        state = reg_value(task_key, "State")
                        if not isinstance(state, int):
                            continue
                        evidence.append(Evidence(
                            source=NAME,
                            kind="autostart",
                            package=family,
                            label=task_id,
                            data={
                                "mechanism": "packaged_task",
                                "mechanism_title": "Store app startup task",
                                "name": task_id,
                                "command": None,
                                "enabled": state in PACKAGED_ENABLED,
                                "state": state,
                            },
                        ))
    return evidence


def collect() -> list[Evidence]:
    return _run_keys() + _startup_folders() + _packaged_tasks()
