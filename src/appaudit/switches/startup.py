"""Startup switches: "stop it starting by itself", generated from the inventory's startup entries.

For an app's own startup entries:

  Run key / Startup folder  the StartupApproved flag Task Manager writes (the Run value stays, so
                            the person can switch it back on in Task Manager too)
  service                   start type "manual": it still starts when the app asks for it
  scheduled task            disabled

Left out on purpose: updaters (stopping them stops security updates), anything that runs from the
Windows folder or the Store's app folder, and programs on the never-stop list.

The inventory lives in a file the user's programs can write, and these switches may be applied by
the elevated helper. So names are only trusted after checking the real system: a service must
exist and run a program outside the Windows folder; a task must exist outside \\Microsoft\\.
"""

from __future__ import annotations

import os
import re

UPDATER = re.compile(r"update|updater|upgrade", re.IGNORECASE)
# Hardware helpers: set to manual, audio, Bluetooth or display features can stop working.
HARDWARE = re.compile(r"audio|bluetooth|display|graphics|driver|chipset|nvme|power|v-cache|provision|realtek|"
                      r"amd|intel|controller|gameinput|input|sensor|firmware|thunderbolt|wlan|wifi|ethernet", re.IGNORECASE)
WINDIR = os.path.normcase(os.environ.get("WINDIR", r"C:\Windows"))
STORE_APPS = os.path.normcase(os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "WindowsApps"))
APPROVED_SUBKEYS = {"Run", "Run32", "StartupFolder"}


def _exe_of(command: str) -> str:
    from ..winutil import command_to_exe

    try:
        return command_to_exe(command) or ""
    except Exception:  # noqa: BLE001
        return ""


def _protected_path(exe: str) -> bool:
    from .. import blocking

    path = os.path.normcase(exe or "")
    return (not path or path.startswith(WINDIR + os.sep) or path.startswith(STORE_APPS + os.sep)
            or bool(blocking.never_stop(os.path.basename(exe))))


def _service_ok(name: str) -> bool:
    """The service exists and runs a program outside the Windows and Store folders."""
    try:
        import win32service

        manager = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
        try:
            handle = win32service.OpenService(manager, name, win32service.SERVICE_QUERY_CONFIG)
            try:
                binary = win32service.QueryServiceConfig(handle)[3]
            finally:
                win32service.CloseServiceHandle(handle)
        finally:
            win32service.CloseServiceHandle(manager)
    except Exception:  # noqa: BLE001 - missing, or not readable
        return False
    return not _protected_path(_exe_of(binary))


def checks_for(entry: dict, service_ok=_service_ok, publisher: str = "") -> dict | None:
    """One check for one inventory startup entry, or None when it should be left alone."""
    mechanism = entry.get("mechanism")
    command = entry.get("command") or ""
    name = entry.get("name") or ""
    if not name or UPDATER.search(name) or UPDATER.search(command):
        return None
    if _protected_path(_exe_of(command)):
        return None
    if mechanism in ("run_key", "startup_folder"):
        location = entry.get("location") or {}
        hive, approved = location.get("hive"), location.get("approved")
        if hive not in ("HKCU", "HKLM") or approved not in APPROVED_SUBKEYS:
            return None
        return {"type": "startup_approved", "hive": hive, "approved": approved, "value": name, "private": "disabled"}
    if mechanism == "service":
        if re.search(r"microsoft|windows|xbox", publisher or "", re.IGNORECASE) or re.search(r"xbox", name, re.IGNORECASE)                 or HARDWARE.search(name) or HARDWARE.search(entry.get("display_name") or ""):
            return None                              # Windows' own services and hardware helpers are left alone
        return {"type": "service", "name": name, "private": ["manual", "disabled"]} if service_ok(name) else None
    if mechanism == "task":
        path = entry.get("path") or ""
        if not path.startswith("\\") or path.lower().startswith("\\microsoft\\"):
            return None
        return {"type": "task", "path": path, "private": "disabled"}
    return None


def load(apps: list[dict] | None = None, service_ok=_service_ok) -> list:
    """Startup switches for every non-Windows app in the latest inventory that starts by itself."""
    from . import build_switch

    if apps is None:
        try:
            from .. import store

            latest = store.latest_scan()
            apps = store.load_apps(latest["id"]) if latest else []
        except Exception:  # noqa: BLE001 - no inventory yet
            apps = []
    found = []
    for app in apps:
        if app.get("is_system") or not app.get("autostart"):
            continue
        if not any(finding.get("code") == "starts_unused" for finding in app.get("findings") or []):
            continue                                 # only apps that start by themselves while you do not use them
        checks, programs, entry_names = [], set(), []
        for entry in app["autostart"]:
            check = checks_for(entry, service_ok, f"{app.get('publisher') or ''} {app.get('name') or ''}")
            if check:
                checks.append(check)
                entry_names.append(entry.get("display_name") or entry.get("name") or "")
                exe = _exe_of(entry.get("command") or "")
                if exe:
                    programs.add(os.path.basename(exe))
        if not checks:
            continue
        for check in checks:
            check["apps"] = sorted(programs)
        label = app.get("name") or ", ".join(entry_names[:2])
        words = re.findall(r"[a-z]{3,}", label.lower())
        if entry_names and not any(word in re.sub(r"[^a-z]", "", entry.lower()) for entry in entry_names for word in words):
            label = f"{entry_names[0]} (listed under {label})"     # the inventory grouped it under another app
        try:
            found.append(build_switch({
                "id": f"startup.{re.sub(r'[^a-z0-9]+', '-', app['id'].lower()).strip('-')}",
                "title": f"{label} starting by itself",
                "group": "Startup (from the inventory)",
                "explain": f"Stops {label} starting when you sign in or in the background. It still starts when you open it. "
                           f"Entries: {', '.join(entry_names)}.",
                "breaks": "Anything it does in the background (syncing, notifications, tray icon) waits until you open it.",
                "risk": "medium" if any(c["type"] == "service" for c in checks) else "low",
                "checks": checks,
            }, "Startup (from the inventory)", origin="startup"))
        except (ValueError, KeyError):
            continue
    return found
