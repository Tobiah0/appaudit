"""Say who a process really is: the app it belongs to, and for generic Windows host processes
the service, task, component or app they are running on behalf of.
"""

from __future__ import annotations

import os
import re
import winreg
from functools import lru_cache

from .explain import components
from .identity import AppRef, Resolver

HOSTS = {
    "svchost.exe": "Windows service host",
    "dllhost.exe": "COM component host",
    "rundll32.exe": "DLL runner",
    "taskhostw.exe": "Scheduled task host",
    "backgroundtaskhost.exe": "Store app background task",
    "runtimebroker.exe": "Store app permission broker",
    "msedgewebview2.exe": "Embedded browser (WebView2)",
    "conhost.exe": "Console window host",
    "wmiprvse.exe": "WMI provider host",
    "sihost.exe": "Shell infrastructure host",
    "wudfhost.exe": "User-mode driver host",
    "services.exe": "Service control manager",
    "wermgr.exe": "Windows Error Reporting",
    "compattelrunner.exe": "Microsoft Compatibility Telemetry",
    "devicecensus.exe": "Device Census (telemetry)",
}

_CLSID = re.compile(r"\{[0-9A-Fa-f-]{36}\}")
_WEBVIEW_HOST = re.compile(r"--webview-exe-name=(\S+)")
_DLL = re.compile(r"([^\s\",\\]+\.(?:dll|cpl|ocx))", re.IGNORECASE)


@lru_cache(maxsize=1024)
def service_info(name: str) -> dict:
    """Display name and Windows' own description of a service."""
    try:
        import psutil

        info = psutil.win_service_get(name).as_dict()
        return {"name": name, "title": info.get("display_name") or name, "description": info.get("description") or "",
                "start": info.get("start_type"), "account": info.get("username"), "binary": info.get("binpath")}
    except Exception:  # noqa: BLE001 - per-user services carry a suffix and may be gone
        base = re.sub(r"_[0-9a-f]{4,8}$", "", name)
        if base != name:
            found = dict(service_info(base))
            found["name"] = name
            return found
        return {"name": name, "title": name, "description": "", "start": None, "account": None, "binary": None}


@lru_cache(maxsize=512)
def com_class_name(clsid: str) -> str | None:
    for path in (rf"AppID\{clsid}", rf"CLSID\{clsid}"):
        try:
            with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, path) as key:
                value = winreg.QueryValueEx(key, "")[0]
                if value:
                    return str(value)
        except OSError:
            continue
    return None


INTERPRETERS = {"python.exe", "pythonw.exe", "py.exe", "node.exe", "java.exe", "javaw.exe", "ruby.exe", "perl.exe",
                "deno.exe", "bun.exe", "php.exe"}
_PROJECT_MARKERS = ("pyproject.toml", "package.json", "setup.py", ".git", "Cargo.toml", "pom.xml", "build.gradle")


def _args(cmdline: str) -> list[str]:
    import shlex

    try:
        return shlex.split(cmdline.replace("\\", "/"), posix=True)
    except ValueError:
        return cmdline.replace("\\", "/").split()


def _project_root(path: str) -> str | None:
    """The nearest folder above `path` that looks like a project, or None."""
    folder = os.path.dirname(os.path.normpath(path))
    for _ in range(6):
        if not folder or os.path.dirname(folder) == folder:
            return None
        if any(os.path.exists(os.path.join(folder, marker)) for marker in _PROJECT_MARKERS):
            return folder
        folder = os.path.dirname(folder)
    return None


def script_identity(exe: str, cmdline: str) -> dict | None:
    """What an interpreter (Python, Node, Java...) is running: the program a person would name.

    "python.exe" says nothing: the same interpreter runs this tool, a project's local server and
    one-off scripts. The actor becomes the module, script or project instead.
    """
    text = (cmdline or "").lower().replace("\\", "/")
    exe_text = (exe or "").lower().replace("\\", "/")
    if "appaudit" in text or "/hackathon/.venv/" in exe_text and ("-m appaudit" in text or "uvicorn" in text):
        return {"id": "self:appaudit", "name": "App Audit (this tool)", "kind": "self", "is_system": False,
                "role": "This tool: the dashboard or the watcher", "publisher": None}
    if "/temp/claude/" in text and "/scratchpad" in text:
        return {"id": "script:claude-code", "name": "Scripts run by Claude Code", "kind": "script", "is_system": False,
                "role": "Developer tool: scripts an AI coding assistant ran on this PC", "publisher": None}
    args = _args(cmdline)[1:]
    module = None
    script = None
    for index, arg in enumerate(args):
        if arg == "-m" and index + 1 < len(args):
            module = args[index + 1]
            break
        if arg in ("-c", "-"):
            break
        if not arg.startswith("-"):
            script = arg
            break
    venv = None
    if "/.venv/" in exe_text or "/venv/" in exe_text:
        venv = exe.replace("\\", "/").lower().split("/.venv/")[0].split("/venv/")[0]
    root = venv or (_project_root(script) if script and os.path.isabs(script) else None)
    if module:
        label = module.split(".")[0]
        project = os.path.basename(root.rstrip("/\\")) if root else None
        name = f"{label} ({project})" if project and project.lower() != label.lower() else label
        return {"id": f"script:module:{label.lower()}:{(project or '').lower()}", "name": f"Python program: {name}",
                "kind": "script", "is_system": False, "role": "Script or local program", "publisher": None}
    if root:
        project = os.path.basename(os.path.normpath(root))
        return {"id": f"script:project:{os.path.normcase(root)}", "name": f"Project: {project}", "kind": "script",
                "is_system": False, "role": "Script or local program", "publisher": None}
    if script:
        base = os.path.basename(script)
        return {"id": f"script:file:{base.lower()}", "name": f"Script: {base}", "kind": "script", "is_system": False,
                "role": "Script or local program", "publisher": None}
    return None


class Attributor:
    def __init__(self, resolver: Resolver | None = None) -> None:
        self.resolver = resolver or Resolver()
        self._cache: dict[tuple, dict] = {}

    def app_for_exe(self, exe: str | None, name: str | None = None) -> AppRef:
        if not exe and (not name or name.startswith("pid ")):
            # Ended before the watcher could read its name. One honest group instead of a row per id.
            return AppRef(id="proc:unidentified", name="Programs that ended before they could be identified",
                          kind="unknown", is_system=False)
        if not exe:
            label = name or "Unknown process"
            return AppRef(id="proc:" + label.lower(), name=label, kind="system", is_system=True)
        try:
            return self.resolver._exe_ref(exe)
        except Exception:  # noqa: BLE001 - a path we cannot read still gets a row
            return AppRef(id="exe:" + exe.lower(), name=os.path.basename(exe))

    def actor(self, proc: dict) -> dict:
        """Describe one process run. `proc` is a row from the live database."""
        key = (proc.get("exe"), proc.get("services"), proc.get("task"), proc.get("package"),
               self._cmdline_key(proc))
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        result = self._describe(proc)
        self._cache[key] = result
        return result

    @staticmethod
    def _cmdline_key(proc: dict) -> str | None:
        name = (proc.get("name") or "").lower()
        if name in ("dllhost.exe", "rundll32.exe", "msedgewebview2.exe", "backgroundtaskhost.exe") or name in INTERPRETERS:
            return proc.get("cmdline")
        return None

    def _describe(self, proc: dict) -> dict:
        name = proc.get("name") or ""
        lowered = name.lower()
        exe = proc.get("exe")
        app = self.app_for_exe(exe, name)
        actor = {"id": app.id, "name": app.name, "publisher": app.publisher, "kind": app.kind,
                 "is_system": app.is_system, "process": name, "role": None, "on_behalf_of": None,
                 "services": [], "task": proc.get("task"), "host": HOSTS.get(lowered)}
        note = components.note(name) or {}
        actor.update(about=note.get("what"), needed=note.get("needed"), reports=bool(note.get("reports")))
        cmdline = proc.get("cmdline") or ""

        if lowered == "svchost.exe" and proc.get("services"):
            services = [service_info(item) for item in proc["services"].split(",") if item]
            actor["services"] = services
            first = services[0]
            actor["id"] = "svc:" + ",".join(sorted(item["name"].lower() for item in services))
            actor["name"] = first["title"] if len(services) == 1 else f"{first['title']} and {len(services) - 1} more"
            actor["role"] = "Windows service" if len(services) == 1 else "Windows services"
            actor["publisher"] = "Microsoft Windows"
        elif lowered == "dllhost.exe":
            match = _CLSID.search(cmdline)
            label = com_class_name(match.group(0)) if match else None
            if label:
                actor["id"] = "com:" + match.group(0).lower()
                actor["name"] = label
                actor["role"] = "COM component"
        elif lowered == "rundll32.exe":
            match = _DLL.search(cmdline.split("rundll32", 1)[-1])
            if match:
                actor["id"] = "dll:" + match.group(1).lower()
                actor["name"] = f"{match.group(1)} (run by rundll32)"
                actor["role"] = "DLL run directly"
        elif lowered == "msedgewebview2.exe":
            match = _WEBVIEW_HOST.search(cmdline)
            if match:
                actor["on_behalf_of"] = match.group(1).strip('"')
        elif lowered in INTERPRETERS:
            script = script_identity(exe or "", cmdline)
            if script:
                actor.update(script)
        elif lowered == "backgroundtaskhost.exe" and proc.get("package"):
            ref = self.resolver._package_ref(_family_from_full_name(proc["package"]))
            actor.update(id=ref.id, name=ref.name, publisher=ref.publisher, kind=ref.kind, is_system=ref.is_system,
                         role="Store app background task")

        if proc.get("task"):
            actor["role"] = actor["role"] or "Scheduled task"
        if actor["on_behalf_of"] is None and proc.get("parent_exe") and lowered in ("conhost.exe", "msedgewebview2.exe"):
            actor["on_behalf_of"] = os.path.basename(proc["parent_exe"])
        return actor


def _family_from_full_name(full_name: str) -> str:
    """Name_1.2.3.4_x64__publisherid -> Name_publisherid."""
    parts = full_name.split("_")
    return f"{parts[0]}_{parts[-1]}" if len(parts) >= 5 else full_name
