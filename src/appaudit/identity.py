"""Group executables, packages and loose names into apps the user would recognise.

Order of preference: Store package, installed program (Uninstall keys), a folder
heuristic under the usual install roots, and finally the executable itself.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import winreg
from dataclasses import dataclass

from .collectors import Evidence
from .winutil import WINDIR, iter_subkeys, reg_value, resolve_shortcut, version_info

# Version resources that name Windows itself instead of a product.
GENERIC_PRODUCTS = {"microsoft® windows® operating system", "microsoft windows operating system"}
PACKAGE_FOLDER = re.compile(r"\\windowsapps\\([^\\]+)\\")

UNINSTALL = r"Software\Microsoft\Windows\CurrentVersion\Uninstall"
UNINSTALL_ROOTS = [
    (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_64KEY),
    (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_32KEY),
    (winreg.HKEY_CURRENT_USER, 0),
]

# Folders that hold several unrelated products, so the app is one level deeper.
VENDOR_FOLDERS = {
    "microsoft", "google", "common files", "adobe", "mozilla", "intel", "amd", "nvidia corporation",
    "nvidia", "jetbrains", "microsoft shared", "programs", "apple", "oracle", "hp", "dell", "lenovo",
    "asus", "msi", "razer", "logitech", "corsair", "steam", "epic games",
}

PACKAGE_QUERY = (
    "[Console]::OutputEncoding=[Text.Encoding]::UTF8; "
    "$p = Get-AppxPackage | Select-Object Name, PackageFamilyName, InstallLocation, Publisher, IsFramework, "
    "@{n='Sig';e={$_.SignatureKind.ToString()}}; "
    "$s = Get-StartApps | Select-Object Name, AppID; "
    "@{packages=@($p); start=@($s)} | ConvertTo-Json -Depth 3 -Compress"
)


@dataclass(frozen=True)
class AppRef:
    id: str
    name: str
    publisher: str | None = None
    kind: str = "desktop"          # desktop | store | system
    is_system: bool = False
    install_dir: str | None = None


def _norm(path: str) -> str:
    return os.path.normcase(os.path.normpath(path))


def _env_dirs(*names: str) -> list[str]:
    return [_norm(os.environ[name]) for name in names if os.environ.get(name)]


def _split_camel(text: str) -> str:
    return re.sub(r"(?<=[a-z])(?=[A-Z])", " ", text).strip()


def _publisher_cn(distinguished: str | None) -> str | None:
    match = re.search(r"CN=([^,]+)", distinguished or "")
    if not match:
        return None
    name = match.group(1).strip().strip('"')
    return None if re.fullmatch(r"[0-9A-Fa-f-]{36}", name) else name


class Resolver:
    def __init__(self) -> None:
        self.windir = _norm(WINDIR)
        local = os.environ.get("LOCALAPPDATA", "")
        self.user_packages = _norm(os.path.join(local, "Packages")) if local else None
        self.generic = set(_env_dirs(
            "SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "ProgramData", "USERPROFILE",
            "LOCALAPPDATA", "APPDATA", "CommonProgramFiles", "CommonProgramFiles(x86)",
        ))
        if local:
            self.generic.add(_norm(os.path.join(local, "Programs")))
        # Install roots for the folder heuristic, most specific first.
        self.roots = []
        if local:
            self.roots.append(_norm(os.path.join(local, "Programs")))
        self.roots += _env_dirs("ProgramW6432", "ProgramFiles", "ProgramFiles(x86)", "ProgramData", "LOCALAPPDATA", "APPDATA")
        self.roots = list(dict.fromkeys(self.roots))

        self.programs = self._load_programs()
        self.program_dirs = sorted(
            ((p["dir_key"], p) for p in self.programs if p["dir_key"]), key=lambda item: -len(item[0])
        )
        self.program_names = {p["name"].casefold(): p for p in self.programs}
        self.packages, self.package_dirs, self.start_names, self.aumid_names = self._load_packages()
        self._cache: dict[str, AppRef] = {}
        self.start_menu = self._load_start_menu()
        # Apps the user can open from the Start menu, as opposed to background components.
        self.launchable = {self._exe_ref(target).id for target in self.start_menu.values()}
        self.launchable |= {"pkg:" + family for family in self.start_names}

    # --- loading ------------------------------------------------------------------

    def _usable_dir(self, folder: str) -> bool:
        key = _norm(folder)
        if key in self.generic or key.startswith(self.windir + os.sep) or key == self.windir:
            return False
        return len(key.rstrip("\\").split("\\")) >= 2

    def _load_programs(self) -> list[dict]:
        programs = []
        for hive, view in UNINSTALL_ROOTS:
            try:
                root = winreg.OpenKey(hive, UNINSTALL, 0, winreg.KEY_READ | view)
            except OSError:
                continue
            with root:
                for sub in list(iter_subkeys(root)):
                    try:
                        key = winreg.OpenKey(root, sub)
                    except OSError:
                        continue
                    with key:
                        name = reg_value(key, "DisplayName")
                        if not isinstance(name, str) or not name.strip():
                            continue
                        folder = str(reg_value(key, "InstallLocation") or "").strip().strip('"')
                        if not folder:
                            icon = str(reg_value(key, "DisplayIcon") or "").split(",")[0].strip().strip('"')
                            if icon.lower().endswith(".exe"):
                                folder = os.path.dirname(icon)
                        folder = os.path.expandvars(folder)
                        usable = bool(folder) and self._usable_dir(folder)
                        programs.append({
                            "key": sub,
                            "name": name.strip(),
                            "publisher": (reg_value(key, "Publisher") or None),
                            "install_dir": os.path.normpath(folder) if usable else None,
                            "dir_key": _norm(folder) + os.sep if usable else None,
                        })
        return programs

    def _load_packages(self):
        packages: dict[str, dict] = {}
        package_dirs: list[tuple[str, str]] = []
        start_names: dict[str, str] = {}
        aumid_names: dict[str, str] = {}
        try:
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", PACKAGE_QUERY],
                capture_output=True, timeout=90, creationflags=subprocess.CREATE_NO_WINDOW,
            )
            payload = json.loads(proc.stdout.decode("utf-8", errors="replace") or "{}")
        except (OSError, subprocess.TimeoutExpired, ValueError):
            payload = {}
        for package in payload.get("packages") or []:
            family = (package.get("PackageFamilyName") or "").lower()
            if not family:
                continue
            packages[family] = package
            if package.get("InstallLocation"):
                package_dirs.append((_norm(package["InstallLocation"]) + os.sep, family))
        for entry in payload.get("start") or []:
            app_id, name = entry.get("AppID") or "", entry.get("Name") or ""
            if not app_id or not name:
                continue
            aumid_names[app_id.lower()] = name
            if "!" in app_id:
                start_names.setdefault(app_id.split("!", 1)[0].lower(), name)
        package_dirs.sort(key=lambda item: -len(item[0]))
        return packages, package_dirs, start_names, aumid_names

    @staticmethod
    def _load_start_menu() -> dict[str, str]:
        """Map Start menu shortcut names to the executables they launch."""
        shortcuts: dict[str, str] = {}
        for base in ("APPDATA", "ProgramData"):
            folder = os.path.join(os.environ.get(base, ""), r"Microsoft\Windows\Start Menu\Programs")
            for current, _dirs, files in os.walk(folder):
                for filename in files:
                    stem, extension = os.path.splitext(filename)
                    if extension.lower() != ".lnk" or "uninstall" in stem.lower():
                        continue
                    target = resolve_shortcut(os.path.join(current, filename))
                    if target and target.lower().endswith(".exe") and os.path.isfile(target):
                        shortcuts.setdefault(stem.casefold(), target)
        return shortcuts

    # --- resolving ------------------------------------------------------------------

    def _package_ref(self, family: str) -> AppRef:
        key = family.lower()
        package = self.packages.get(key)
        raw_name = package["Name"] if package else family.split("_")[0]
        name = self.start_names.get(key) or _split_camel(raw_name.split(".")[-1]) or raw_name
        is_system = bool(package and (package.get("Sig") == "System" or package.get("IsFramework")))
        return AppRef(
            id="pkg:" + key,
            name=name,
            publisher=_publisher_cn(package.get("Publisher")) if package else None,
            kind="system" if is_system else "store",
            is_system=is_system,
            install_dir=package.get("InstallLocation") if package else None,
        )

    def _exe_ref(self, exe: str) -> AppRef:
        key = _norm(exe)

        for folder, family in self.package_dirs:
            if key.startswith(folder):
                return self._package_ref(family)
        # Store apps live in a WindowsApps folder on any drive, named
        # Name_Version_Arch_Resource_PublisherId (or just Name_PublisherId for aliases).
        match = PACKAGE_FOLDER.search(key)
        if match:
            parts = match.group(1).split("_")
            if len(parts) >= 5:
                return self._package_ref(f"{parts[0]}_{parts[-1]}")
            if len(parts) == 2:
                return self._package_ref(match.group(1))
        if self.user_packages and key.startswith(self.user_packages + os.sep):
            return self._package_ref(key[len(self.user_packages) + 1:].split("\\")[0])

        info = dict(version_info(exe))
        base = os.path.basename(exe)
        windows_component = (info.get("ProductName") or "").casefold() in GENERIC_PRODUCTS
        if windows_component:
            del info["ProductName"]
        if key.startswith(self.windir + os.sep):
            return AppRef(
                id="exe:" + key,
                name=info.get("FileDescription") or base,
                publisher=info.get("CompanyName"),
                kind="system",
                is_system=True,
            )

        for folder, program in self.program_dirs:
            if key.startswith(folder):
                return self._program_ref(program, program["install_dir"])

        for root in self.roots:
            if not key.startswith(root + os.sep):
                continue
            parts = key[len(root) + 1:].split("\\")
            if len(parts) < 2:
                break  # the executable sits directly in the root
            depth = 2 if parts[0] in VENDOR_FOLDERS and len(parts) >= 3 else 1
            group_dir = os.path.join(root, *parts[:depth])
            real_dir = os.path.normpath(exe)[: len(group_dir)]
            folder_name = os.path.basename(real_dir)
            for candidate in (info.get("ProductName"), folder_name):
                program = self.program_names.get((candidate or "").casefold())
                if program:
                    return self._program_ref(program, real_dir)
            return AppRef(
                id="dir:" + group_dir,
                name=info.get("ProductName") or folder_name,
                publisher=info.get("CompanyName"),
                kind="system" if windows_component else "desktop",
                is_system=windows_component,
                install_dir=real_dir,
            )

        return AppRef(
            id="exe:" + key,
            name=info.get("ProductName") or info.get("FileDescription") or base,
            publisher=info.get("CompanyName"),
            kind="system" if windows_component else "desktop",
            is_system=windows_component,
            install_dir=os.path.dirname(exe),
        )

    @staticmethod
    def _program_ref(program: dict, install_dir: str | None) -> AppRef:
        return AppRef(
            id="inst:" + program["key"].lower(),
            name=program["name"],
            publisher=program["publisher"],
            install_dir=install_dir,
        )

    def resolve(self, evidence: Evidence) -> AppRef:
        if evidence.package:
            cache_key = "pkg|" + evidence.package.lower()
        elif evidence.exe:
            cache_key = "exe|" + _norm(evidence.exe)
        else:
            cache_key = f"name|{evidence.kind}|{(evidence.label or '').lower()}"
        cached = self._cache.get(cache_key)
        if cached:
            return cached

        if evidence.package:
            ref = self._package_ref(evidence.package)
        elif evidence.exe:
            ref = self._exe_ref(evidence.exe)
        else:
            label = evidence.label or "Unknown"
            aumid = (evidence.data.get("aumid") or "").lower()
            friendly = self.aumid_names.get(aumid)
            name = friendly or label
            program = self.program_names.get(name.casefold())
            target = self.start_menu.get(name.casefold())
            if target:
                ref = self._exe_ref(target)
            elif program:
                ref = self._program_ref(program, program["install_dir"])
            elif evidence.kind == "process":
                # Windows hides the path of protected system processes from normal users.
                ref = AppRef(id="proc:" + label.lower(), name=label, kind="system", is_system=True)
            elif aumid and not friendly:
                # An internal app ID with no Start menu name; nothing useful to show.
                ref = AppRef(id="name:" + name.casefold(), name=name, kind="unknown", is_system=True)
            else:
                ref = AppRef(id="name:" + name.casefold(), name=name)
        self._cache[cache_key] = ref
        return ref
