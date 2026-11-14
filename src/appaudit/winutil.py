"""Small Windows helpers shared by the collectors."""

from __future__ import annotations

import ctypes
import os
import shutil
import uuid
import winreg
from ctypes import wintypes
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Iterator

EPOCH_1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)
WINDIR = os.path.normpath(os.environ.get("SystemRoot", r"C:\Windows"))


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except OSError:
        return False


def filetime_to_dt(filetime: int | None) -> datetime | None:
    """Convert a Windows FILETIME (100 ns ticks since 1601) to an aware UTC datetime."""
    if not filetime or filetime <= 0:
        return None
    try:
        return EPOCH_1601 + timedelta(microseconds=filetime // 10)
    except OverflowError:
        return None


def local_naive_to_utc(value) -> datetime | None:
    """COM dates arrive as local wall-clock time; years before 2000 mean 'never'."""
    if value is None or value.year < 2000:
        return None
    naive = datetime(value.year, value.month, value.day, value.hour, value.minute, value.second)
    return naive.astimezone(timezone.utc)


# --- registry -----------------------------------------------------------------

def iter_subkeys(key) -> Iterator[str]:
    index = 0
    while True:
        try:
            yield winreg.EnumKey(key, index)
        except OSError:
            return
        index += 1


def iter_values(key) -> Iterator[tuple[str, object, int]]:
    index = 0
    while True:
        try:
            yield winreg.EnumValue(key, index)
        except OSError:
            return
        index += 1


def reg_value(key, name: str, default=None):
    try:
        return winreg.QueryValueEx(key, name)[0]
    except OSError:
        return default


# --- known folders --------------------------------------------------------------

class _GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]


_shell32 = ctypes.windll.shell32
_ole32 = ctypes.windll.ole32
_shell32.SHGetKnownFolderPath.argtypes = [
    ctypes.POINTER(_GUID), wintypes.DWORD, wintypes.HANDLE, ctypes.POINTER(ctypes.c_void_p)
]
_shell32.SHGetKnownFolderPath.restype = ctypes.c_long
_ole32.CoTaskMemFree.argtypes = [ctypes.c_void_p]
_ole32.CoTaskMemFree.restype = None


@lru_cache(maxsize=256)
def known_folder(guid_text: str) -> str | None:
    """Resolve a known-folder GUID such as {6D809377-...} to its path."""
    try:
        guid = _GUID.from_buffer_copy(uuid.UUID(guid_text).bytes_le)
    except ValueError:
        return None
    out = ctypes.c_void_p()
    if _shell32.SHGetKnownFolderPath(ctypes.byref(guid), 0, None, ctypes.byref(out)) != 0:
        return None
    try:
        return ctypes.wstring_at(out.value)
    finally:
        _ole32.CoTaskMemFree(out)


def expand_known_folder(name: str) -> str:
    """Turn '{GUID}\\rest' into a real path; other strings pass through unchanged."""
    if name.startswith("{") and "}" in name:
        guid_text, _, rest = name.partition("}")
        folder = known_folder(guid_text + "}")
        if folder:
            return folder + rest
    return name


# --- command lines and shortcuts ------------------------------------------------

def _resolve_candidate(candidate: str, must_exist: bool) -> str | None:
    candidate = candidate.strip().strip('"')
    if not candidate:
        return None
    if candidate.startswith("\\??\\"):
        candidate = candidate[4:]
    lowered = candidate.lower()
    if lowered.startswith("\\systemroot\\"):
        candidate = os.path.join(WINDIR, candidate[12:])
    elif lowered.startswith("system32\\"):
        candidate = os.path.join(WINDIR, candidate)
    if not os.path.isabs(candidate):
        found = shutil.which(candidate)
        if found:
            return os.path.normpath(found)
        return None if must_exist else candidate
    if os.path.isfile(candidate):
        return os.path.normpath(candidate)
    if os.path.isfile(candidate + ".exe"):
        return os.path.normpath(candidate + ".exe")
    return None if must_exist else os.path.normpath(candidate)


def command_to_exe(command: str | None) -> str | None:
    """Extract the executable path from a command line as stored in the registry."""
    if not command:
        return None
    command = os.path.expandvars(command.strip())
    if not command:
        return None
    if command.startswith('"'):
        end = command.find('"', 1)
        return _resolve_candidate(command[1:end] if end > 0 else command[1:], must_exist=False)
    parts = command.split(" ")
    for count in range(1, len(parts) + 1):
        resolved = _resolve_candidate(" ".join(parts[:count]), must_exist=True)
        if resolved:
            return resolved
    return _resolve_candidate(parts[0], must_exist=False)


def resolve_shortcut(path: str) -> str | None:
    """Return the target of a .lnk file, or None when it cannot be read."""
    try:
        import pythoncom
        from win32com.shell import shell

        pythoncom.CoInitialize()
        link = pythoncom.CoCreateInstance(
            shell.CLSID_ShellLink, None, pythoncom.CLSCTX_INPROC_SERVER, shell.IID_IShellLink
        )
        link.QueryInterface(pythoncom.IID_IPersistFile).Load(path)
        target, _ = link.GetPath(shell.SLGP_RAWPATH)
        target = os.path.expandvars(target or "")
        return os.path.normpath(target) if target else None
    except Exception:  # noqa: BLE001 - broken shortcuts are common and not interesting
        return None


@lru_cache(maxsize=4096)
def version_info(exe: str) -> dict[str, str]:
    """Read ProductName, CompanyName and FileDescription from an executable."""
    try:
        import win32api

        translations = win32api.GetFileVersionInfo(exe, "\\VarFileInfo\\Translation")
        lang, codepage = translations[0]
        info = {}
        for field in ("ProductName", "CompanyName", "FileDescription"):
            try:
                value = win32api.GetFileVersionInfo(exe, f"\\StringFileInfo\\{lang:04x}{codepage:04x}\\{field}")
            except Exception:  # noqa: BLE001
                value = None
            if value and value.strip():
                info[field] = value.strip()
        return info
    except Exception:  # noqa: BLE001 - many files have no version resource
        return {}
