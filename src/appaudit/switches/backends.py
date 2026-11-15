"""Where switch checks are read and written.

`RealBackend` touches Windows. `SandboxBackend` keeps every change in memory, seeded from the real
values, so the whole apply/undo path can be exercised without changing the PC.

A value that does not exist is represented by None.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import time
import winreg
from functools import lru_cache
from pathlib import Path

from ..store import data_dir


def _ttl_bucket(seconds: int = 60) -> int:
    return int(time.time() // seconds)


@lru_cache(maxsize=2)
def _known_processes_at(_bucket: int) -> frozenset[str]:
    import psutil

    names = {(process.info.get("name") or "").lower() for process in psutil.process_iter(["name"])}
    try:
        from .. import livestore

        conn = livestore.connect(readonly=True)
        try:
            names |= {row[0].lower() for row in conn.execute("SELECT DISTINCT name FROM procs") if row[0]}
        finally:
            conn.close()
    except Exception:  # noqa: BLE001 - the watcher may never have run
        pass
    return frozenset(names - {""})


def _known_processes() -> frozenset[str]:
    return _known_processes_at(_ttl_bucket())

HIVES = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}
KINDS = {"dword": winreg.REG_DWORD, "string": winreg.REG_SZ, "qword": winreg.REG_QWORD}
ENVIRONMENT = r"Environment"
MACHINE_ENVIRONMENT = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"


class RealBackend:
    name = "real"

    # -- registry ---------------------------------------------------------------------
    def registry_get(self, hive: str, key: str, value: str):
        try:
            with winreg.OpenKey(HIVES[hive], key, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as handle:
                return winreg.QueryValueEx(handle, value)[0]
        except FileNotFoundError:
            return None

    def registry_set(self, hive: str, key: str, value: str, data, kind: str = "dword") -> None:
        access = winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY
        if data is None:
            try:
                with winreg.OpenKey(HIVES[hive], key, 0, access) as handle:
                    winreg.DeleteValue(handle, value)
            except FileNotFoundError:
                pass
            return
        with winreg.CreateKeyEx(HIVES[hive], key, 0, access) as handle:
            winreg.SetValueEx(handle, value, 0, KINDS[kind], data)

    # -- services ---------------------------------------------------------------------
    def service_get(self, name: str):
        import psutil

        try:
            return psutil.win_service_get(name).start_type()
        except Exception:  # noqa: BLE001 - not installed
            return None

    def service_set(self, name: str, start_type: str) -> None:
        import win32service

        codes = {"disabled": win32service.SERVICE_DISABLED, "manual": win32service.SERVICE_DEMAND_START,
                 "automatic": win32service.SERVICE_AUTO_START}
        manager = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
        try:
            handle = win32service.OpenService(manager, name, win32service.SERVICE_CHANGE_CONFIG
                                              | win32service.SERVICE_STOP | win32service.SERVICE_QUERY_STATUS)
            try:
                win32service.ChangeServiceConfig(handle, win32service.SERVICE_NO_CHANGE, codes[start_type],
                                                 win32service.SERVICE_NO_CHANGE, None, None, 0, None, None, None, None)
                if start_type == "disabled":
                    try:
                        win32service.ControlService(handle, win32service.SERVICE_CONTROL_STOP)
                    except Exception:  # noqa: BLE001 - already stopped, or it refuses to stop
                        pass
            finally:
                win32service.CloseServiceHandle(handle)
        finally:
            win32service.CloseServiceHandle(manager)

    # -- scheduled tasks ----------------------------------------------------------------
    def _task(self, path: str):
        import pythoncom
        import win32com.client

        pythoncom.CoInitialize()
        scheduler = win32com.client.Dispatch("Schedule.Service")
        scheduler.Connect()
        folder, _, name = path.rpartition("\\")
        return scheduler.GetFolder(folder or "\\").GetTask(name)

    def task_get(self, path: str):
        try:
            return "enabled" if self._task(path).Enabled else "disabled"
        except Exception:  # noqa: BLE001 - the task does not exist on this PC
            return None

    def task_set(self, path: str, state: str) -> None:
        self._task(path).Enabled = state == "enabled"

    # -- user environment variables ---------------------------------------------------
    def env_get(self, name: str):
        """The user value, or the machine-wide value when the user has none."""
        value = self.registry_get("HKCU", ENVIRONMENT, name)
        if value is None:
            value = self.registry_get("HKLM", MACHINE_ENVIRONMENT, name)
        return value

    def env_set(self, name: str, data) -> None:
        self.registry_set("HKCU", ENVIRONMENT, name, data, "string")
        try:                                   # tell running programs the environment changed
            import win32con
            import win32gui

            win32gui.SendMessageTimeout(win32con.HWND_BROADCAST, win32con.WM_SETTINGCHANGE, 0, "Environment",
                                        win32con.SMTO_ABORTIFHUNG, 2000)
        except Exception:  # noqa: BLE001
            pass

    # -- app config files -----------------------------------------------------------
    # Text is read and written with the file's own encoding (UTF-8, with its byte-order mark kept
    # if it had one). Writes go to a temporary file in the same folder that then replaces the
    # original, so a crash mid-write cannot leave a half-written settings file.
    def expand(self, path: str) -> str:
        expanded = os.path.normpath(os.path.expandvars(path))
        if "%" in expanded:
            raise ValueError(f"unknown folder in {path}")
        return expanded

    def file_read(self, path: str) -> str | None:
        try:
            raw = Path(path).read_bytes()
        except FileNotFoundError:
            return None
        if raw.startswith(b"\xef\xbb\xbf"):
            return raw[3:].decode("utf-8")
        if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
            return raw.decode("utf-16")
        return raw.decode("utf-8")

    def file_write(self, path: str, text: str) -> None:
        target = Path(path)
        if not target.parent.is_dir():
            raise FileNotFoundError(f"the app's folder does not exist: {target.parent}")
        try:
            head = target.read_bytes()[:3]
        except FileNotFoundError:
            head = b""
        if head.startswith((b"\xff\xfe", b"\xfe\xff")):
            data = text.encode("utf-16")
        else:
            data = (b"\xef\xbb\xbf" if head == b"\xef\xbb\xbf" else b"") + text.encode("utf-8")
        handle, temporary = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".appaudit", dir=target.parent)
        try:
            with os.fdopen(handle, "wb") as file:
                file.write(data)
            os.replace(temporary, target)
        except BaseException:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise

    def file_backup(self, path: str) -> str | None:
        """Copy the whole file to the backup folder. None when there is no file yet."""
        source = Path(path)
        if not source.exists():
            return None
        folder = data_dir() / "backups"
        folder.mkdir(parents=True, exist_ok=True)
        target = folder / f"{time.strftime('%Y%m%d-%H%M%S')}-{source.parent.name}-{source.name}"
        counter = 1
        while target.exists():
            target = target.with_name(f"{target.stem}-{counter}{target.suffix}")
            counter += 1
        shutil.copy2(source, target)
        return str(target)

    def file_restore(self, path: str, backup: str) -> None:
        folder = (data_dir() / "backups").resolve()
        source = Path(backup).resolve()
        if folder not in source.parents:
            raise ValueError("a backup must come from the backup folder")
        shutil.copy2(source, path)

    def file_remove(self, path: str) -> None:
        Path(path).unlink(missing_ok=True)

    # -- programs ---------------------------------------------------------------------
    def running(self, names: list[str]) -> set[str]:
        """Which of these program names are running now."""
        if not names:
            return set()
        import psutil

        wanted = {name.lower() for name in names}
        found = set()
        for process in psutil.process_iter(["name"]):
            name = (process.info.get("name") or "").lower()
            if name in wanted:
                found.add(process.info["name"])
        return found

    def known_processes(self) -> set[str]:
        """Programs running now or seen by the watcher: evidence that an app is installed and used."""
        return _known_processes()

    # -- startup entries (Task Manager's StartupApproved flag) --------------------------
    # The value is 12 bytes: 02 enabled / 03 disabled, padding, then when it was switched. It is
    # handled as a hex string so the journal can put back exactly what was there.
    APPROVED = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved"

    def startup_get(self, hive: str, approved: str, name: str):
        try:
            with winreg.OpenKey(HIVES[hive], self.APPROVED + "\\" + approved, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as handle:
                data = winreg.QueryValueEx(handle, name)[0]
        except FileNotFoundError:
            return None
        return bytes(data).hex() if data else None

    def startup_set(self, hive: str, approved: str, name: str, value) -> None:
        if value == "disabled":
            stamp = int((time.time() + 11644473600) * 10_000_000).to_bytes(8, "little")
            data = bytes([3, 0, 0, 0]) + stamp
        elif value is None:
            try:
                with winreg.OpenKey(HIVES[hive], self.APPROVED + "\\" + approved, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as handle:
                    winreg.DeleteValue(handle, name)
            except FileNotFoundError:
                pass
            return
        else:
            data = bytes.fromhex(str(value))
        with winreg.CreateKeyEx(HIVES[hive], self.APPROVED + "\\" + approved, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as handle:
            winreg.SetValueEx(handle, name, 0, winreg.REG_BINARY, data)

    # -- presence ---------------------------------------------------------------------
    def path_exists(self, path: str) -> bool:
        return os.path.exists(os.path.expandvars(path))

    def glob_exists(self, pattern: str) -> bool:
        import glob

        return bool(glob.glob(os.path.expandvars(pattern)))

    def registry_key_exists(self, hive: str, key: str) -> bool:
        try:
            winreg.CloseKey(winreg.OpenKey(HIVES[hive], key, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY))
            return True
        except OSError:
            return False


class SandboxBackend(RealBackend):
    """Reads fall through to the real PC until a value has been written; writes stay in memory."""

    name = "sandbox"

    def __init__(self) -> None:
        self.written: dict[tuple, object] = {}
        self.log: list[tuple] = []

    def _read(self, key: tuple, real):
        return self.written[key] if key in self.written else real()

    def _write(self, key: tuple, data) -> None:
        self.written[key] = data
        self.log.append((key, data))

    def registry_get(self, hive, key, value):
        return self._read(("registry", hive, key.lower(), value.lower()),
                          lambda: RealBackend.registry_get(self, hive, key, value))

    def registry_set(self, hive, key, value, data, kind="dword"):
        self._write(("registry", hive, key.lower(), value.lower()), data)

    def service_get(self, name):
        return self._read(("service", name.lower()), lambda: RealBackend.service_get(self, name))

    def service_set(self, name, start_type):
        self._write(("service", name.lower()), start_type)

    def task_get(self, path):
        return self._read(("task", path.lower()), lambda: RealBackend.task_get(self, path))

    def task_set(self, path, state):
        self._write(("task", path.lower()), state)

    def env_get(self, name):
        return self._read(("env", name.lower()), lambda: RealBackend.env_get(self, name))

    def env_set(self, name, data):
        self._write(("env", name.lower()), data)

    def startup_get(self, hive, approved, name):
        return self._read(("startup", hive, approved, name.lower()), lambda: RealBackend.startup_get(self, hive, approved, name))

    def startup_set(self, hive, approved, name, value):
        self._write(("startup", hive, approved, name.lower()), "03000000" + "00" * 8 if value == "disabled" else value)

    # Files: reads fall through to the real file; writes, backups and removals stay in memory.
    def file_read(self, path):
        return self._read(("file", path.lower()), lambda: RealBackend.file_read(self, path))

    def file_write(self, path, text):
        self._write(("file", path.lower()), text)

    def file_backup(self, path):
        text = self.file_read(path)
        if text is None:
            return None
        key = f"sandbox-backup-{len(self.log)}"
        self.backups = getattr(self, "backups", {})
        self.backups[key] = text
        return key

    def file_restore(self, path, backup):
        self._write(("file", path.lower()), self.backups[backup])

    def file_remove(self, path):
        self._write(("file", path.lower()), None)
