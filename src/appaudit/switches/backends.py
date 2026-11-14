"""Where switch checks are read and written.

`RealBackend` touches Windows. `SandboxBackend` keeps every change in memory, seeded from the real
values, so the whole apply/undo path can be exercised without changing the PC.

A value that does not exist is represented by None.
"""

from __future__ import annotations

import os
import winreg

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

    # -- presence ---------------------------------------------------------------------
    def path_exists(self, path: str) -> bool:
        return os.path.exists(os.path.expandvars(path))

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
