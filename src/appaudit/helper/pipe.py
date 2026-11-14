"""Named-pipe command channel between the dashboard and the elevated helper.

The pipe's access list allows only the signed-in user and SYSTEM, so another account on the PC
cannot send commands. Each message is one JSON object; each reply is one JSON object.
"""

from __future__ import annotations

import json
from typing import Callable

import pywintypes
import win32api
import win32con
import win32file
import win32pipe
import win32security

from . import PIPE_NAME

BUFFER = 1 << 20


def current_user_sid() -> str:
    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    sid, _ = win32security.GetTokenInformation(token, win32security.TokenUser)
    return win32security.ConvertSidToStringSid(sid)


def _security(user_sid: str):
    # The medium-integrity label lets the unelevated dashboard of the same user connect to a
    # pipe created by the elevated helper; without it Windows refuses writes "upwards".
    descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        f"D:P(A;;GA;;;{user_sid})(A;;GA;;;SY)S:(ML;;NW;;;ME)", win32security.SDDL_REVISION_1)
    attributes = win32security.SECURITY_ATTRIBUTES()
    attributes.SECURITY_DESCRIPTOR = descriptor
    attributes.bInheritHandle = False
    return attributes


def serve(handle_command: Callable[[dict], dict], should_stop: Callable[[], bool], name: str = PIPE_NAME) -> None:
    """Serve one client at a time until `should_stop()` is true after a command."""
    attributes = _security(current_user_sid())
    while not should_stop():
        pipe = win32pipe.CreateNamedPipe(
            name, win32pipe.PIPE_ACCESS_DUPLEX,
            win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT
            | win32pipe.PIPE_REJECT_REMOTE_CLIENTS,
            win32pipe.PIPE_UNLIMITED_INSTANCES, BUFFER, BUFFER, 0, attributes)
        try:
            win32pipe.ConnectNamedPipe(pipe, None)
            _status, raw = win32file.ReadFile(pipe, BUFFER)
            try:
                request = json.loads(raw.decode("utf-8"))
                if not isinstance(request, dict):
                    raise ValueError("a command must be a JSON object")
                reply = handle_command(request)
            except Exception as error:  # noqa: BLE001 - report to the caller, keep serving
                reply = {"ok": False, "error": f"{type(error).__name__}: {error}"}
            win32file.WriteFile(pipe, json.dumps(reply, default=str).encode("utf-8"))
            win32file.FlushFileBuffers(pipe)
        except pywintypes.error:
            pass
        finally:
            try:
                win32pipe.DisconnectNamedPipe(pipe)
            except pywintypes.error:
                pass
            win32file.CloseHandle(pipe)


def send(command: dict, name: str = PIPE_NAME, timeout_ms: int = 4000) -> dict:
    """Send one command. Raises ConnectionError when the helper is not running."""
    try:
        win32pipe.WaitNamedPipe(name, timeout_ms)
        handle = win32file.CreateFile(name, win32con.GENERIC_READ | win32con.GENERIC_WRITE, 0, None,
                                      win32con.OPEN_EXISTING, 0, None)
    except pywintypes.error as error:
        raise ConnectionError("the helper is not running") from error
    try:
        win32pipe.SetNamedPipeHandleState(handle, win32pipe.PIPE_READMODE_MESSAGE, None, None)
        win32file.WriteFile(handle, json.dumps(command).encode("utf-8"))
        chunks = []
        while True:                                     # a reply larger than the buffer arrives in parts
            status, raw = win32file.ReadFile(handle, BUFFER)
            chunks.append(raw)
            if status != 234:                           # ERROR_MORE_DATA
                break
        return json.loads(b"".join(chunks).decode("utf-8"))
    except pywintypes.error as error:
        raise ConnectionError(f"the helper did not answer: {error}") from error
    finally:
        win32file.CloseHandle(handle)
