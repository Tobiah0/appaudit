"""The helper takes changes only from App Audit's dashboard; anyone running as the user may read."""

import pytest

from appaudit.helper.commands import Commands
from appaudit.helper.pipe import is_dashboard

VENV = r"D:\dev\HackaThon\.venv\Scripts"


@pytest.mark.parametrize("exe, cmdline, expected", [
    (VENV + r"\python.exe", [VENV + r"\python.exe", VENV + r"\appaudit.exe", "--no-browser"], True),
    (r"C:\py\python.exe", [r"C:\py\python.exe", "-m", "uvicorn", "appaudit.api:app"], True),
    (r"C:\py\python.exe", [r"C:\py\python.exe", "evil.py"], False),
    (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", ["powershell", "-c", "appaudit.api"], False),
    (r"C:\py\python.exe", [r"C:\py\python.exe", "-c", "print('appaudit')"], False),
])
def test_dashboard_is_recognised(exe, cmdline, expected):
    assert is_dashboard(exe, cmdline) is expected


def test_changes_need_the_dashboard_and_reads_do_not():
    commands = Commands(capture=None)
    commands._table["trace_sessions"] = lambda request: {"sessions": []}
    stranger = {"pid": 4242, "dashboard": False}
    refused = commands.handle({"cmd": "switch_apply", "id": "svc.diagtrack"}, stranger)
    assert not refused["ok"] and "dashboard" in refused["error"]
    assert not commands.handle({"cmd": "stop"}, stranger)["ok"]
    assert commands.handle({"cmd": "trace_sessions"}, stranger)["ok"]
    assert commands.handle({"cmd": "stop"}, {"pid": 1, "dashboard": True}) == {"ok": True, "stopping": True}
