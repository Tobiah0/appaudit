"""Interpreters are attributed to what they run, not to "Python"."""

import pytest

from appaudit.attribution import script_identity


@pytest.mark.parametrize("exe, cmdline, actor_id, name", [
    (r"C:\py\pythonw.exe", r'"C:\py\pythonw.exe" -m appaudit.helper', "self:appaudit", "App Audit (this tool)"),
    (r"D:\p\.venv\Scripts\python.exe", r"D:\p\.venv\Scripts\python.exe -m uvicorn appaudit.api:app", "self:appaudit", "App Audit (this tool)"),
    (r"D:\dev\novel\backend\.venv\Scripts\python.exe", r"D:\dev\novel\backend\.venv\Scripts\python.exe -m novel.cli serve",
     "script:module:novel:backend", "Python program: novel (backend)"),
    (r"C:\py\python.exe", r"C:\py\python.exe C:\Users\x\AppData\Local\Temp\claude\a\b\scratchpad\probe.py",
     "script:claude-code", "Scripts run by Claude Code"),
    (r"C:\py\python.exe", r"C:\py\python.exe C:\tools\backup.py", "script:file:backup.py", "Script: backup.py"),
])
def test_interpreter_runs_are_named_after_what_they_run(exe, cmdline, actor_id, name):
    found = script_identity(exe, cmdline)
    assert (found["id"], found["name"]) == (actor_id, name)


def test_project_root_found_by_marker(tmp_path):
    (tmp_path / "proj").mkdir()
    (tmp_path / "proj" / "pyproject.toml").write_text("")
    (tmp_path / "proj" / "tools").mkdir()
    script = tmp_path / "proj" / "tools" / "run.py"
    script.write_text("")
    found = script_identity(r"C:\py\python.exe", f'C:\\py\\python.exe "{script}"')
    assert found["name"] == "Project: proj"


def test_unidentifiable_runs_stay_with_the_interpreter():
    assert script_identity(r"C:\py\python.exe", r"C:\py\python.exe -c print(1)") is None
    assert script_identity(r"C:\py\python.exe", "") is None


def test_process_known_only_by_id_borrows_the_program_of_an_overlapping_record(tmp_path):
    from appaudit import activity, livestore

    conn = livestore.connect(file=tmp_path / "live.db")
    conn.execute("INSERT INTO procs (id, pid, started, ended, exe, name, seen_start) VALUES (1, 77, 1000, 1100, ?, 'App.exe', 1)",
                 (r"C:\App\App.exe",))
    conn.commit()
    procs = {2: {"id": 2, "pid": 77, "started": 1010, "ended": None, "exe": None, "name": "pid 77"},
             3: {"id": 3, "pid": 88, "started": 1010, "ended": None, "exe": None, "name": "pid 88"}}
    activity._fill_unnamed(conn, procs)
    assert procs[2]["name"] == "App.exe" and procs[3]["exe"] is None


def test_unidentified_processes_share_one_honest_group():
    from appaudit.attribution import Attributor

    ref = Attributor.__new__(Attributor).app_for_exe(None, "pid 88")
    assert ref.id == "proc:unidentified" and "ended before" in ref.name
