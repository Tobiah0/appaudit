"""Config-file switches and the toptout import, run against files in a temporary folder.

The user-folder variables are pointed at the test's own folder, so the real backend reads and
writes only there; nothing on the PC changes.
"""

import json

import pytest

from appaudit import switches
from appaudit.switches import RealBackend, toptout

SETTINGS = '{\n\t// mine\n\t"editor.fontSize": 14,\n}\n'


@pytest.fixture
def home(tmp_path, monkeypatch):
    for name in ("APPDATA", "LOCALAPPDATA", "USERPROFILE"):
        monkeypatch.setenv(name, str(tmp_path / name.lower()))
        (tmp_path / name.lower()).mkdir()
    monkeypatch.setenv("APPAUDIT_DATA", str(tmp_path / "data"))
    return tmp_path


def vscode_switch(**extra) -> switches.Switch:
    entry = {"id": "test.vscode", "title": "VS Code telemetry", "explain": "x",
             "checks": [{"type": "file", "format": "json", "path": "%APPDATA%\\Code\\User\\settings.json",
                         "keys": ["telemetry.telemetryLevel"], "private": "off", "apps": ["NoSuchApp.exe"], **extra}]}
    return switches.build_switch(entry, "Test")


def write_settings(home, text=SETTINGS):
    folder = home / "appdata" / "Code" / "User"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "settings.json").write_text(text, encoding="utf-8", newline="")
    return folder / "settings.json"


def test_plan_shows_the_exact_diff_and_changes_nothing(home):
    path = write_settings(home)
    switch = vscode_switch()
    assert switches.state(switch)["state"] == "exposed"
    [change] = switches.plan(switch)
    assert change["file"] == str(path)
    assert '+\t"telemetry.telemetryLevel": "off",' in change["diff"]
    assert change["running"] == []
    assert path.read_text(encoding="utf-8") == SETTINGS


def test_apply_backs_up_then_undo_restores_byte_for_byte(home):
    path = write_settings(home)
    switch = vscode_switch()
    result = switches.apply(switch, journal_file=home / "journal.db")
    assert not result["failed"]
    assert switches.state(switch)["state"] == "private"
    written = path.read_text(encoding="utf-8")
    assert "// mine" in written and '"telemetry.telemetryLevel": "off"' in written
    backup = result["changed"][0]["backup"]
    assert open(backup, encoding="utf-8").read() == SETTINGS

    switches.load_catalogue.cache_clear()
    entry = switches.journal_entries(home / "journal.db")[0]
    assert entry["changes"][0]["check_def"]["keys"] == ["telemetry.telemetryLevel"]
    # undo() finds the check in the journal, since this switch is not in the catalogue
    undone = switches.undo(result["journal_id"], journal_file=home / "journal.db")
    assert not undone["failed"]
    assert path.read_text(encoding="utf-8") == SETTINGS


def test_undo_keeps_other_edits_made_after_the_switch(home):
    path = write_settings(home)
    result = switches.apply(vscode_switch(), journal_file=home / "journal.db")
    path.write_text(path.read_text(encoding="utf-8").replace("14", "18"), encoding="utf-8", newline="")
    switches.undo(result["journal_id"], journal_file=home / "journal.db")
    text = path.read_text(encoding="utf-8")
    assert '"editor.fontSize": 18' in text and "telemetryLevel" not in text


def test_switch_creates_a_missing_file_and_undo_removes_it(home):
    folder = home / "appdata" / "Code" / "User"
    folder.mkdir(parents=True)
    result = switches.apply(vscode_switch(), journal_file=home / "journal.db")
    assert json.loads((folder / "settings.json").read_text(encoding="utf-8")) == {"telemetry.telemetryLevel": "off"}
    switches.undo(result["journal_id"], journal_file=home / "journal.db")
    assert not (folder / "settings.json").exists()


def test_unreadable_file_is_refused_and_left_alone(home):
    path = write_settings(home, '{"broken": ')
    switch = vscode_switch()
    assert switches.state(switch)["state"] == "unknown"
    with pytest.raises(ValueError):
        switches.plan(switch)
    assert path.read_text(encoding="utf-8") == '{"broken": '


def test_running_app_is_reported_in_the_plan(home, monkeypatch):
    write_settings(home)
    monkeypatch.setattr(RealBackend, "running", lambda self, names: {"Code.exe"} if names else set())
    assert switches.plan(vscode_switch())[0]["running"] == ["Code.exe"]


@pytest.mark.parametrize("path", ["C:\\Windows\\win.ini", "%PROGRAMDATA%\\x.json", "%APPDATA%\\..\\..\\x.json"])
def test_file_checks_outside_the_users_folders_are_rejected(path):
    with pytest.raises(ValueError):
        switches.build_switch({"id": "t", "title": "t", "checks": [
            {"type": "file", "format": "json", "path": path, "keys": ["a"], "private": 1}]}, "T")


def test_restore_refuses_a_backup_outside_the_backup_folder(home):
    path = write_settings(home)
    with pytest.raises(ValueError):
        RealBackend().file_restore(str(path), str(home / "elsewhere.json"))


# --- toptout import ---------------------------------------------------------------------------

PRODUCTS = {
    "vscode": {"id": "vscode", "name": "Visual Studio Code", "executable_name": ["code"], "category_name": "Applications",
               "telemetry": [{"id": "telemetry-level", "name": "Telemetry", "target": {"json_file": {"scope": {"user": {
                   "path": {"windows": "%APPDATA%\\Code\\User\\settings.json"},
                   "selector": {"json_pointer": "/telemetry.telemetryLevel"}, "value": {"opt_out": "off"},
                   "display_value": "{}"}}}}}]},
    "vscode-julia": {"id": "vscode-julia", "name": "Julia for VS Code", "executable_name": ["code"],
                     "telemetry": [{"id": "usage", "name": "Usage", "target": {"json_file": {"scope": {"user": {
                         "path": {"windows": "%APPDATA%\\Code\\User\\settings.json"},
                         "selector": {"json_pointer": "/julia.enableTelemetry"}, "value": {"opt_out": False},
                         "display_value": "{}"}}}}}]},
    "tool": {"id": "tool", "name": "Some CLI", "executable_name": ["sometool-not-installed"],
             "telemetry": [
                 {"id": "env", "name": "Env", "target": {"env": {"scope": {"process": {"path": {"default": "TOOL_NO_TELEMETRY"},
                                                                                       "value": {"opt_out": "ANY_VALUE"}}}}}},
                 {"id": "app", "name": "In the app", "target": {"noop": [{"name": "Open settings", "description": "Turn it off.",
                                                                           "link": "https://example.com"}]}},
                 {"id": "cmd", "name": "Command", "target": {"exec": {"scope": {"user": {"path": {"default": "tool"},
                                                                                         "value": {"opt_out": ["telemetry", "off"]}}}}}},
                 {"id": "broken", "name": "Broken", "target": {"registry": {"scope": {"user": {"path": 5}}}}}]},
}


@pytest.fixture
def imported(home, monkeypatch):
    folder = home / "toptout"
    folder.mkdir()
    for name, product in PRODUCTS.items():
        (folder / f"{name}.json").write_text(json.dumps(product), encoding="utf-8")
    (folder / "garbage.json").write_text("{not json", encoding="utf-8")
    monkeypatch.setattr(toptout, "folder", lambda: folder)
    return {item.id: item for item in toptout.load(set())}


def test_import_turns_targets_into_checks_and_steps(imported):
    assert imported["toptout.vscode.telemetry-level"].checks[0]["keys"] == ["telemetry.telemetryLevel"]
    env = imported["toptout.tool.env"].checks[0]
    assert env["name"] == "TOOL_NO_TELEMETRY" and env["private_any"]
    assert imported["toptout.tool.app"].steps[0]["link"] == "https://example.com"
    assert "`tool telemetry off`" in imported["toptout.tool.cmd"].steps[0]["description"]
    assert all(item.origin == "toptout" for item in imported.values())


def test_bad_entries_are_skipped_not_fatal(imported):
    assert "toptout.tool.broken" not in imported
    assert any("garbage.json" in reason for reason in toptout.skipped)


def test_shared_settings_file_detects_the_main_product_not_its_add_ons(imported, home):
    write_settings(home)
    assert switches.present(imported["toptout.vscode.telemetry-level"], RealBackend())
    assert not switches.present(imported["toptout.vscode-julia.usage"], RealBackend())


def test_imported_checks_already_in_the_catalogue_are_skipped(home, monkeypatch, imported):
    covered = {switches.check_identity(imported["toptout.vscode.telemetry-level"].checks[0])}
    again = {item.id for item in toptout.load(covered)}
    assert "toptout.vscode.telemetry-level" not in again


def test_switches_for_an_app_match_its_programs_not_shared_hosts():
    ids = lambda programs: {item.id for item in switches.for_app(programs)}  # noqa: E731
    assert "firefox.telemetry" in ids({r"C:\Program Files\Mozilla Firefox\firefox.exe"})
    assert "adobe.acrobat-usage" in ids({r"C:\x\AdobeCollabSync.exe"})
    # The WebView2 runtime hosts both Widgets and Copilot, so it is evidence for neither.
    assert not {"win.widgets", "ai.copilot"} & ids({r"C:\x\msedgewebview2.exe"})
    assert "win.widgets" in ids({r"C:\x\Widgets.exe"})


def test_command_switches_match_the_exact_program_not_its_name(monkeypatch, tmp_path):
    tool = tmp_path / "bin" / "claude.exe"
    tool.parent.mkdir()
    tool.write_text("")
    monkeypatch.setattr(switches.shutil, "which", lambda name: str(tool) if name == "claude" else None)
    switch = switches.build_switch({"id": "t.cli", "title": "CLI", "detect": {"command": "claude"},
                                    "checks": [{"type": "env", "name": "X", "private": "1"}]}, "T")
    assert switches.programs_of(switch) == {"path:" + str(tool).lower()}
    monkeypatch.setattr(switches, "load_catalogue", lambda: {"t.cli": switch})
    assert switches.for_app({str(tool)}) == [switch]
    assert switches.for_app({r"C:\Users\x\AppData\Local\AnthropicClaude\claude.exe"}) == []


def test_any_value_counts_as_off():
    check = {"type": "env", "name": "X", "private": "1", "private_any": True}
    assert switches.check_state(check, "yes") == "private"
    assert switches.check_state(check, None) == "exposed"
