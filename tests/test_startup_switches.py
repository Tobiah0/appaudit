"""Startup switches from the inventory, applied and undone in the sandbox."""

from appaudit import switches
from appaudit.switches import startup
from appaudit.switches.backends import SandboxBackend


def app(name, entries, publisher="Vendor", codes=("starts_unused",)):
    return {"id": f"inst:{name.lower()}", "name": name, "publisher": publisher, "is_system": False,
            "findings": [{"code": code} for code in codes], "autostart": entries}


RUN = {"mechanism": "run_key", "name": "Chatter", "command": r'"C:\Program Files\Chatter\Chatter.exe" --tray',
       "location": {"hive": "HKCU", "approved": "Run"}}


def test_only_apps_that_start_unused_get_a_switch_and_updaters_are_left_alone():
    found = startup.load([
        app("Chatter", [RUN]),
        app("Used daily", [RUN], codes=()),
        app("Updater only", [{**RUN, "name": "ChatterUpdate", "command": r"C:\Program Files\Chatter\update.exe"}]),
    ], service_ok=lambda name: True)
    assert [item.title for item in found] == ["Chatter starting by itself"]


def test_windows_services_and_hardware_helpers_are_left_alone():
    entries = [{"mechanism": "service", "name": "RtkAudioUniversalService", "display_name": "Realtek Audio",
                "command": r"C:\Program Files\Realtek\Audio\svc.exe"},
               {"mechanism": "service", "name": "XboxService", "command": r"C:\Program Files\X\x.exe"},
               {"mechanism": "service", "name": "ChatterSync", "command": r"C:\Program Files\Chatter\sync.exe"},
               {"mechanism": "task", "path": r"\Microsoft\Windows\Something", "name": "Something", "command": r"C:\P\a.exe"}]
    [switch] = startup.load([app("Chatter", entries)], service_ok=lambda name: True)
    assert [check.get("name") or check.get("path") for check in switch.checks] == ["ChatterSync"]


def test_startup_flag_apply_and_undo_in_the_sandbox(tmp_path):
    [switch] = startup.load([app("Chatter", [RUN])], service_ok=lambda name: True)
    backend = SandboxBackend()
    backend.startup_set("HKCU", "Run", "Chatter", "020000000000000000000000")    # enabled, as Windows writes it
    assert switches.state(switch, backend)["state"] == "exposed"
    result = switches.apply(switch, backend, tmp_path / "j.db")
    assert switches.state(switch, backend)["state"] == "private"
    switches.undo(result["journal_id"], backend, tmp_path / "j.db")
    assert backend.startup_get("HKCU", "Run", "Chatter") == "020000000000000000000000"
