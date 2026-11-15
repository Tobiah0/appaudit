"""The switch engine, exercised only through the sandbox backend: nothing on the PC changes."""

import pytest

from appaudit import switches
from appaudit.switches.backends import SandboxBackend


def test_catalogue_loads_and_is_valid():
    catalogue = switches.load_catalogue()
    assert len(catalogue) >= 100
    for item in catalogue.values():
        assert item.title and (item.checks or item.steps), item.id
        assert item.origin != "catalogue" or item.explain, item.id
        assert item.risk in ("low", "medium", "high"), item.id


def test_every_switch_can_be_read_on_this_pc():
    backend = SandboxBackend()
    states = [switches.state(item, backend) for item in switches.load_catalogue().values()]
    assert {entry["state"] for entry in states} <= {"private", "exposed", "partly", "not_installed", "unknown", "manual"}
    assert not [entry["id"] for entry in states if entry["state"] == "unknown"]


def forced_exposed(switch, backend):
    """Put every check of a switch into a known exposed state inside the sandbox."""
    for check in switch.checks:
        exposed = {"registry": 12345, "service": "automatic", "task": "enabled", "env": "exposed"}[check["type"]]
        switches.write_check(check, exposed, backend)


@pytest.mark.parametrize("switch_id", ["win.advertising-id", "svc.diagtrack", "task.device-census", "dev.dotnet",
                                       "ai.recall", "win.inking-typing"])
def test_apply_then_undo_restores_previous_values(switch_id, tmp_path):
    switch = switches.load_catalogue()[switch_id]
    backend = SandboxBackend()
    forced_exposed(switch, backend)
    before = [switches.read_check(check, backend) for check in switch.checks]
    assert switches.state(switch, backend)["state"] == "exposed"
    assert len(switches.plan(switch, backend)) == len(switch.checks)

    journal = tmp_path / "journal.db"
    result = switches.apply(switch, backend, journal)
    assert not result["failed"] and len(result["changed"]) == len(switch.checks)
    assert switches.state(switch, backend)["state"] == "private"
    assert switches.plan(switch, backend) == []

    undone = switches.undo(result["journal_id"], backend, journal)
    assert not undone["failed"]
    assert [switches.read_check(check, backend) for check in switch.checks] == before
    assert switches.journal_entries(journal, "sandbox")[0]["undone"] is not None


def test_apply_can_be_split_between_user_and_admin_halves(tmp_path):
    switch = switches.load_catalogue()["ai.recall"]          # two HKLM checks and one HKCU check
    backend = SandboxBackend()
    forced_exposed(switch, backend)
    user = switches.apply(switch, backend, tmp_path / "j.db", only_admin=False)
    assert [change["admin"] for change in user["changed"]] == [False]
    assert switches.state(switch, backend)["state"] == "partly"
    admin = switches.apply(switch, backend, tmp_path / "j.db", only_admin=True)
    assert all(change["admin"] for change in admin["changed"]) and len(admin["changed"]) == 2
    assert switches.state(switch, backend)["state"] == "private"


def test_absent_registry_value_is_restored_as_absent(tmp_path):
    switch = switches.load_catalogue()["win.onesettings"]
    backend = SandboxBackend()
    check = switch.checks[0]
    switches.write_check(check, None, backend)
    result = switches.apply(switch, backend, tmp_path / "j.db")
    assert result["changed"][0]["before"] is None
    switches.undo(result["journal_id"], backend, tmp_path / "j.db")
    assert switches.read_check(check, backend) is None


def test_sandbox_never_writes_to_windows():
    backend = SandboxBackend()
    switch = switches.load_catalogue()["dev.nextjs"]
    real_before = switches.backends.RealBackend().env_get("NEXT_TELEMETRY_DISABLED")
    switches.write_check(switch.checks[0], "exposed", backend)
    switches.apply(switch, backend, None if False else __import__("pathlib").Path(__file__).parent / "_tmp_journal.db")
    assert switches.backends.RealBackend().env_get("NEXT_TELEMETRY_DISABLED") == real_before
    (__import__("pathlib").Path(__file__).parent / "_tmp_journal.db").unlink()
