"""The elevated helper never trusts the user-writable journal for administrator changes."""

import json
import sqlite3

import pytest

from appaudit import blocks, protected, switches
from appaudit.switches.backends import SandboxBackend


@pytest.fixture
def folders(tmp_path, monkeypatch):
    monkeypatch.setenv("APPAUDIT_DATA", str(tmp_path / "data"))
    monkeypatch.setenv("APPAUDIT_PROTECTED", str(tmp_path / "programdata"))
    return tmp_path


def test_admin_undo_uses_the_protected_record_not_the_users_copy(folders):
    switch = switches.load_catalogue()["svc.diagtrack"]                      # a service: administrator change
    backend = SandboxBackend()
    backend.service_set("DiagTrack", "automatic")
    result = switches.apply(switch, backend, only_admin=True)
    entry = result["journal_id"]
    user_copy = folders / "data" / "appaudit.db"
    # A program running as the user rewrites the value undo would put back.
    conn = sqlite3.connect(user_copy)
    changes = json.loads(conn.execute("SELECT changes FROM switch_journal WHERE id = ?", (entry,)).fetchone()[0])
    changes[0]["before"] = "attacker-value"
    conn.execute("UPDATE switch_journal SET changes = ? WHERE id = ?", (json.dumps(changes), entry))
    conn.commit()
    conn.close()
    switches.undo(entry, backend, only_admin=True)
    assert backend.service_get("DiagTrack") == "automatic"
    shown = switches.journal_entries(backend_name="sandbox")
    assert shown[0]["id"] == entry and shown[0]["undone"]                   # the display copy is marked too


def test_unknown_entry_in_the_protected_record_is_refused(folders):
    with pytest.raises(KeyError, match="protected"):
        switches.undo(999, SandboxBackend(), only_admin=True)


def test_helper_refuses_to_remove_a_rule_it_did_not_make(folders):
    firewall = blocks.SandboxFirewall()
    firewall.rules["Core Networking - DNS (UDP-Out)"] = "svchost.exe"
    with blocks._db() as conn:
        entry = conn.execute("INSERT INTO blocks (exe, rule, backend, created) VALUES (?,?,?,0)",
                             ("x.exe", "Core Networking - DNS (UDP-Out)", "sandbox")).lastrowid
    with pytest.raises(ValueError, match="not made by App Audit"):
        blocks.remove(entry, firewall)
    assert "Core Networking - DNS (UDP-Out)" in firewall.rules


def test_protected_folder_is_refused_without_administrator_rights(monkeypatch):
    monkeypatch.delenv("APPAUDIT_PROTECTED", raising=False)
    monkeypatch.setattr("appaudit.winutil.is_admin", lambda: False)
    with pytest.raises(protected.Unsafe):
        protected.ensure()
