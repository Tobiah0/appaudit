"""Per-app blocks against the sandbox firewall: no Windows Firewall rule is created."""

import sys

import pytest

from appaudit import blocks


def test_add_list_remove(tmp_path):
    firewall = blocks.SandboxFirewall()
    journal = tmp_path / "blocks.db"
    result = blocks.add(sys.executable, firewall, journal)
    assert result["rule"].startswith(blocks.PREFIX) and firewall.exists(result["rule"])
    assert blocks.add(sys.executable, firewall, journal)["already"] is True
    listed = blocks.active(journal, firewall)
    assert len(listed) == 1 and listed[0]["in_firewall"]
    blocks.remove(result["id"], firewall, journal)
    assert not firewall.rules and blocks.active(journal, firewall) == []


@pytest.mark.parametrize("path, reason", [
    (r"C:\Windows\System32\svchost.exe", "Windows components"),
    ("notepad.exe", "full path"),
    (r"C:\definitely\not\here.exe", "not on this PC"),
    (r"C:\Windows\System32\drivers\etc\hosts", "full path"),
])
def test_refuses_unsafe_targets(path, reason):
    with pytest.raises(ValueError, match=reason):
        blocks.validate(path)
