"""Address and name blocks against the sandbox backend: nothing on the PC changes."""

import pytest

from appaudit import livestore, stops
from appaudit.naming import labels

HOSTS = "# my own entries\r\n127.0.0.1 checkhost.local\r\n109.94.209.70 www.example-mirror.org\r\n"


@pytest.fixture(autouse=True)
def no_lists(monkeypatch):
    monkeypatch.setattr(labels, "_blocklists", lambda: (set(), {}))
    labels.for_name.cache_clear()
    yield
    labels.for_name.cache_clear()


@pytest.fixture
def live(tmp_path):
    conn = livestore.connect(file=tmp_path / "live.db")
    conn.executemany("INSERT INTO names VALUES (?, ?, 'dns', ?, ?)", [
        ("203.0.113.1", "http-intake.logs.us5.datadoghq.com", 1000, 5000),
        ("203.0.113.2", "www.google-analytics.com", 1000, 5000), ("203.0.113.2", "safebrowsing.googleapis.com", 3000, 9000),
        ("203.0.113.3", "api.mixpanel.com", 1000, 5000)])
    conn.commit()
    return conn


@pytest.fixture
def program(tmp_path):
    exe = tmp_path / "Chat" / "Chat.exe"
    exe.parent.mkdir()
    exe.write_bytes(b"MZ")
    return str(exe)


def test_address_block_uses_addresses_from_this_pc_and_undo_removes_the_rule(live, program, tmp_path):
    backend = stops.SandboxBackend()
    added = stops.add_address_block(live, program, "http-intake.logs.us5.datadoghq.com", backend, file=tmp_path / "j.db")
    assert added["addresses"] == ["203.0.113.1"] and backend.rules[added["rule"]]["exe"] == program
    stops.remove(added["id"], backend, file=tmp_path / "j.db")
    assert backend.rules == {}


@pytest.mark.parametrize("name, why", [
    ("www.google-analytics.com", "also serve"),          # shared with Safe Browsing
    ("login.live.com", "must keep working"),
    ("tracker.never-seen.example", "not seen"),
])
def test_address_block_refusals(live, program, tmp_path, name, why):
    with pytest.raises(stops.Refused, match=why):
        stops.add_address_block(live, program, name, stops.SandboxBackend(), file=tmp_path / "j.db")


def test_name_block_edits_only_its_own_section_and_undo_restores_the_file(live, tmp_path):
    backend = stops.SandboxBackend(HOSTS)
    added = stops.add_name_block(live, "api.mixpanel.com", backend, file=tmp_path / "j.db")
    assert "0.0.0.0 api.mixpanel.com" in backend.hosts and backend.hosts.startswith(HOSTS.rstrip("\r\n"))
    assert stops.hosts_names(backend.hosts) == ["api.mixpanel.com"]
    stops.remove(added["id"], backend, file=tmp_path / "j.db")
    assert backend.hosts == HOSTS


@pytest.mark.parametrize("name, why", [
    ("mobile.events.data.microsoft.com", "Microsoft"),
    ("spclient.wg.spotify.com", "must keep working"),
    ("not a name", "not a host name"),
])
def test_name_block_refusals(live, tmp_path, name, why):
    with pytest.raises(stops.Refused, match=why):
        stops.add_name_block(live, name, stops.SandboxBackend(HOSTS), file=tmp_path / "j.db")


def test_refresh_follows_a_name_to_new_clean_addresses(live, program, tmp_path):
    backend = stops.SandboxBackend()
    added = stops.add_address_block(live, program, "http-intake.logs.us5.datadoghq.com", backend, file=tmp_path / "j.db")
    live.execute("INSERT INTO names VALUES ('203.0.113.9', 'http-intake.logs.us5.datadoghq.com', 'dns', 6000, 7000)")
    assert stops.refresh_addresses(live, backend, file=tmp_path / "j.db") == 1
    assert backend.rules[added["rule"]]["addresses"] == ["203.0.113.1", "203.0.113.9"]


def test_real_stops_are_off_until_enabled():
    assert stops.REAL_ENABLED is False
    with pytest.raises(stops.Refused, match="switched off"):
        stops.backend_for_real()
