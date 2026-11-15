"""Shared addresses and the never-block list."""

import pytest

from appaudit import blocking, livestore
from appaudit.naming import labels


@pytest.fixture(autouse=True)
def no_lists(monkeypatch):
    monkeypatch.setattr(labels, "_blocklists", lambda: (set(), {}))
    labels.for_name.cache_clear()
    yield
    labels.for_name.cache_clear()


@pytest.mark.parametrize("name, blocked", [
    ("login.live.com", True), ("safebrowsing.googleapis.com", True), ("time.windows.com", True),
    ("lcs-cops.adobe.io", True), ("spclient.wg.spotify.com", True), ("firefox.settings.services.mozilla.com", True),
    ("api.mixpanel.com", False), ("www.google-analytics.com", False),
])
def test_never_block(name, blocked):
    assert (blocking.never_block(name) is not None) is blocked


def test_shared_address_is_found_and_names_what_would_break(tmp_path):
    conn = livestore.connect(file=tmp_path / "live.db")
    rows = [("203.0.113.1", "www.google-analytics.com", 1000, 5000), ("203.0.113.1", "safebrowsing.googleapis.com", 3000, 9000),
            ("203.0.113.2", "collector.example.com", 1000, 5000),
            ("203.0.113.3", "telemetry.vendor.org", 1000.0, 5000), ("203.0.113.3", "edge.vendor-cdn.net", 1000.5, 5000)]
    conn.executemany("INSERT INTO names VALUES (?, ?, 'dns', ?, ?)", rows)
    analytics = blocking.shared(conn, "www.google-analytics.com")
    assert not analytics["clean"] and analytics["would_break"] == ["safebrowsing.googleapis.com"]
    assert blocking.shared(conn, "collector.example.com")["clean"]
    assert blocking.shared(conn, "telemetry.vendor.org")["clean"]          # a CNAME in the same answer is not sharing
    assert blocking.shared(conn, "unknown.example.com")["clean"] is False   # no addresses: nothing to judge
