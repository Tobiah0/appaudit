"""Destination labels: the knowledge base's corrections, without the downloaded block lists."""

import pytest
import yaml

from appaudit.naming import labels


@pytest.fixture(autouse=True)
def no_lists(monkeypatch):
    monkeypatch.setattr(labels, "_blocklists", lambda: (set(), {}))
    labels.for_name.cache_clear()
    yield
    labels.for_name.cache_clear()


@pytest.mark.parametrize("name, category, blockable", [
    ("spclient.wg.spotify.com", "content", "no"),             # Spotify's main API, not logging
    ("log.spotify.com", "telemetry", "yes"),
    ("lcs-cops.adobe.io", "licensing", "no"),
    ("cc-api-data.adobe.io", "telemetry", "yes"),
    ("docs.mixpanel.com", "developer", None),                 # documentation is not reporting
    ("api.mixpanel.com", "telemetry", "yes"),
    ("www.datadoghq.com", "developer", None),                 # a collector vendor's home page
    ("http-intake.logs.us5.datadoghq.com", "telemetry", "yes"),
    ("o12345.ingest.sentry.io", "telemetry", "yes"),
    ("www.google-analytics.com", "telemetry", "yes"),         # Google Analytics really collects on www
    ("facebook.com", "communication", None),                  # visiting Facebook is not a tracker
    ("connect.facebook.net", "advertising", "yes"),
    ("downloadcenter.intel.com", "cloud", None),
    ("firefox.settings.services.mozilla.com", "security", "no"),   # security blocklists, not telemetry
    ("nexus-websocket-a.intercom.io", "telemetry", "careful"),
])
def test_corrected_labels(name, category, blockable):
    label = labels.for_name(name)
    assert (label["category"], label["blockable"]) == (category, blockable), label


def test_every_reporting_entry_says_whether_it_can_be_blocked():
    entries = yaml.safe_load((labels.KNOWLEDGE / "domains.yaml").read_text(encoding="utf-8"))
    for entry in entries:
        if entry["category"] in labels.REPORTING:
            assert entry.get("blockable") in ("yes", "careful", "no"), entry["purpose"]
            if entry["blockable"] != "yes":
                assert entry.get("breaks"), f"{entry['purpose']}: say what breaks"
        if entry.get("blockable") == "no":
            assert entry.get("breaks"), entry["purpose"]
