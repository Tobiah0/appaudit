"""The method chooser, with the cases from STOPPING.md's table."""

import pytest

from appaudit import stopping, switches
from appaudit.naming import labels


@pytest.fixture(autouse=True)
def no_lists(monkeypatch):
    monkeypatch.setattr(labels, "_blocklists", lambda: (set(), {}))
    labels.for_name.cache_clear()
    yield
    labels.for_name.cache_clear()


def dest(name, company):
    return {"name": name, "company": company, "address": "203.0.113.9", "sent": 1000}


CLEAN = {"clean": True, "addresses": ["203.0.113.9"]}
SHARED = {"clean": False, "addresses": ["203.0.113.9"], "would_break": ["safebrowsing.googleapis.com"],
          "would_also_block": ["safebrowsing.googleapis.com"]}


def pick(sender, destination, publisher, shared=CLEAN, share=None, switch_ids=(), states=None):
    catalogue = switches.load_catalogue()
    chosen = [catalogue[item] for item in switch_ids]
    return stopping.choose(sender=sender, sender_share=share, destination=destination, publisher=publisher,
                           switches=chosen, switch_states=states or {item: "exposed" for item in switch_ids}, shared=shared)


def test_a_switch_that_covers_it_comes_first():
    result = pick("firefox.exe", dest("incoming.telemetry.mozilla.org", "Mozilla"), "Mozilla", switch_ids=["firefox.telemetry"])
    assert result["method"] == "switch" and result["switch"] == "firefox.telemetry"


def test_a_switch_already_off_is_not_offered():
    result = pick("firefox.exe", dest("incoming.telemetry.mozilla.org", "Mozilla"), "Mozilla",
                  switch_ids=["firefox.telemetry"], states={"firefox.telemetry": "private"})
    assert result["method"] != "switch"


def test_a_program_that_only_reports_can_be_stopped():
    result = pick("LogTransport2.exe", dest("cc-api-data.adobe.io", "Adobe"), "Adobe",
                  share={"sent": 1000, "reporting": 990, "exe": r"C:\A\LogTransport2.exe"})
    assert result["method"] == "stop_program"


def test_security_software_is_never_stopped():
    result = pick("MpDefenderCoreService.exe", dest("mobile.events.data.microsoft.com", "Microsoft"), "Microsoft",
                  share={"sent": 1000, "reporting": 1000})
    assert result["method"] == "nothing_safe" and "Defender" in result["reasons"][0]


def test_clean_addresses_allow_a_block_for_this_program_only():
    result = pick("claude.exe", dest("http-intake.logs.us5.datadoghq.com", "Datadog"), "Anthropic PBC")
    assert result["method"] == "address_block" and result["addresses"] == ["203.0.113.9"]


def test_shared_addresses_fall_back_to_a_name_block_for_third_party_trackers():
    result = pick("Spotify.exe", dest("www.google-analytics.com", "Google"), "Spotify AB", shared=SHARED)
    assert result["method"] == "name_block" and any("Safe Browsing" in r or "safebrowsing" in r for r in result["reasons"])


def test_shared_first_party_reporting_has_nothing_safe():
    result = pick("chrome.exe", dest("clientservices.googleapis.com", "Google"), "Google LLC", shared=SHARED)
    assert result["method"] == "nothing_safe"


def test_never_block_hosts_are_left_alone():
    result = pick("Spotify.exe", dest("spclient.wg.spotify.com", "Spotify"), "Spotify AB")
    assert result["method"] == "nothing_safe"


def test_careful_destinations_carry_their_warning():
    result = pick("claude.exe", dest("nexus-websocket-a.intercom.io", "Intercom"), "Anthropic PBC")
    assert result["method"] == "address_block" and result["reasons"][0].startswith("Careful:")
