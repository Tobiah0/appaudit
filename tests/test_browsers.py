"""A browser's own reporting versus trackers loaded by the websites opened in it."""

from appaudit import browsers


def test_browser_is_found_by_its_program():
    assert browsers.browser_for(["firefox.exe"])["name"] == "Firefox"
    assert browsers.browser_for(["Spotify.exe"]) is None


def test_own_reporting_versus_website_trackers():
    firefox = browsers.browser_for(["firefox.exe"])
    chrome = browsers.browser_for(["chrome.exe"])
    assert browsers.is_own(firefox, "incoming.telemetry.mozilla.org")
    assert not browsers.is_own(firefox, "www.google-analytics.com")
    assert browsers.is_own(chrome, "clientservices.googleapis.com")
    assert not browsers.is_own(chrome, "www.google-analytics.com")      # Google, but loaded by websites
    assert not browsers.is_own(chrome, None)
