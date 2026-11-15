"""Cases: first versus third party, decisions that stick, and reopening when the evidence changes."""

import pytest

from appaudit import cases


@pytest.mark.parametrize("publisher, company, same", [
    ("Anthropic PBC", "Anthropic", True),
    ("Adobe Inc.", "Adobe", True),
    ("Spotify AB", "Google", False),
    ("Notion Labs", "Splunk", False),
    (None, "Google", False),
])
def test_first_party_is_the_apps_own_maker(publisher, company, same):
    assert cases.same_company(publisher, company) is same


def case(case_id="third-party:x", fingerprint="f1", severity="medium", actionable=False):
    return {"id": case_id, "kind": "third_party", "severity": severity, "app": "X", "title": "t",
            "actions": [], "fingerprint": fingerprint, "actionable": actionable}


@pytest.fixture
def db(tmp_path, monkeypatch):
    from appaudit import dismissed

    monkeypatch.setattr(dismissed, "listing", lambda: [])
    return tmp_path / "cases.db"


def test_accepted_case_stays_hidden_until_its_evidence_changes(db):
    cases.decide("third-party:x", "accepted", "f1", file=db)
    same = cases.listing(file=db, built=[case(fingerprint="f1")])
    assert same["cases"][0]["state"] == "accepted" and same["counts"]["open"] == 0
    changed = cases.listing(file=db, built=[case(fingerprint="f2")])
    assert changed["cases"][0]["state"] == "open" and changed["cases"][0]["reopened"]


def test_open_cases_come_first_by_severity_and_actions(db):
    cases.decide("b", "accepted", "f1", file=db)
    result = cases.listing(file=db, built=[case("a", severity="low"), case("b", severity="high"),
                                           case("c", severity="medium", actionable=True), case("d", severity="medium")])
    assert [item["id"] for item in result["cases"]] == ["c", "d", "a", "b"]


def test_a_said_vs_does_case_that_went_away_is_reported_fixed(db):
    cases.decide("off-but-active:svc.x", "testing", "f1", file=db)
    result = cases.listing(file=db, built=[])
    assert result["fixed"][0]["id"] == "off-but-active:svc.x"


def test_unknown_state_is_refused(db):
    with pytest.raises(ValueError):
        cases.decide("x", "deleted", "f", file=db)


def test_size_bands_ignore_small_changes():
    assert cases._size_band(100_000) == cases._size_band(150_000)
    assert cases._size_band(100_000) != cases._size_band(2_000_000)
