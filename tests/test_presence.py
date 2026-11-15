"""Presence: one bit per minute, and traffic split into while-present, while-away and unknown."""

from appaudit import presence


def test_a_minute_with_any_presence_stays_present(tmp_path):
    db = tmp_path / "p.db"
    presence.record(False, now=600, file=db)
    presence.record(True, now=610, file=db)
    presence.record(False, now=620, file=db)
    assert presence.minutes(0, 1000, file=db) == {10: True}


def test_split_counts_unrecorded_minutes_as_unknown_not_away():
    known = {10: True, 11: False}
    here, away, unknown = presence.split(600, 779, known)        # minutes 10, 11, 12
    assert (round(here, 2), round(away, 2), round(unknown, 2)) == (0.33, 0.33, 0.33)


def test_summarise_reports_the_away_share_of_known_bytes():
    known = {10: False, 11: False, 12: True}
    rows = [{"sent": 900, "first": 600, "last": 719},             # minutes 10-11: away
            {"sent": 300, "first": 720, "last": 779},             # minute 12: present
            {"sent": 100, "first": 900, "last": 900}]             # minute 15: no record
    summary = presence.summarise(rows, known)
    assert (summary["away"], summary["present"], summary["unknown"]) == (900, 300, 100)
    assert summary["away_share"] == 0.75 and round(summary["coverage"], 3) == round(1200 / 1300, 3)


def test_idle_seconds_is_a_number_on_windows():
    assert isinstance(presence.idle_seconds(), float)
