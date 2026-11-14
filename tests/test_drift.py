"""Drift log: a switch that was off and is on again is reported once."""

from appaudit import drift


def test_reports_switch_turned_back_on(tmp_path):
    file = tmp_path / "d.db"
    assert drift.record([{"id": "a", "state": "private"}, {"id": "b", "state": "exposed"}], file, now=1) == []
    assert drift.record([{"id": "a", "state": "private"}, {"id": "b", "state": "exposed"}], file, now=2) == []
    changes = drift.record([{"id": "a", "state": "exposed"}, {"id": "b", "state": "private"}], file, now=3)
    assert {c["id"] for c in changes} == {"a", "b"}
    log = {item["id"]: item for item in drift.log(file)}
    assert log["a"]["turned_back_on"] is True and log["b"]["turned_back_on"] is False
    assert drift.record([{"id": "a", "state": "exposed"}], file, now=4) == []
