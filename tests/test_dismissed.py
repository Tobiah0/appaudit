import pytest

from appaudit import dismissed


def test_add_list_remove(tmp_path):
    file = tmp_path / "d.db"
    dismissed.add("program", r"C:\Apps\Fine.exe", "Fine", file)
    dismissed.add("program", r"c:\apps\fine.exe", "Fine again", file)
    assert [(item["key"], item["label"]) for item in dismissed.listing(file)] == [(r"c:\apps\fine.exe", "Fine again")]
    dismissed.remove("program", r"C:\APPS\FINE.EXE", file)
    assert dismissed.listing(file) == []


def test_rejects_unknown_kind(tmp_path):
    with pytest.raises(ValueError):
        dismissed.add("registry", "x", "x", tmp_path / "d.db")
