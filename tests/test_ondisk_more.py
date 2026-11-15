"""The R1 readers: Unreal crash context, Bugsnag store, Unity log, Local Storage IDs."""

import json

from appaudit import ondisk

BUDGET = lambda: {"files": 0.0, "deadline": float("inf")}  # noqa: E731


def test_unreal_crash_context_marks_account_fields_as_identifying(tmp_path):
    crash = tmp_path / "Crashes" / "UECC-1"
    crash.mkdir(parents=True)
    (crash / "CrashContext.runtime-xml").write_text(
        "<FGenericCrashContext><RuntimeProperties><GameName>UE4-Game</GameName><EpicAccountId>abc123</EpicAccountId>"
        "<Misc.CPUBrand>Ryzen</Misc.CPUBrand></RuntimeProperties></FGenericCrashContext>", encoding="utf-8")
    (crash / "UE4Minidump.dmp").write_bytes(b"MDMP" + b"0" * 100)
    result = ondisk.read_unreal(tmp_path / "Crashes", BUDGET())
    facts = {label: (value, identifying) for label, value, identifying in result["facts"]}
    assert facts["Epic account ID"] == ("abc123", True) and facts["game"] == ("UE4-Game", False)
    assert result["items"][0]["size"] == 104


def test_bugsnag_store_counts_waiting_events(tmp_path):
    store = tmp_path / "bugsnag" / "hash"
    (store / "events").mkdir(parents=True)
    (store / "device.json").write_text(json.dumps({"id": "device-1"}), encoding="utf-8")
    (store / "events" / "e1.json").write_text(json.dumps({"events": [], "apiKey": "k"}), encoding="utf-8")
    result = ondisk.read_bugsnag(tmp_path / "bugsnag", BUDGET())
    assert result["facts"] == [["device id", "device-1", True]] and result["total"] == 1


def test_unity_log_counts_sdk_lines_and_events(tmp_path):
    log = tmp_path / "Player.log"
    log.write_text("GameAnalytics init\nGAEvents:AddDesignEvent(x)\nGAEvents:AddDesignEvent(y)\nSteamworks ok\n", encoding="utf-8")
    facts = {label: value for label, value, _ in ondisk.read_unity_log(log, BUDGET())["facts"]}
    assert facts["analytics events recorded in this log"] == 2 and facts["Steamworks"] == "1 log lines"


def test_local_storage_ids_are_found_by_key(tmp_path):
    folder = tmp_path / "leveldb"
    folder.mkdir()
    (folder / "000003.log").write_bytes(b"\x00_dd_s\x01id=1\x00statsig.cached.evaluations\x00ajs_anonymous_id\x00")
    labels = [label for label, _, _ in ondisk.read_local_storage(folder, BUDGET())["facts"]]
    assert labels == ["Datadog session", "Segment ID", "Statsig experiments"]
