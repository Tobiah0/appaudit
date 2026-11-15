"""Reading what apps keep on disk, against hand-made files in a temporary folder."""

import json
import struct
import uuid

import pytest

from appaudit import appdetail, ondisk


@pytest.fixture
def home(tmp_path, monkeypatch):
    for name in ("APPDATA", "LOCALAPPDATA"):
        (tmp_path / name).mkdir()
        monkeypatch.setenv(name, str(tmp_path / name))
    return tmp_path


def envelope(*items) -> bytes:
    lines = [json.dumps({"sent_at": "2026-11-14T10:00:00Z", "sdk": {"name": "sentry.javascript.electron"}})]
    for kind, payload in items:
        body = json.dumps(payload)
        lines += [json.dumps({"type": kind, "length": len(body.encode())}), body]
    return "\n".join(lines).encode()


def test_envelope_items_are_summarised():
    raw = envelope(("session", {"status": "exited", "did": "device-1", "started": "2026-11-14T09:00:00Z", "errors": 0}),
                   ("event", {"level": "error", "release": "app@1", "user": {"email": "a@b.c"},
                              "exception": {"values": [{"type": "TypeError", "value": "x is undefined"}]},
                              "breadcrumbs": {"values": [{"category": "ui.click"}] * 3}, "contexts": {"os": {}}}))
    parsed = ondisk.parse_envelope(raw)
    session, event = parsed["items"]
    assert session["status"] == "exited" and session["device_id"] == "device-1"
    assert event["error"] == "TypeError: x is undefined" and event["breadcrumbs"] == 3
    assert event["user"] == {"email": "a@b.c"} and '"release": "app@1"' in event["raw"]


def test_envelope_payload_with_newlines_uses_its_length():
    body = json.dumps({"message": "line one\nline two", "level": "info"}, indent=1)
    raw = b"\n".join([b'{"sent_at": "x"}', json.dumps({"type": "event", "length": len(body.encode())}).encode(),
                      body.encode(), json.dumps({"type": "session"}).encode(), b'{"status": "ok"}'])
    items = ondisk.parse_envelope(raw)["items"]
    assert [item["type"] for item in items] == ["event", "session"]
    assert items[1]["status"] == "ok"


def test_crashpad_settings_are_decoded(tmp_path):
    client = uuid.uuid4()
    (tmp_path / "settings.dat").write_bytes(struct.pack("<IIIIq", ondisk.CRASHPAD_MAGIC, 1, 1, 0, 1700000000) + client.bytes_le)
    settings = ondisk.read_crashpad_settings(tmp_path / "settings.dat")
    assert settings == {"uploads_enabled": True, "last_upload_attempt": 1700000000, "client_id": str(client), "version": 1}
    (tmp_path / "bad.dat").write_bytes(b"\x00" * 40)
    assert ondisk.read_crashpad_settings(tmp_path / "bad.dat") is None


def test_app_folders_are_found_by_the_apps_own_folder_name(home):
    exes = [str(home / "LOCALAPPDATA" / "Discord" / "app-1.0.9" / "Discord.exe"),
            r"C:\Program Files\Google\Chrome\Application\chrome.exe"]
    keys = ondisk.keys_for(exes)
    assert "discord" in keys and "chrome" in keys and "google" not in keys and "app109" not in keys


def test_sentry_folder_is_read_and_ids_are_returned_for_hiding(home):
    sentry = home / "APPDATA" / "discord" / "sentry"
    (sentry / "queue").mkdir(parents=True)
    (sentry / "scope_v3.json").write_text(json.dumps({
        "scope": {"user": {"id": "42", "email": "me@example.com"}, "breadcrumbs": [
            {"category": "ui.click", "message": "button.send", "timestamp": 1.0}, {"category": "console", "message": "hi"}],
            "tags": {"channel": "stable"}},
        "event": {"release": "discord@1", "contexts": {"os": {"name": "Windows", "version": "10.0.26200"}}}}), encoding="utf-8")
    (sentry / "session.json").write_text(json.dumps({"did": "dev-9", "status": "ok"}), encoding="utf-8")
    (sentry / "queue" / "abc").write_bytes(envelope(("session", {"status": "ok"})))
    (home / "APPDATA" / "discord" / "Crashpad").mkdir()
    result = ondisk.for_app([str(home / "LOCALAPPDATA" / "Discord" / "app-1.0" / "Discord.exe")], "Discord")
    kinds = {source["kind"]: source for source in result["sources"]}
    assert set(kinds) == {"sentry", "crashpad"}
    sentry_source = kinds["sentry"]
    assert sentry_source["user"]["email"] == "me@example.com"
    assert sentry_source["breadcrumbs"][0]["text"] == "hi"             # newest first
    assert sentry_source["device"]["os"]["version"] == "10.0.26200"
    assert sentry_source["session"]["device_id"] == "dev-9" and sentry_source["queued_total"] == 1


def test_empty_crash_folders_are_left_out(home):
    (home / "APPDATA" / "SomeApp" / "crash_reports").mkdir(parents=True)
    assert ondisk.for_app([str(home / "APPDATA" / "SomeApp" / "SomeApp.exe")])["sources"] == []


@pytest.mark.parametrize("command, hidden", [
    ("app.exe --token=abc123 --flag", "--token=[hidden] --flag"),
    ('app.exe /password "p w"', '/password [hidden]'),
    ("app.exe --api-key xyz", "--api-key [hidden]"),
    ("app.exe --type=renderer", "--type=renderer"),
])
def test_command_lines_hide_secret_arguments(command, hidden):
    assert hidden in appdetail.hide_secrets(command)
