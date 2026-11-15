"""Reading a Chromium network log, with a hand-built log: HTTP/2 frames and an HTTP/1.1 request."""

import base64
import gzip
import json

import pytest

from appaudit import inspection, netlog

TYPES = {"URL_REQUEST_START_JOB": 1, "HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS": 2, "HTTP_TRANSACTION_SEND_REQUEST_HEADERS": 3,
         "HTTP_TRANSACTION_READ_RESPONSE_HEADERS": 4, "HTTP_STREAM_REQUEST_BOUND_TO_JOB": 5, "HTTP2_SESSION_INITIALIZED": 6,
         "HTTP2_SESSION_SEND_HEADERS": 7, "SSL_SOCKET_BYTES_SENT": 8, "SOCKET_POOL_BOUND_TO_SOCKET": 9}


def frame(kind: int, stream: int, payload: bytes, flags: int = 0) -> bytes:
    return len(payload).to_bytes(3, "big") + bytes([kind, flags]) + stream.to_bytes(4, "big") + payload


def ev(kind: str, source: int, params: dict | None = None, time: int = 1000) -> dict:
    event = {"type": TYPES[kind], "source": {"id": source, "type": 1}, "time": str(time), "phase": 1}
    if params is not None:
        event["params"] = params
    return event


def build_log() -> dict:
    telemetry = b"\n".join(json.dumps({"name": n, "data": {"machineId": "m-123", "email": "me@example.com", "ok": 1}}).encode()
                           for n in ("app/start", "app/click", "app/click"))
    body = gzip.compress(telemetry)
    h2 = netlog.PREFACE + frame(4, 0, b"") + frame(1, 1, b"\x82") + frame(0, 1, body[:20]) + frame(0, 1, body[20:], flags=1)
    h1 = (b"POST /collect?token=abc123&v=2 HTTP/1.1\r\nHost: t.example\r\nContent-Length: 13\r\n\r\nuser_id=42&x=")
    events = [
        ev("URL_REQUEST_START_JOB", 10, {"url": "https://events.example.com/v1", "method": "POST"}),
        ev("URL_REQUEST_START_JOB", 10),                                         # the END entry has no params
        ev("HTTP_STREAM_REQUEST_BOUND_TO_JOB", 10, {"source_dependency": {"id": 20, "type": 17}}),
        ev("HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS", 10, {"headers": [":method: POST", "content-encoding: gzip",
                                                                         "authorization: Bearer abcdefghijklmnop", "content-type: application/json"]}),
        ev("HTTP2_SESSION_INITIALIZED", 30, {"source_dependency": {"id": 40, "type": 10}}),
        ev("HTTP2_SESSION_SEND_HEADERS", 30, {"source_dependency": {"id": 20, "type": 17}, "stream_id": 1, "headers": []}),
        ev("SSL_SOCKET_BYTES_SENT", 40, {"byte_count": 10, "bytes": base64.b64encode(h2[:25]).decode()}),
        ev("SSL_SOCKET_BYTES_SENT", 40, {"byte_count": 10, "bytes": base64.b64encode(h2[25:]).decode()}),
        ev("HTTP_TRANSACTION_READ_RESPONSE_HEADERS", 10, {"headers": ["HTTP/1.1 204", "date: x"]}),
        ev("URL_REQUEST_START_JOB", 11, {"url": "https://t.example/collect?token=abc123&v=2", "method": "POST"}, time=2000),
        ev("HTTP_STREAM_REQUEST_BOUND_TO_JOB", 11, {"source_dependency": {"id": 21, "type": 17}}),
        ev("SOCKET_POOL_BOUND_TO_SOCKET", 21, {"source_dependency": {"id": 41, "type": 10}}),
        ev("HTTP_TRANSACTION_SEND_REQUEST_HEADERS", 11, {"headers": ["Host: t.example", "Content-Length: 13"]}),
        ev("SSL_SOCKET_BYTES_SENT", 41, {"bytes": base64.b64encode(h1).decode()}),
    ]
    return {"constants": {"logEventTypes": TYPES, "logCaptureMode": "Everything"}, "events": events}


def test_http2_request_body_is_found_decompressed_and_summarised():
    first, second = netlog.requests_in(build_log())
    assert first["url"] == "https://events.example.com/v1" and first["status"] == "204"
    assert first["body_note"] == "gzip" and first["body_decoded_size"] > first["body_size"] - 100
    summary = first["summary"]
    assert summary["records"] == 3 and dict(summary["event_names"]) == {"app/click": 2, "app/start": 1}
    assert summary["identifying"]["data.machineId"] == "m-123" and summary["identifying"]["data.email"] == "me@example.com"
    assert "abcdefghijklmnop" not in first["request_headers"]                 # sign-in header hidden


def test_http1_request_body_and_secret_query_values_are_hidden():
    _, second = netlog.requests_in(build_log())
    assert second["body"] == "user_id=42&x="
    assert "abc123" not in second["url"] and "v=2" in second["url"]
    assert second["summary"]["format"] == "form" and "user_id" in second["summary"]["fields"]


def test_unfinished_log_is_read_up_to_the_last_complete_event():
    text = json.dumps(build_log())
    cut = text[:text.rfind('{"type"')] + '{"type": 8, "sour'                 # the app was closed mid-write
    assert len(netlog.load(cut)["events"]) == len(build_log()["events"]) - 1


def test_file_reader_keeps_request_events_and_skips_the_rest(tmp_path):
    log = build_log()
    log["constants"]["logEventTypes"]["SSL_SOCKET_BYTES_RECEIVED"] = 99
    received = {"params": {"bytes": "AAAA" * 1000}, "phase": 0, "source": {"id": 40, "type": 10}, "time": "1", "type": 99}
    lines = ['{"constants": ' + json.dumps(log["constants"]) + ",", '"events": [']
    lines += [json.dumps(event, sort_keys=True) + "," for event in log["events"] + [received]]
    path = tmp_path / "net.json"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")            # unfinished: the app was killed
    loaded = netlog.load_file(path)
    assert len(loaded["events"]) == len(log["events"])                    # the received bytes were skipped
    assert netlog.report_file(path)["requests"][0]["summary"]["records"] == 3


def test_report_groups_by_destination():
    report = netlog.report(json.dumps(build_log()))
    hosts = {entry["host"]: entry for entry in report["hosts"]}
    assert hosts["events.example.com"]["event_names"][0] == ("app/click", 2)
    assert "data.email" in hosts["events.example.com"]["identifying"]


def test_inspection_refuses_to_start_a_running_app(monkeypatch, tmp_path):
    exe = tmp_path / "App.exe"
    exe.write_bytes(b"MZ")
    monkeypatch.setattr(inspection, "running", lambda path: [{"pid": 1, "name": "App.exe", "since": 0}])
    with pytest.raises(inspection.Running):
        inspection.start("actor", "App", str(exe))


def test_candidates_put_the_main_chromium_program_first(tmp_path):
    (tmp_path / "app-1.0").mkdir()
    main = tmp_path / "app-1.0" / "Chat.exe"
    main.write_bytes(b"MZ")
    (tmp_path / "app-1.0" / "resources.pak").write_bytes(b"")
    update = tmp_path / "Update.exe"
    update.write_bytes(b"MZ")
    found = inspection.candidates([str(update), str(main), r"C:\Windows\System32\svchost.exe"])
    assert [item["name"] for item in found] == ["Chat.exe", "Update.exe"]
    assert found[0]["main"] and found[0]["chromium"] and not found[1]["main"]
