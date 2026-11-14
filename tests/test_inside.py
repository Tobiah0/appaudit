"""Request content, built-in components, examples and data requests. Nothing here touches the PC
outside a temporary folder, and nothing is sent anywhere."""

import gzip
import struct
import time

from appaudit import datarequests, etw, examples, livestore, sdks
from appaudit.capture import decode, redact
from appaudit.capture.aggregate import Aggregator

FT = int((time.time() + livestore.EPOCH_DELTA) * 1e7)      # now: captured content older than a week is dropped
REQUEST = 0x1F2E3D4C5B6A


def event(event_id: int, data: bytes, pid: int = 4242) -> etw.Event:
    return etw.Event(etw.guid_bytes(etw.WEBIO), event_id, 0, pid, FT, data)


def created(url: str, method: bytes = b"POST") -> etw.Event:
    data = struct.pack("<QQQQ", REQUEST, 1, 2, 3) + method + b"\x00" + url.encode("utf-16-le") + b"\x00\x00"
    return event(17, data + struct.pack("<HHI", 1, 1, 0))


def headers(event_id: int, text: bytes) -> etw.Event:
    return event(event_id, struct.pack("<QH", REQUEST, len(text)) + text)


def body(chunk: bytes) -> etw.Event:
    return event(111, struct.pack("<QQQIQI", REQUEST, 7, 8, 0, 9, len(chunk)) + chunk)


def test_decode_request_content():
    request = decode.webio(created("https://telemetry.example.com/v1/events?key=abc"))
    assert request.request == REQUEST and request.method == "POST"
    sent = decode.webio_content(headers(100, b"POST /v1/events HTTP/1.1\r\nHost: telemetry.example.com\r\n\r\n"))
    assert (sent.kind, sent.request) == ("request_headers", REQUEST) and sent.data.startswith(b"POST /v1/events")
    assert decode.webio_content(headers(101, b"HTTP/1.1 200 OK\r\n\r\n")).kind == "response_headers"
    piece = decode.webio_content(body(b'{"event":"app_opened"}'))
    assert (piece.kind, piece.data) == ("request_body", b'{"event":"app_opened"}')


def test_redaction_hides_secrets_and_keeps_the_rest():
    block = redact.headers(b"POST /v1/e?token=abc123 HTTP/1.1\r\nHost: a.example.com\r\nAuthorization: Bearer abcdefghijklmnop\r\n"
                           b"Cookie: sid=12345\r\nX-Api-Key: secretvalue\r\nUser-Agent: App/1.2\r\n")
    assert "abc123" not in block and "abcdefghijklmnop" not in block and "12345" not in block and "secretvalue" not in block
    assert "User-Agent: App/1.2" in block and "Host: a.example.com" in block
    assert redact.header_value(block, "host") == "a.example.com"
    text = redact.body(b'{"event":"open","access_token":"qwertyuiop","user":"u1","password":"hunter22"}')
    assert "qwertyuiop" not in text and "hunter22" not in text and '"event":"open"' in text
    assert "hidden token" in redact.body(b"id=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijk")
    assert redact.body(gzip.compress(b'{"event":"zipped"}'), "gzip") == '{"event":"zipped"}'
    assert redact.body(bytes(range(256)) * 4).startswith("[1024 bytes")


def test_content_is_ignored_unless_switched_on(tmp_path):
    def run(on: bool) -> list:
        aggregator = Aggregator(lookup=lambda pid: {"name": "app.exe", "exe": r"C:\Apps\App\app.exe", "started": 1.0})
        aggregator.content = on
        aggregator.feed(created("https://telemetry.example.com/v1/events?key=abc"))
        aggregator.feed(headers(100, b"POST /v1/events HTTP/1.1\r\nHost: telemetry.example.com\r\nAuthorization: Bearer abcdefghijkl\r\n"))
        aggregator.feed(body(b'{"event":"app_opened","device_id":"D-1"}'))
        aggregator.feed(headers(101, b"HTTP/1.1 204 No Content\r\n"))
        conn = livestore.connect(file=tmp_path / f"live-{on}.db")
        aggregator.flush(conn)
        rows = conn.execute("SELECT * FROM payloads").fetchall()
        conn.close()
        return rows

    assert run(False) == []
    rows = run(True)
    assert len(rows) == 1
    row = rows[0]
    assert row["host"] == "telemetry.example.com" and row["url"] == "https://telemetry.example.com/v1/events"
    assert "abcdefghijkl" not in row["request_headers"] and '"device_id":"D-1"' in row["body"]
    assert row["response_headers"].startswith("HTTP/1.1 204") and row["body_size"] == 40


def test_only_a_few_examples_are_kept_per_host(tmp_path):
    aggregator = Aggregator(lookup=lambda pid: {"name": "app.exe", "exe": r"C:\Apps\App\app.exe", "started": 1.0})
    aggregator.content = True
    conn = livestore.connect(file=tmp_path / "live.db")
    for index in range(9):
        aggregator.feed(created("https://telemetry.example.com/v1/events"))
        aggregator.feed(body(f'{{"n":{index}}}'.encode()))
        aggregator.feed(headers(101, b"HTTP/1.1 200 OK\r\n"))
        aggregator.flush(conn)
    assert conn.execute("SELECT COUNT(*) FROM payloads").fetchone()[0] == 5
    conn.close()


def test_component_scan_reads_plain_and_wide_text(tmp_path):
    app = tmp_path / "Vendor" / "App"
    (app / "resources").mkdir(parents=True)
    (app / "app.exe").write_bytes(b"\x00" * 300 + "https://o1.ingest.sentry.io/api/5/".encode("utf-16-le") + b"\x00" * 300)
    (app / "resources" / "app.asar").write_bytes(b"x" * 500 + b"https://API.Segment.IO/v1/track" + b"y" * 500)
    (app / "crashpad_handler.exe").write_bytes(b"MZ" + b"\x00" * 200)
    (app / "notes.txt").write_bytes(b"api.amplitude.com")                    # not a file type the scan reads
    blocklist = b" ".join([b"ingest.sentry.io", b"api.segment.io", b"api.amplitude.com", b"api.mixpanel.com",
                           b"heapanalytics.com", b"app.adjust.com"]) + b" " * 100
    (app / "trackers.dat").write_bytes(blocklist)                            # a list of trackers, not a component
    (app / "bundle.js").write_bytes(b"api.segment.io ingest.sentry.io")     # program code is never taken for a list
    result = sdks.scan_folder(str(app))
    found = {item["id"]: item for item in result["found"]}
    assert set(found) == {"sentry", "segment", "crashpad"} and result["complete"]
    assert found["segment"]["evidence"][0] == {"file": "resources\\app.asar", "match": "api.segment.io"}
    described = sdks.describe(result["found"], ["o1.ingest.sentry.io", "example.org"])
    by_id = {item["id"]: item for item in described}
    assert by_id["sentry"]["seen_talking_to"] == ["o1.ingest.sentry.io"] and by_id["segment"]["seen_talking_to"] == []


def test_component_scan_reads_only_the_newest_version_and_refuses_shared_folders(tmp_path):
    root = tmp_path / "Vendor" / "App"
    old, new = root / "app-1.0.1", root / "app-1.0.2"
    old.mkdir(parents=True)
    new.mkdir()
    (old / "a.dll").write_bytes(b"z" * 100 + b"api.mixpanel.com" + b"z" * 100)
    (new / "a.dll").write_bytes(b"z" * 100 + b"api.amplitude.com" + b"z" * 100)
    stub = root / "app-1.0.3"                              # an updater's leftover: newest name, nearly empty
    stub.mkdir()
    (stub / "a.dll").write_bytes(b"z" * 100 + b"api.rollbar.com" + b"z" * 100)
    for index in range(5):
        (new / f"extra{index}.txt").write_bytes(b"-")
    assert [item["id"] for item in sdks.scan_folder(str(root))["found"]] == ["amplitude"]
    assert sdks.roots_for([str(old / "app.exe"), str(new / "app.exe")]) == [str(new)]
    assert sdks.roots_for([r"C:\Windows\System32\svchost.exe", r"C:\Program Files\tool.exe"]) == []


def test_documented_examples_match_by_host_suffix():
    doc = examples.documented("browser-intake-datadoghq.com")
    assert doc is None                                   # a different site, not a subdomain of datadoghq.com
    doc = examples.documented("http-intake.logs.datadoghq.com")
    assert doc["id"] == "datadog-log" and doc["url"].startswith("https://") and "message" in doc["sample"]
    assert examples.documented(example_id="sentry-event")["company"] == "Sentry"
    assert examples.documented("example.org") is None
    for sdk in sdks.catalogue().values():                # every example a component points at exists
        if sdk.get("example"):
            assert examples.documented(example_id=sdk["example"]), sdk["id"]


ACTORS = [
    {"name": "Notes", "publisher": "Anthropic PBC", "first": 1794600000.0, "last": 1794640000.0, "destinations": [
        {"name": "api.anthropic.com", "company": "Anthropic", "category": "ai", "sent": 500_000},
        {"name": "http-intake.logs.datadoghq.com", "company": "Datadog", "category": "telemetry", "sent": 2_000_000},
        {"name": None, "company": "Your local network", "category": "local", "sent": 5}]},
    {"name": "Player", "publisher": "Spotify AB", "first": 1794600000.0, "last": 1794640000.0, "destinations": [
        {"name": "spclient.wg.spotify.com", "company": "Spotify", "category": "content", "sent": 9000}]},
]


def test_letter_quotes_what_was_observed():
    assert datarequests.company_for("Anthropic PBC") == "Anthropic" and datarequests.company_for("Spotify AB") == "Spotify"
    assert datarequests.company_for("Parsec Cloud Inc.") == "Parsec Cloud"
    evidence = datarequests.evidence_from(ACTORS, "Anthropic")
    assert [item["app"] for item in evidence] == ["Notes"] and len(evidence[0]["hosts"]) == 2
    letter = datarequests.draft("Anthropic", evidence, {"name": "Sam Example", "email": "sam@example.org", "law": "gdpr"})
    assert "Article 15" in letter["body"] and "within one month" in letter["body"] and letter["days"] == 31
    assert "http-intake.logs.datadoghq.com, operated by Datadog (1.9 MB sent)" in letter["body"]
    assert "Please include what they hold on your behalf: Datadog." in letter["body"]
    assert "Sam Example" in letter["body"] and letter["contact"]["role"] == "controller"
    processor = datarequests.evidence_from(ACTORS, "Datadog")
    assert [item["app"] for item in processor] == ["Notes"] and datarequests.contact("Datadog")["role"] == "processor"
    assert datarequests.contact("Nobody Ltd") == {"company": "Nobody Ltd", "role": "unknown", "known": False}
    assert "[your name]" in datarequests.draft("Spotify", [], {})["body"]


def test_request_record_tracks_the_due_date(tmp_path):
    file = tmp_path / "appaudit.db"
    assert datarequests.profile(file)["law"] == "other"
    assert datarequests.save_profile({"name": "Sam", "law": "nonsense"}, file)["law"] == "other"
    datarequests.save_profile({"name": "Sam Example", "email": "sam@example.org", "law": "ccpa"}, file)
    who = datarequests.profile(file)
    letter = datarequests.draft("Spotify", datarequests.evidence_from(ACTORS, "Spotify"), who)
    start = 1794640000.0
    request_id = datarequests.save(letter, ["Player"], file, now=start)
    assert datarequests.listing(file, now=start)[0]["state"] == "draft"
    datarequests.update(request_id, "sent", file, now=start)
    item = datarequests.listing(file, now=start + 86400)[0]
    assert (item["state"], item["days_left"], item["about"]) == ("waiting", 44, ["Player"])
    late = datarequests.listing(file, now=start + 46 * 86400)[0]
    assert late["state"] == "overdue"
    reminder = datarequests.reminder(late, who)
    assert reminder["subject"].startswith("Reminder:") and letter["body"] in reminder["body"]
    datarequests.update(request_id, "answered", file, now=start + 47 * 86400)
    assert datarequests.listing(file, now=time.time())[0]["state"] == "answered"
    datarequests.update(request_id, "delete", file)
    assert datarequests.listing(file) == []
