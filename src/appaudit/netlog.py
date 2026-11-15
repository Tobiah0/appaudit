"""Read a Chromium network log: every request an app made, with headers and body.

Chromium, and every app built on it (Electron apps such as VS Code, Discord, Slack, Notion), can
write a log of its own network activity: `--log-net-log=<file> --net-log-capture-mode=Everything`.
At that level the log includes request headers and the bytes sent on each connection after the
app's own encryption, so the requests can be read without intercepting anything.

This module turns such a log into a list of requests:

  URL_REQUEST           url, method, request headers, response status and headers
  -> HTTP_STREAM_JOB    (HTTP_STREAM_REQUEST_BOUND_TO_JOB)
  -> HTTP2_SESSION      SEND_HEADERS names the job and the stream id
  -> SOCKET             (HTTP2_SESSION_INITIALIZED) whose SSL_SOCKET_BYTES_SENT carry the frames;
                        DATA frames of that stream are the request body.
  HTTP/1.1              the socket bytes are plain requests; bodies follow by Content-Length.

Bodies are decompressed (gzip, deflate, zstd), summarised (records, event names, fields that
identify a person) and stored with secrets replaced, the same way request content recording does.
"""

from __future__ import annotations

import base64
import json
import re
import zlib
from collections import defaultdict, Counter

from .capture import redact

MAX_BODY_TEXT = 60_000
PERSONAL = re.compile(r"(e-?mail|user(name|_?id)?$|^uid$|account|device_?id|machine_?id|install_?id|client_?id|session_?id|"
                      r"^did$|^sid$|ip_?addr|^ip$|phone|hostname|computer_?name|serial|advertising_?id|"
                      r"(full|first|last|display|user|machine)_?name)", re.IGNORECASE)
EVENT_KEYS = ("name", "event", "eventName", "event_name", "eventType", "event_type", "type", "action", "category")


# --- loading --------------------------------------------------------------------------------

def load(text: str) -> dict:
    """The log as JSON, also when the app was closed before it finished writing the file."""
    try:
        return json.loads(text)
    except ValueError:
        pass
    end = text.rfind("},")
    while end > 0:
        try:
            return json.loads(text[:end + 1] + "]}")
        except ValueError:
            end = text.rfind("},", 0, end)
    raise ValueError("not a network log")


NEEDED = {"URL_REQUEST_START_JOB", "HTTP_TRANSACTION_SEND_REQUEST_HEADERS", "HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS",
          "HTTP_TRANSACTION_QUIC_SEND_REQUEST_HEADERS", "HTTP_TRANSACTION_READ_RESPONSE_HEADERS", "HTTP_STREAM_REQUEST_BOUND_TO_JOB",
          "HTTP2_SESSION_INITIALIZED", "HTTP2_SESSION_SEND_HEADERS", "SOCKET_POOL_BOUND_TO_SOCKET", "SSL_SOCKET_BYTES_SENT",
          "TCP_CONNECT"}
_EVENT_TYPE = re.compile(rb'"type":\s*(\d+)\s*\}\s*,?\s*$')


def load_file(path) -> dict:
    """The log from a file, keeping only the events about requests sent.

    With full capture a log grows by gigabytes, mostly the bytes the app received. Chromium writes
    one event per line with its keys sorted, so the event type is the last key on the line and the
    events not needed are skipped without being parsed.
    """
    events = []
    with open(path, "rb") as file:
        first = file.readline()                       # {"constants": {...},
        try:
            constants = json.loads(first.rstrip().rstrip(b",").decode("utf-8", "replace") + "}")["constants"]
        except (ValueError, KeyError, TypeError):
            # Not in Chromium's one-event-per-line layout: read it whole (only small files get here).
            file.seek(0)
            return load(file.read().decode("utf-8", "replace"))
        wanted = {value for key, value in (constants.get("logEventTypes") or {}).items() if key in NEEDED}
        for line in file:
            match = _EVENT_TYPE.search(line)
            if not match or int(match.group(1)) not in wanted:
                continue                              # "events": [, the closing ]}, and unneeded events
            try:
                events.append(json.loads(line.rstrip().rstrip(b",").decode("utf-8", "replace")))
            except ValueError:
                continue
    return {"constants": constants, "events": events}


def _dep(params: dict) -> int | None:
    dependency = params.get("source_dependency")
    return dependency.get("id") if isinstance(dependency, dict) else None


# --- HTTP/2 and HTTP/1.1 from the bytes sent on a connection ----------------------------------

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def http2_data(stream: bytes) -> dict[int, bytes]:
    """Request bodies per stream id from the frames a client sent."""
    if stream.startswith(PREFACE):
        stream = stream[len(PREFACE):]
    bodies: dict[int, bytearray] = defaultdict(bytearray)
    index = 0
    while index + 9 <= len(stream):
        length = int.from_bytes(stream[index:index + 3], "big")
        kind, flags = stream[index + 3], stream[index + 4]
        stream_id = int.from_bytes(stream[index + 5:index + 9], "big") & 0x7FFFFFFF
        payload = stream[index + 9:index + 9 + length]
        if kind == 0 and stream_id:                         # DATA
            if flags & 0x8 and payload:                     # PADDED
                pad = payload[0]
                payload = payload[1:len(payload) - pad]
            bodies[stream_id] += payload
        index += 9 + length
    return {key: bytes(value) for key, value in bodies.items()}


def http1_requests(stream: bytes) -> list[dict]:
    """Plain HTTP/1.1 requests (request line, headers, body) in the bytes sent on a connection."""
    found, index = [], 0
    while index < len(stream):
        end = stream.find(b"\r\n\r\n", index)
        if end < 0:
            break
        head = stream[index:end].decode("latin-1", "replace").split("\r\n")
        request_line = head[0].split(" ")
        if len(request_line) < 3 or not request_line[2].startswith("HTTP/"):
            break
        headers = {line.split(":", 1)[0].strip().lower(): line.split(":", 1)[1].strip() for line in head[1:] if ":" in line}
        length = int(headers.get("content-length", "0") or 0) if headers.get("content-length", "0").isdigit() else 0
        found.append({"method": request_line[0], "path": request_line[1], "body": stream[end + 4:end + 4 + length]})
        index = end + 4 + length
    return found


# --- bodies ---------------------------------------------------------------------------------

def decode(body: bytes, encoding: str) -> tuple[bytes, str]:
    """(decoded bytes, note). Unknown encodings come back as they are, with a note."""
    encoding = (encoding or "").lower()
    try:
        if "gzip" in encoding or body[:2] == b"\x1f\x8b":
            return zlib.decompress(body, 47), "gzip"
        if "deflate" in encoding:
            try:
                return zlib.decompress(body), "deflate"
            except zlib.error:
                return zlib.decompress(body, -15), "deflate"
        if "zstd" in encoding or body[:4] == b"\x28\xb5\x2f\xfd":
            from compression import zstd

            return zstd.decompress(body), "zstd"
        if "br" in encoding:
            return body, "compressed with brotli; not decoded"
    except Exception as error:  # noqa: BLE001 - a broken body is shown as it is
        return body, f"could not decompress ({type(error).__name__})"
    return body, ""


def _records(text: str) -> list:
    """JSON records in a body: one document, or one per line (JSON lines)."""
    text = text.strip()
    if not text or text[0] not in "[{":
        return []
    try:
        document = json.loads(text)
        return document if isinstance(document, list) else [document]
    except ValueError:
        pass
    records = []
    for line in text.splitlines():
        line = line.strip()
        if line[:1] in "[{":
            try:
                records.append(json.loads(line))
            except ValueError:
                return []
    return records


def _walk(value, path: str, out: list, depth: int = 0) -> None:
    if depth > 6 or len(out) > 2000:
        return
    if isinstance(value, dict):
        for key, child in value.items():
            _walk(child, f"{path}.{key}" if path else key, out, depth + 1)
    elif isinstance(value, list):
        for child in value[:50]:
            _walk(child, path, out, depth + 1)
    else:
        out.append((path, value))


def summarise(text: str, content_type: str = "") -> dict:
    """What a body holds, in terms a person can check: records, event names, identifying fields."""
    records = _records(text)
    if not records:
        if "x-www-form-urlencoded" in content_type or re.fullmatch(r"[\w.%-]+=[^&\s]*(&[\w.%-]+=[^&\s]*)*", text.strip() or "x"):
            fields = [pair.split("=", 1)[0] for pair in text.strip().split("&") if pair]
            return {"format": "form", "fields": fields[:60]}
        printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in text[:2000]) / max(1, len(text[:2000]))
        return {"format": "text" if printable > 0.9 else "binary"}
    leaves: list[tuple[str, object]] = []
    for record in records[:500]:
        _walk(record, "", leaves)
    names = Counter()
    for record in records[:2000]:
        if isinstance(record, dict):
            for key in EVENT_KEYS:
                value = record.get(key)
                if isinstance(value, str) and 0 < len(value) < 120:
                    names[value] += 1
                    break
    fields = Counter(path for path, _ in leaves)
    personal = {}
    for path, value in leaves:
        last = path.rsplit(".", 1)[-1]
        if PERSONAL.search(last) and value not in (None, "", 0) and path not in personal:
            personal[path] = str(value)[:200]
    return {"format": "json", "records": len(records), "event_names": names.most_common(40),
            "fields": [path for path, _ in fields.most_common(80)], "identifying": personal}


def _safe_text(body: bytes) -> str:
    text = body.decode("utf-8", "replace")
    text = redact._SECRET_FIELD.sub(lambda m: m.group(1) + redact.hidden(m.group(2)) + m.group(3), text)
    text = redact._SECRET_FORM.sub(lambda m: m.group(1) + redact.hidden(m.group(2)), text)
    return redact._JWT.sub("[hidden token]", redact._BEARER.sub(lambda m: f"{m.group(1)} [hidden]", text))


def safe_url(url: str) -> str:
    """The address with secret-looking query values hidden."""
    base, _, query = url.partition("?")
    if not query:
        return url
    return base + "?" + redact._SECRET_FORM.sub(lambda m: m.group(1) + "[hidden]", query.replace("&", " &")).replace(" &", "&")


def _headers_text(lines: list[str]) -> str:
    return redact.headers("\r\n".join(["request"] + lines).encode("latin-1", "replace")).split("\n", 1)[-1]


# --- the whole log ----------------------------------------------------------------------------

def requests_in(log: dict) -> list[dict]:
    constants = log.get("constants") or {}
    types = {value: key for key, value in (constants.get("logEventTypes") or {}).items()}
    events = log.get("events") or []

    urls: dict[int, dict] = {}
    job_of_request: dict[int, int] = {}
    request_of_job: dict[int, int] = {}
    socket_of_session: dict[int, int] = {}
    stream_of_job: dict[int, tuple[int, int]] = {}
    sent: dict[int, bytearray] = defaultdict(bytearray)
    socket_of_job: dict[int, int] = {}
    remote_of_socket: dict[int, str] = {}

    for event in events:
        kind = types.get(event.get("type"))
        source = (event.get("source") or {}).get("id")
        params = event.get("params") or {}
        if kind == "URL_REQUEST_START_JOB" and params.get("url"):      # the BEGIN entry; END has no params
            urls[source] = {"url": params.get("url", ""), "method": params.get("method", ""), "time": event.get("time"),
                            "initiator": params.get("initiator"), "request_headers": [], "status": None,
                            "response_headers": [], "upload": None}
        elif kind in ("HTTP_TRANSACTION_SEND_REQUEST_HEADERS", "HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS",
                      "HTTP_TRANSACTION_QUIC_SEND_REQUEST_HEADERS") and source in urls:
            urls[source]["request_headers"] = list(params.get("headers") or [])
        elif kind == "HTTP_TRANSACTION_READ_RESPONSE_HEADERS" and source in urls:
            headers = list(params.get("headers") or [])
            urls[source]["response_headers"] = headers
            if headers:
                urls[source]["status"] = headers[0].split(" ", 2)[1] if " " in headers[0] else headers[0]
        elif kind == "HTTP_STREAM_REQUEST_BOUND_TO_JOB" and _dep(params) is not None:
            job_of_request[source] = _dep(params)
            request_of_job[_dep(params)] = source
        elif kind == "HTTP2_SESSION_INITIALIZED" and _dep(params) is not None:
            socket_of_session[source] = _dep(params)
        elif kind == "HTTP2_SESSION_SEND_HEADERS" and _dep(params) is not None:
            stream_of_job[_dep(params)] = (source, int(params.get("stream_id") or 0))
        elif kind in ("SOCKET_POOL_BOUND_TO_SOCKET",) and _dep(params) is not None:
            socket_of_job[source] = _dep(params)
        elif kind == "SSL_SOCKET_BYTES_SENT" and params.get("bytes"):
            try:
                sent[source] += base64.b64decode(params["bytes"])
            except ValueError:
                pass
        elif kind == "TCP_CONNECT" and params.get("address_list"):
            remote_of_socket[source] = str(params["address_list"][0]) if isinstance(params["address_list"], list) else str(params["address_list"])

    h2_bodies: dict[int, dict[int, bytes]] = {}
    h1_bodies: dict[int, list[dict]] = {}
    results = []
    for source, request in urls.items():
        job = job_of_request.get(source)
        body = b""
        if job in stream_of_job:
            session, stream_id = stream_of_job[job]
            socket = socket_of_session.get(session)
            if socket is not None:
                if socket not in h2_bodies:
                    h2_bodies[socket] = http2_data(bytes(sent.get(socket, b"")))
                body = h2_bodies[socket].get(stream_id, b"")
        else:
            socket = socket_of_job.get(job) or socket_of_job.get(source)
            if socket is not None:
                if socket not in h1_bodies:
                    h1_bodies[socket] = http1_requests(bytes(sent.get(socket, b"")))
                path = "/" + request["url"].split("://", 1)[-1].split("/", 1)[-1] if "/" in request["url"].split("://", 1)[-1] else "/"
                match = next((item for item in h1_bodies[socket] if item["path"] == path and item["method"] == request["method"]), None)
                if match:
                    body = match["body"]
                    h1_bodies[socket].remove(match)
        headers = {line.split(":", 1)[0].strip().lower(): line.split(":", 1)[1].strip()
                   for line in request["request_headers"] if ":" in line.lstrip(":")}
        decoded, note = decode(body, headers.get("content-encoding", "")) if body else (b"", "")
        text = decoded.decode("utf-8", "replace") if decoded else ""
        host = request["url"].split("://", 1)[-1].split("/", 1)[0]
        results.append({
            "time": request["time"], "method": request["method"], "url": safe_url(request["url"]), "host": host,
            "status": request["status"], "initiator": request["initiator"],
            "request_headers": _headers_text(request["request_headers"]) if request["request_headers"] else "",
            "response_headers": _headers_text(request["response_headers"]) if request["response_headers"] else "",
            "body_size": len(body), "body_decoded_size": len(decoded), "body_note": note,
            "body": _safe_text(decoded[:MAX_BODY_TEXT]) if decoded else "",
            "body_truncated": len(decoded) > MAX_BODY_TEXT,
            "summary": summarise(text, headers.get("content-type", "")) if text else None,
        })
    results.sort(key=lambda item: float(item["time"] or 0))
    return results


def report(text: str) -> dict:
    """Requests, plus an overview per destination."""
    return report_from(load(text))


def report_file(path) -> dict:
    return report_from(load_file(path))


def report_from(log: dict) -> dict:
    return {**overview(requests_in(log)), "capture_mode": (log.get("constants") or {}).get("logCaptureMode")}


def overview(requests: list[dict]) -> dict:
    """Requests plus a summary per destination; shared by the Chromium and Firefox readers."""
    hosts: dict[str, dict] = {}
    for item in requests:
        entry = hosts.setdefault(item["host"], {"host": item["host"], "requests": 0, "sent": 0, "with_body": 0,
                                                "identifying": set(), "event_names": Counter()})
        entry["requests"] += 1
        entry["sent"] += item["body_size"]
        entry["with_body"] += 1 if item["body_size"] else 0
        summary = item["summary"] or {}
        entry["identifying"] |= set((summary.get("identifying") or {}).keys())
        for name, count in summary.get("event_names") or []:
            entry["event_names"][name] += count
    summary = [{**entry, "identifying": sorted(entry["identifying"])[:30], "event_names": entry["event_names"].most_common(25)}
                for entry in hosts.values()]
    summary.sort(key=lambda entry: (-entry["sent"], -entry["requests"]))
    return {"requests": requests, "hosts": summary}
