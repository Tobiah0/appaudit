"""Decoders for the trace events the helper listens to.

Each decoder takes an `etw.Event` and returns a small tuple or None. They are pure functions over
bytes so they can be tested with hand-built payloads. Layouts were read from the provider
manifests on Windows 11 build 26200 and checked against a live capture (see RESEARCH.md).
"""

from __future__ import annotations

import ipaddress
import re
import struct
from typing import NamedTuple

from ..etw import DNS_CLIENT, KERNEL_NETWORK, KERNEL_PROCESS, PKTMON, TASK_SCHEDULER, WEBIO, WININET, Event, guid_bytes

P_NETWORK = guid_bytes(KERNEL_NETWORK)
P_PROCESS = guid_bytes(KERNEL_PROCESS)
P_DNS = guid_bytes(DNS_CLIENT)
P_WEBIO = guid_bytes(WEBIO)
P_WININET = guid_bytes(WININET)
P_PKTMON = guid_bytes(PKTMON)
P_TASKS = guid_bytes(TASK_SCHEDULER)


class NetEvent(NamedTuple):
    kind: str            # send | recv | connect | accept | close
    proto: str           # tcp | udp
    pid: int
    size: int
    daddr: str
    saddr: str
    dport: int
    sport: int


_NET_KINDS = {
    10: ("send", "tcp", 4), 11: ("recv", "tcp", 4), 12: ("connect", "tcp", 4), 13: ("close", "tcp", 4),
    15: ("accept", "tcp", 4), 26: ("send", "tcp", 6), 27: ("recv", "tcp", 6), 28: ("connect", "tcp", 6),
    29: ("close", "tcp", 6), 31: ("accept", "tcp", 6), 42: ("send", "udp", 4), 43: ("recv", "udp", 4),
    58: ("send", "udp", 6), 59: ("recv", "udp", 6),
}


def _ip4(raw: bytes) -> str:
    return "%d.%d.%d.%d" % tuple(raw)


def _ip6(raw: bytes) -> str:
    text = str(ipaddress.IPv6Address(raw))
    return text[7:] if text.startswith("::ffff:") and "." in text else text


def network(event: Event) -> NetEvent | None:
    spec = _NET_KINDS.get(event.event_id)
    if spec is None:
        return None
    kind, proto, family = spec
    data = event.data
    try:
        pid, size = struct.unpack_from("<II", data, 0)
        if family == 4:
            daddr, saddr = _ip4(data[8:12]), _ip4(data[12:16])
            dport, sport = struct.unpack_from(">HH", data, 16)
        else:
            daddr, saddr = _ip6(data[8:24]), _ip6(data[24:40])
            dport, sport = struct.unpack_from(">HH", data, 40)
    except (struct.error, ValueError):
        return None
    return NetEvent(kind, proto, pid, size if kind in ("send", "recv") else 0, daddr, saddr, dport, sport)


def _wide(data: bytes, offset: int) -> tuple[str, int]:
    """Read a null-terminated UTF-16 string. Returns the text and the offset after it."""
    end = offset
    limit = len(data) - 1
    while end < limit and (data[end] or data[end + 1]):
        end += 2
    return data[offset:end].decode("utf-16-le", "replace"), end + 2


def _ansi(data: bytes, offset: int) -> tuple[str, int]:
    end = data.find(b"\x00", offset)
    if end < 0:
        end = len(data)
    return data[offset:end].decode("latin-1"), end + 1


class DnsAnswer(NamedTuple):
    pid: int
    name: str
    addresses: list[str]
    aliases: list[str]


_IP_TOKEN = re.compile(r"^(?:::ffff:)?((?:\d{1,3}\.){3}\d{1,3})$|^([0-9a-f:]+)$", re.IGNORECASE)


def dns(event: Event) -> DnsAnswer | None:
    """Event 3008: a lookup finished. The header process is the program that asked."""
    if event.event_id != 3008:
        return None
    data = event.data
    try:
        name, offset = _wide(data, 0)
        _qtype, _options, status = struct.unpack_from("<IQI", data, offset)
        results, _ = _wide(data, offset + 16)
    except struct.error:
        return None
    if status != 0 or not name:
        return None
    addresses, aliases = [], []
    for token in results.split(";"):
        token = token.strip()
        if not token:
            continue
        if token.lower().startswith("type:"):
            parts = token.split()
            if len(parts) >= 3:
                aliases.append(parts[-1].rstrip(".").lower())
            continue
        match = _IP_TOKEN.match(token)
        if match:
            addresses.append((match.group(1) or match.group(2)).lower())
    if not addresses:
        return None
    return DnsAnswer(event.pid, name.rstrip(".").lower(), addresses, aliases)


class ProcessStart(NamedTuple):
    pid: int
    parent: int
    image: str
    package: str
    filetime: int


def process_start(event: Event) -> ProcessStart | None:
    if event.event_id != 1:
        return None
    data = event.data
    try:
        pid = struct.unpack_from("<I", data, 0)[0]
        package = ""
        if event.version >= 3:
            created, parent = struct.unpack_from("<qI", data, 12)
            offset = 12 + 8 + 4 + 8 + 4 + 4 + 4 + 4            # up to the mandatory-label SID
            offset += 8 + 4 * data[offset + 1]                  # SID: 8 bytes plus sub-authorities
            image, offset = _wide(data, offset)
            package, _ = _wide(data, offset + 8)
        else:
            created, parent = struct.unpack_from("<qI", data, 4)
            offset = 4 + 8 + 4 + 4 + (4 if event.version >= 1 else 0)
            image, offset = _wide(data, offset)
            if event.version >= 2:
                package, _ = _wide(data, offset + 8)
    except (struct.error, IndexError):
        return None
    return ProcessStart(pid, parent, image, package, created or event.filetime)


def process_stop(event: Event) -> int | None:
    if event.event_id != 2 or len(event.data) < 4:
        return None
    return struct.unpack_from("<I", event.data, 0)[0]


class HttpRequest(NamedTuple):
    pid: int
    method: str
    url: str
    request: int = 0     # WinHTTP's request pointer; later header and body events carry the same one


def webio(event: Event) -> HttpRequest | None:
    """Event 17: WinHTTP created a request. Carries the method and the full URL."""
    if event.event_id != 17:
        return None
    try:
        request = struct.unpack_from("<Q", event.data, 0)[0]
        method, offset = _ansi(event.data, 32)
        url, _ = _wide(event.data, offset)
    except (struct.error, IndexError):
        return None
    return HttpRequest(event.pid, method, url, request) if url else None


class HttpContent(NamedTuple):
    pid: int
    request: int
    kind: str            # request_headers | response_headers | request_body
    data: bytes


def webio_content(event: Event) -> HttpContent | None:
    """Events 100 and 101 (headers sent and received) and 111 (a piece of the request body).

    Windows marks these as carrying personal data. The helper only asks for them when the person
    at the PC has switched content capture on.
    """
    data = event.data
    try:
        request = struct.unpack_from("<Q", data, 0)[0]
        if event.event_id in (100, 101):
            length = struct.unpack_from("<H", data, 8)[0]
            kind = "request_headers" if event.event_id == 100 else "response_headers"
            return HttpContent(event.pid, request, kind, data[10:10 + length])
        if event.event_id == 111:
            length = struct.unpack_from("<I", data, 36)[0]
            return HttpContent(event.pid, request, "request_body", data[40:40 + length])
    except struct.error:
        return None
    return None


def wininet(event: Event) -> HttpRequest | None:
    """Event 102: InternetOpenUrl. Event 103: InternetConnect (server name only)."""
    data = event.data
    try:
        if event.event_id == 102:
            length = struct.unpack_from("<H", data, 16)[0]
            return HttpRequest(event.pid, "GET", data[18:18 + length].decode("latin-1").rstrip("\x00"))
        if event.event_id == 103:
            length = struct.unpack_from("<H", data, 16)[0]
            server = data[18:18 + length].decode("latin-1").rstrip("\x00")
            port = struct.unpack_from("<I", data, 18 + length)[0]
            scheme = "http" if port == 80 else "https"
            return HttpRequest(event.pid, "", f"{scheme}://{server}/") if server else None
    except (struct.error, IndexError):
        return None
    return None


class TaskLaunch(NamedTuple):
    task: str
    path: str
    pid: int


def task_launch(event: Event) -> TaskLaunch | None:
    """Task Scheduler event 129: a task started a process."""
    if event.event_id != 129:
        return None
    try:
        task, offset = _wide(event.data, 0)
        path, offset = _wide(event.data, offset)
        pid = struct.unpack_from("<I", event.data, offset)[0]
    except struct.error:
        return None
    return TaskLaunch(task, path, pid)


def packet(event: Event) -> bytes | None:
    """Packet Monitor event 160: returns the raw frame (it may be truncated)."""
    if event.event_id != 160 or len(event.data) <= 34:
        return None
    return event.data[34:]
