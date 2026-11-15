"""Minimal frame parsing: find DNS answers and TLS server names in captured packets.

Frames arrive as Ethernet from wired adapters and as raw 802.11 data frames from Wi-Fi.
"""

from __future__ import annotations

import struct
from typing import NamedTuple

from .decode import _ip4, _ip6


class Segment(NamedTuple):
    proto: int           # 6 TCP, 17 UDP
    src: str
    dst: str
    sport: int
    dport: int
    payload: bytes


def _network_layer(frame: bytes) -> tuple[int, int] | None:
    """Return (ethertype, offset of the IP header)."""
    if len(frame) < 34:
        return None
    ethertype = struct.unpack_from(">H", frame, 12)[0]
    if ethertype in (0x0800, 0x86DD):
        return ethertype, 14
    if ethertype == 0x8100 and len(frame) >= 18:           # VLAN tag
        return struct.unpack_from(">H", frame, 16)[0], 18
    # 802.11 data frame: 24-byte header (26 with QoS), then LLC/SNAP aa aa 03 00 00 00 <ethertype>.
    if frame[0] & 0x0C == 0x08:
        header = 26 if frame[0] & 0x80 else 24
        if frame[header:header + 3] == b"\xaa\xaa\x03" and len(frame) >= header + 8:
            return struct.unpack_from(">H", frame, header + 6)[0], header + 8
    return None


def segment(frame: bytes) -> Segment | None:
    layer = _network_layer(frame)
    if layer is None:
        return None
    ethertype, offset = layer
    try:
        if ethertype == 0x0800:
            header_length = (frame[offset] & 0x0F) * 4
            proto = frame[offset + 9]
            src, dst = _ip4(frame[offset + 12:offset + 16]), _ip4(frame[offset + 16:offset + 20])
            transport = offset + header_length
        elif ethertype == 0x86DD:
            proto = frame[offset + 6]
            src, dst = _ip6(frame[offset + 8:offset + 24]), _ip6(frame[offset + 24:offset + 40])
            transport = offset + 40
        else:
            return None
        sport, dport = struct.unpack_from(">HH", frame, transport)
        if proto == 17:
            return Segment(proto, src, dst, sport, dport, frame[transport + 8:])
        if proto == 6:
            data_offset = (frame[transport + 12] >> 4) * 4
            return Segment(proto, src, dst, sport, dport, frame[transport + data_offset:])
    except (IndexError, struct.error):
        return None
    return None


def _dns_name(message: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
    labels = []
    jumped_to = None
    while True:
        length = message[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if depth > 8:
                raise ValueError("compression loop")
            pointer = ((length & 0x3F) << 8) | message[offset + 1]
            if jumped_to is None:
                jumped_to = offset + 2
            offset = pointer
            depth += 1
            continue
        labels.append(message[offset + 1:offset + 1 + length].decode("ascii", "replace"))
        offset += 1 + length
    return ".".join(labels).lower(), (jumped_to if jumped_to is not None else offset)


def dns_answers(message: bytes) -> tuple[str, list[str]] | None:
    """Parse a DNS response. Returns the question name and the addresses in the answer."""
    try:
        flags, questions, answers = struct.unpack_from(">HHH", message, 2)
        if not flags & 0x8000 or questions < 1:
            return None
        name, offset = _dns_name(message, 12)
        offset += 4
        addresses = []
        for _ in range(answers):
            _owner, offset = _dns_name(message, offset)
            rtype, _rclass, _ttl, length = struct.unpack_from(">HHIH", message, offset)
            offset += 10
            if rtype == 1 and length == 4:
                addresses.append(_ip4(message[offset:offset + 4]))
            elif rtype == 28 and length == 16:
                addresses.append(_ip6(message[offset:offset + 16]))
            offset += length
    except (IndexError, struct.error, ValueError):
        return None
    return (name, addresses) if name and addresses else None


ECH_EXTENSION = 0xFE0D          # Encrypted Client Hello: the server name sent is only an outer cover name


def client_hello(payload: bytes) -> dict | None:
    """Server name and whether Encrypted Client Hello hides the real one, from a whole ClientHello."""
    try:
        if payload[0] != 0x16 or payload[5] != 0x01:
            return None
        offset = 5 + 4 + 2 + 32
        offset += 1 + payload[offset]                                   # session id
        offset += 2 + struct.unpack_from(">H", payload, offset)[0]      # cipher suites
        offset += 1 + payload[offset]                                   # compression methods
        end = offset + 2 + struct.unpack_from(">H", payload, offset)[0]
        offset += 2
        name, ech = None, False
        while offset + 4 <= min(end, len(payload)):
            kind, length = struct.unpack_from(">HH", payload, offset)
            offset += 4
            if kind == 0:
                name_length = struct.unpack_from(">H", payload, offset + 3)[0]
                raw = payload[offset + 5:offset + 5 + name_length]
                name = raw.decode("ascii").lower() if len(raw) == name_length else None
            elif kind == ECH_EXTENSION:
                ech = True
            offset += length
        return {"name": name, "ech": ech} if name else None
    except (IndexError, struct.error, UnicodeDecodeError):
        return None


def tls_server_name(payload: bytes) -> str | None:
    """Server name from a TLS ClientHello, if this payload starts one and the name is real (not ECH's cover)."""
    hello = client_hello(payload)
    return hello["name"] if hello and not hello["ech"] else None


class HelloAssembler:
    """Joins the first segments of a TLS connection: a modern ClientHello (Chrome with post-quantum
    key shares) is about 1,800 bytes, so its server name can be in the second TCP segment."""

    MAX_PENDING = 500
    MAX_AGE = 10.0
    MAX_SEGMENTS = 3

    def __init__(self) -> None:
        self._pending: dict[tuple, tuple[float, bytearray, int]] = {}
        self.hidden = 0                  # connections whose real name Encrypted Client Hello hid

    def feed(self, part: Segment, now: float) -> str | None:
        key = (part.src, part.sport, part.dst, part.dport)
        pending = self._pending.pop(key, None)
        if pending is None:
            if len(part.payload) < 6 or part.payload[0] != 0x16 or part.payload[5] != 0x01:
                return None
            data, count = bytearray(part.payload), 1
        else:
            if now - pending[0] > self.MAX_AGE:
                return None
            data, count = pending[1] + part.payload, pending[2] + 1
        need = 5 + int.from_bytes(data[3:5], "big")
        if len(data) >= need or count >= self.MAX_SEGMENTS:
            hello = client_hello(bytes(data[:need]))
            if hello and hello["ech"]:
                self.hidden += 1
                return None
            return hello["name"] if hello else None
        if len(self._pending) >= self.MAX_PENDING:                       # drop the oldest
            oldest = min(self._pending, key=lambda item: self._pending[item][0])
            del self._pending[oldest]
        self._pending[key] = (now, data, count)
        return None


ASSEMBLER = HelloAssembler()


def names_from_frame(frame: bytes) -> tuple[str, list[str], str] | None:
    """One call for the helper: (name, addresses, source) learned from this frame, if any."""
    part = segment(frame)
    if part is None:
        return None
    if part.sport == 53:
        message = part.payload[2:] if part.proto == 6 else part.payload
        answer = dns_answers(message)
        return (answer[0], answer[1], "packet") if answer else None
    if part.proto == 6 and part.dport == 443 and part.payload:
        import time

        name = ASSEMBLER.feed(part, time.time())
        if name:
            return name, [part.dst], "sni"
    return None
