"""Server names from TLS ClientHellos split over two TCP segments, and Encrypted Client Hello."""

import socket
import struct

from appaudit.capture import packets


def client_hello(name: bytes, padding: int = 0, ech: bool = False) -> bytes:
    """A ClientHello whose extensions start with `padding` bytes of padding, so the server name can
    land in a later segment, as with Chrome's large post-quantum key shares."""
    extensions = b""
    if padding:
        extensions += struct.pack(">HH", 21, padding) + b"\x00" * padding
    if ech:
        extensions += struct.pack(">HH", 0xFE0D, 4) + b"\x00" * 4
    extensions += struct.pack(">HH", 0, len(name) + 5) + struct.pack(">HBH", len(name) + 3, 0, len(name)) + name
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + struct.pack(">H", 2) + b"\x13\x01" + b"\x01\x00"
    body += struct.pack(">H", len(extensions)) + extensions
    return b"\x16\x03\x01" + struct.pack(">H", len(body) + 4) + b"\x01" + len(body).to_bytes(3, "big") + body


def tcp_frame(payload: bytes, src="10.0.0.5", dst="203.0.113.7", sport=50000, dport=443) -> bytes:
    tcp = struct.pack(">HHIIBBHHH", sport, dport, 1, 0, 5 << 4, 0x18, 65535, 0, 0) + payload
    ip = (bytes([0x45, 0]) + struct.pack(">H", 20 + len(tcp)) + b"\x00" * 5 + bytes([6]) + b"\x00\x00"
          + socket.inet_aton(src) + socket.inet_aton(dst) + tcp)
    return b"\x11" * 6 + b"\x22" * 6 + b"\x08\x00" + ip


def test_name_in_the_second_segment_is_found():
    packets.ASSEMBLER = packets.HelloAssembler()
    hello = client_hello(b"telemetry.example.com", padding=1700)
    assert packets.names_from_frame(tcp_frame(hello[:1400])) is None            # first segment: no name yet
    assert packets.names_from_frame(tcp_frame(hello[1400:])) == ("telemetry.example.com", ["203.0.113.7"], "sni")


def test_other_connections_do_not_mix():
    packets.ASSEMBLER = packets.HelloAssembler()
    first = client_hello(b"a.example.com", padding=1700)
    second = client_hello(b"b.example.com", padding=1700)
    assert packets.names_from_frame(tcp_frame(first[:1400], sport=50001)) is None
    assert packets.names_from_frame(tcp_frame(second[:1400], sport=50002)) is None
    assert packets.names_from_frame(tcp_frame(second[1400:], sport=50002))[0] == "b.example.com"
    assert packets.names_from_frame(tcp_frame(first[1400:], sport=50001))[0] == "a.example.com"


def test_encrypted_client_hello_cover_name_is_not_recorded():
    packets.ASSEMBLER = packets.HelloAssembler()
    hello = client_hello(b"cloudflare-ech.com", ech=True)
    assert packets.names_from_frame(tcp_frame(hello)) is None
    assert packets.ASSEMBLER.hidden == 1
    assert packets.client_hello(hello) == {"name": "cloudflare-ech.com", "ech": True}


def test_a_lone_continuation_segment_is_ignored():
    packets.ASSEMBLER = packets.HelloAssembler()
    assert packets.names_from_frame(tcp_frame(b"\x17\x03\x03\x00\x20" + b"\x00" * 32)) is None


def test_sampling_widens_the_filter_then_restores_dns_only(monkeypatch):
    from appaudit.helper import capture

    commands = []
    monkeypatch.setattr(capture, "_run", lambda args: commands.append(" ".join(args)) or "")
    timers = []

    class Timer:
        def __init__(self, seconds, action):
            timers.append((seconds, action))
            self.daemon = True

        def start(self):
            pass

    monkeypatch.setattr(capture.threading, "Timer", Timer)
    cap = capture.Capture.__new__(capture.Capture)
    cap.packets_on, cap.packet_note = True, "reading DNS packets"
    assert cap.sample_tls(60).startswith("sampling")
    assert any("-t TCP -p 443" in command for command in commands) and any("--pkt-size 2048" in command for command in commands)
    assert cap.sample_tls(60) == "already sampling"
    commands.clear()
    timers[0][1]()                                               # the window ends
    assert not any("443" in command for command in commands) and any("--pkt-size 512" in command for command in commands)
    assert cap.packet_note == "reading DNS packets" and not cap._sampling
