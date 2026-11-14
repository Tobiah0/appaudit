"""Decoders and aggregation, exercised with hand-built payloads (no admin, no network)."""

import socket
import struct

from appaudit import etw, livestore
from appaudit.capture import decode, packets
from appaudit.capture.aggregate import Aggregator, strip_query

FT = 134300581845538210          # 2026-08-01 11:43:04 UTC


def wide(text: str) -> bytes:
    return text.encode("utf-16-le") + b"\x00\x00"


def event(provider: str, event_id: int, data: bytes, pid: int = 4, version: int = 0) -> etw.Event:
    return etw.Event(etw.guid_bytes(provider), event_id, version, pid, FT, data)


def net4(event_id: int, pid: int, size: int, daddr: str, saddr: str, dport: int, sport: int) -> etw.Event:
    data = struct.pack("<II", pid, size) + socket.inet_aton(daddr) + socket.inet_aton(saddr)
    data += struct.pack(">HH", dport, sport) + b"\x00" * 12
    return event(etw.KERNEL_NETWORK, event_id, data)


def test_network_ipv4_and_ipv6():
    decoded = decode.network(net4(10, 6988, 31, "104.18.1.181", "10.0.0.173", 443, 60801))
    assert decoded == decode.NetEvent("send", "tcp", 6988, 31, "104.18.1.181", "10.0.0.173", 443, 60801)
    data = struct.pack("<II", 77, 1200) + socket.inet_pton(socket.AF_INET6, "2606:4700:10::6814:179a")
    data += socket.inet_pton(socket.AF_INET6, "2601:19b::1") + struct.pack(">HH", 443, 50000) + b"\x00" * 8
    decoded = decode.network(event(etw.KERNEL_NETWORK, 27, data))
    assert (decoded.kind, decoded.proto, decoded.pid, decoded.size) == ("recv", "tcp", 77, 1200)
    assert decoded.daddr == "2606:4700:10::6814:179a"


def test_live_sample_from_spike():
    # Raw payload recorded on the dev PC: TCPv4 receive, 31 bytes, port 443.
    raw = bytes.fromhex("4c1b00001f000000681201b50a0000ad01bbed810000000000000000")
    decoded = decode.network(event(etw.KERNEL_NETWORK, 11, raw))
    assert (decoded.pid, decoded.size, decoded.dport, decoded.daddr) == (0x1B4C, 31, 443, "104.18.1.181")


def test_dns_answer():
    results = "type:   5 edge.example.net;::ffff:93.184.216.34;2606:4700::1;"
    data = wide("Example.ORG") + struct.pack("<IQI", 1, 0, 0) + wide(results)
    answer = decode.dns(event(etw.DNS_CLIENT, 3008, data, pid=500))
    assert answer.pid == 500 and answer.name == "example.org"
    assert answer.addresses == ["93.184.216.34", "2606:4700::1"]
    assert answer.aliases == ["edge.example.net"]
    failed = wide("nope.example") + struct.pack("<IQI", 1, 0, 9003) + wide("")
    assert decode.dns(event(etw.DNS_CLIENT, 3008, failed)) is None


def test_process_start_v3_and_stop():
    sid = bytes([1, 1, 0, 0, 0, 0, 0, 16]) + struct.pack("<I", 0x2000)
    data = struct.pack("<IQqIQIIII", 4242, 9, FT, 1000, 8, 1, 0, 2, 0) + sid
    data += wide(r"\Device\HarddiskVolume3\Windows\System32\devicecensus.exe") + struct.pack("<II", 1, 2)
    data += wide("") + wide("")
    start = decode.process_start(event(etw.KERNEL_PROCESS, 1, data, version=3))
    assert (start.pid, start.parent) == (4242, 1000)
    assert start.image.endswith("devicecensus.exe")
    assert decode.process_stop(event(etw.KERNEL_PROCESS, 2, struct.pack("<I", 4242) + b"\x00" * 40)) == 4242


def test_http_events():
    data = b"\x00" * 32 + b"POST\x00" + wide("https://example.com/a?token=secret")
    request = decode.webio(event(etw.WEBIO, 17, data, pid=9))
    assert request == decode.HttpRequest(9, "POST", "https://example.com/a?token=secret")
    assert strip_query(request.url) == "https://example.com/a"
    url = b"https://example.com/x"
    data = b"\x00" * 16 + struct.pack("<H", len(url)) + url
    assert decode.wininet(event(etw.WININET, 102, data, pid=9)).url == "https://example.com/x"


def dns_response(name: str, address: str) -> bytes:
    question = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00"
    message = struct.pack(">HHHHHH", 7, 0x8180, 1, 1, 0, 0) + question + struct.pack(">HH", 1, 1)
    message += b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton(address)
    return message


def ipv4_udp(payload: bytes, src: str, dst: str, sport: int, dport: int) -> bytes:
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    return (bytes([0x45, 0]) + struct.pack(">H", 20 + len(udp)) + b"\x00" * 5 + bytes([17]) + b"\x00\x00"
            + socket.inet_aton(src) + socket.inet_aton(dst) + udp)


def test_dns_packet_over_ethernet_and_wifi():
    ip = ipv4_udp(dns_response("tracker.example.com", "203.0.113.9"), "75.75.75.75", "10.0.0.173", 53, 51000)
    ethernet = b"\x11" * 6 + b"\x22" * 6 + b"\x08\x00" + ip
    assert packets.names_from_frame(ethernet) == ("tracker.example.com", ["203.0.113.9"], "packet")
    wifi = b"\x08\x01\x00\x80" + b"\x11" * 18 + b"\x00\x00" + b"\xaa\xaa\x03\x00\x00\x00\x08\x00" + ip
    assert packets.names_from_frame(wifi) == ("tracker.example.com", ["203.0.113.9"], "packet")


def test_tls_server_name():
    name = b"example.com"
    extension = struct.pack(">HH", 0, len(name) + 5) + struct.pack(">HBH", len(name) + 3, 0, len(name)) + name
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + struct.pack(">H", 2) + b"\x13\x01" + b"\x01\x00"
    body += struct.pack(">H", len(extension)) + extension
    hello = b"\x16\x03\x01" + struct.pack(">H", len(body) + 4) + b"\x01" + len(body).to_bytes(3, "big") + body
    assert packets.tls_server_name(hello) == "example.com"
    assert packets.tls_server_name(b"\x17\x03\x03\x00\x10" + b"\x00" * 16) is None


def test_aggregator_writes_flows_names_and_requests(tmp_path):
    known = {900: {"name": "chatty.exe", "exe": r"C:\Apps\chatty.exe", "started": 1000.0}}
    aggregator = Aggregator(local_addresses={"10.0.0.173"}, lookup=known.get)
    aggregator.feed(net4(10, 900, 500, "203.0.113.9", "10.0.0.173", 443, 50001))
    aggregator.feed(net4(11, 900, 9000, "10.0.0.173", "203.0.113.9", 50001, 443))   # receive, addresses swapped
    aggregator.feed(net4(10, 900, 5, "127.0.0.1", "127.0.0.1", 8000, 8001))          # loopback is ignored
    results = "203.0.113.9;"
    aggregator.feed(event(etw.DNS_CLIENT, 3008, wide("tracker.example.com") + struct.pack("<IQI", 1, 0, 0)
                          + wide(results), pid=900))
    aggregator.feed(event(etw.WEBIO, 17, b"\x00" * 32 + b"GET\x00" + wide("https://tracker.example.com/p?id=1"),
                          pid=900))
    conn = livestore.connect(file=tmp_path / "live.db")
    aggregator.flush(conn)
    flow = conn.execute("SELECT * FROM flows").fetchall()
    assert len(flow) == 1 and (flow[0]["sent"], flow[0]["received"], flow[0]["remote"]) == (500, 9000, "203.0.113.9")
    assert conn.execute("SELECT name FROM names WHERE address = '203.0.113.9'").fetchone()[0] == "tracker.example.com"
    assert conn.execute("SELECT url FROM requests").fetchone()[0] == "https://tracker.example.com/p"
    assert conn.execute("SELECT exe FROM procs").fetchone()[0] == r"C:\Apps\chatty.exe"


def test_recording_round_trip(tmp_path):
    recorder = etw.Recorder(tmp_path / "events.bin")
    first = net4(10, 1, 2, "203.0.113.9", "10.0.0.1", 443, 5)
    recorder.write(first)
    recorder.close()
    assert list(etw.replay(tmp_path / "events.bin")) == [first]
