"""Elevated feasibility test 2: can packet contents (DNS questions, TLS server names) be read
through the built-in Packet Monitor, without installing any driver?

It also lists who owns a few of the trace sessions already running on this PC.

What it does, all transient:
  - adds Packet Monitor filters for DNS (port 53) and for example.com's addresses on port 443,
    starts a capture limited to network adapters, then stops it and removes the filters;
  - sends three recognisable test requests (a normal lookup, a hand-made DNS packet like the ones
    browsers send, and one TLS connection);
  - checks whether this process can read the captured packets live from its own trace session.
It aborts the packet part if Packet Monitor is already running or already has filters.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import json
import random
import socket
import ssl
import struct
import sys
import threading
import time
import traceback
import uuid
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import etw_spike as base  # noqa: E402  (shared ctypes structures and helpers)

OUT = base.OUT
RESULT: dict = {"started": time.strftime("%Y-%m-%d %H:%M:%S")}
SESSION = "appaudit-spike-c"
PKTMON = "4d4f80d9-c8bd-4d73-bb5b-19c90402c5ac"
DNS_CLIENT = base.DNS_CLIENT
TAG = f"{random.randrange(16**6):06x}"
NAME_API = f"appaudit-api-{TAG}.example.org"        # looked up through Windows' own resolver
NAME_DIRECT = f"appaudit-direct-{TAG}.example.org"  # hand-made DNS packet, bypasses Windows' resolver
SNI_HOST = "example.com"


def save() -> None:
    (OUT / "result_pktmon.json").write_text(json.dumps(RESULT, indent=1, default=str), encoding="utf-8")


def session_owners() -> None:
    info = {}
    for name in ["1DSListener", "UQI_local_trace", "WINNETESP", "WinDiag-Realtime-Session", "Steam Event Tracing",
                 "DiagLog", "MoUxCoreWorker", "NVIDIA-NVTOPPS-NOCAT", "SleepStudyTraceSession",
                 "UpdateSessionOrchestration", "GamingServices", "ScreenOnPowerStudyTraceSession"]:
        text = base.run(["logman", "query", name, "-ets"])
        (OUT / f"session_{name.replace(' ', '_')}.txt").write_text(text, encoding="utf-8")
        lines = text.splitlines()
        providers = [line.split(":", 1)[1].strip() for line in lines if line.strip().startswith("Name:")][1:]
        guids = [line.split(":", 1)[1].strip() for line in lines if line.strip().startswith("Provider Guid:")]
        mode = next((line.split(":", 1)[1].strip() for line in lines if line.strip().startswith("File Mode")), "")
        output = next((line.split(":", 1)[1].strip() for line in lines if line.strip().startswith("Output Location")), "")
        info[name] = {"providers": len(guids), "first_names": providers[:8], "file_mode": mode, "output": output[-90:]}
    RESULT["sessions"] = info


class LiveSession:
    """A real-time trace session consumed in this process."""

    def __init__(self, name: str, providers: list[str], on_event) -> None:
        self.name, self.providers, self.on_event = name, providers, on_event
        self.api = ctypes.WinDLL("advapi32", use_last_error=True)
        api = self.api
        api.StartTraceW.argtypes = [ctypes.POINTER(ctypes.c_uint64), wt.LPCWSTR, ctypes.c_void_p]
        api.StartTraceW.restype = ctypes.c_uint32
        api.ControlTraceW.argtypes = [ctypes.c_uint64, wt.LPCWSTR, ctypes.c_void_p, ctypes.c_uint32]
        api.ControlTraceW.restype = ctypes.c_uint32
        api.EnableTraceEx2.argtypes = [ctypes.c_uint64, ctypes.POINTER(base.GUID), ctypes.c_uint32, ctypes.c_ubyte,
                                       ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint32, ctypes.c_void_p]
        api.EnableTraceEx2.restype = ctypes.c_uint32
        api.OpenTraceW.argtypes = [ctypes.POINTER(base.EVENT_TRACE_LOGFILEW)]
        api.OpenTraceW.restype = ctypes.c_uint64
        api.ProcessTrace.argtypes = [ctypes.POINTER(ctypes.c_uint64), ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p]
        api.ProcessTrace.restype = ctypes.c_uint32
        api.CloseTrace.argtypes = [ctypes.c_uint64]
        api.CloseTrace.restype = ctypes.c_uint32
        self.session = ctypes.c_uint64(0)
        self.trace = ctypes.c_uint64(0)
        self.worker = None
        self.status: dict = {}
        self._callback = base.EVENT_RECORD_CALLBACK(self._dispatch)

    def _dispatch(self, record: int) -> None:
        try:
            header = ctypes.string_at(record, 112)
            length = struct.unpack_from("<H", header, 86)[0]
            address = struct.unpack_from("<Q", header, 96)[0]
            self.on_event(header[24:40], struct.unpack_from("<H", header, 40)[0],
                          struct.unpack_from("<I", header, 12)[0], ctypes.string_at(address, length) if length else b"")
        except Exception:  # noqa: BLE001
            self.status["callback_errors"] = self.status.get("callback_errors", 0) + 1

    def __enter__(self):
        stale, _ = base.make_properties(self.name)
        self.api.ControlTraceW(0, self.name, stale, 1)
        buffer, _ = base.make_properties(self.name)
        self.status["start"] = self.api.StartTraceW(ctypes.byref(self.session), self.name, buffer)
        if self.status["start"] != 0:
            raise OSError(f"StartTrace failed with {self.status['start']}")
        for guid_text in self.providers:
            guid = base.make_guid(guid_text)
            self.status[f"enable_{guid_text[:8]}"] = self.api.EnableTraceEx2(
                self.session, ctypes.byref(guid), 1, 5, 0xFFFFFFFFFFFFFFFF, 0, 0, None)
        logfile = base.EVENT_TRACE_LOGFILEW()
        logfile.LoggerName = self.name
        logfile.ProcessTraceMode = 0x00000100 | 0x10000000
        logfile.EventRecordCallback = self._callback
        self._logfile = logfile
        self.trace = ctypes.c_uint64(self.api.OpenTraceW(ctypes.byref(logfile)))
        if self.trace.value in (0xFFFFFFFFFFFFFFFF, 0x00000000FFFFFFFF):
            raise OSError(f"OpenTrace failed with {ctypes.get_last_error()}")

        def pump() -> None:
            handles = (ctypes.c_uint64 * 1)(self.trace.value)
            self.status["process_trace"] = self.api.ProcessTrace(handles, 1, None, None)

        self.worker = threading.Thread(target=pump, daemon=True)
        self.worker.start()
        return self

    def __exit__(self, *_exc) -> None:
        stop, props = base.make_properties(self.name)
        self.status["stop"] = self.api.ControlTraceW(self.session, None, stop, 1)
        self.status["events_lost"] = props.EventsLost
        if self.worker is not None:
            self.worker.join(15)
        if self.trace.value not in (0, 0xFFFFFFFFFFFFFFFF, 0x00000000FFFFFFFF):
            self.api.CloseTrace(self.trace)


def direct_dns_query(name: str, server: str):
    """Send a DNS question straight to the resolver, the way browsers with their own DNS code do."""
    header = struct.pack(">HHHHHH", random.randrange(65536), 0x0100, 1, 0, 0, 0)
    question = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".")) + b"\x00"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    try:
        sock.sendto(header + question + struct.pack(">HH", 1, 1), (server, 53))
        return len(sock.recvfrom(2048)[0])
    except OSError as error:
        return repr(error)
    finally:
        sock.close()


def make_traffic(dns_server: str) -> dict:
    done: dict = {}
    try:
        socket.getaddrinfo(NAME_API, 443)
        done["api_lookup"] = "resolved"
    except OSError as error:
        done["api_lookup"] = f"answered ({error.errno})"
    done["direct_lookup_bytes"] = direct_dns_query(NAME_DIRECT, dns_server)
    try:
        context = ssl.create_default_context()
        with socket.create_connection((SNI_HOST, 443), timeout=10) as raw:
            done["tls_peer"] = raw.getpeername()[0]
            with context.wrap_socket(raw, server_hostname=SNI_HOST) as tls:
                tls.sendall(b"HEAD / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
                done["tls_reply_bytes"] = len(tls.recv(300))
                done["tls_version"] = tls.version()
    except OSError as error:
        done["tls"] = repr(error)
    return done


def packet_test() -> None:
    info: dict = {"names": {"api": NAME_API, "direct": NAME_DIRECT, "sni": SNI_HOST}}
    RESULT["packets"] = info
    status = base.run(["pktmon", "status"])
    filters = base.run(["pktmon", "filter", "list"])
    info["before"] = {"status": base.last_line(status), "filters": base.last_line(filters)}
    if "not running" not in status.lower() or "none" not in filters.lower():
        info["aborted"] = "Packet Monitor is already in use; left untouched"
        return

    dns_server = base.ps("(Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses } | "
                         "Select-Object -First 1).ServerAddresses[0]").strip() or "1.1.1.1"
    addresses = sorted({item[4][0] for item in socket.getaddrinfo(SNI_HOST, 443)})
    info["dns_server"] = dns_server
    info["sni_addresses"] = len(addresses)

    pktmon_guid = uuid.UUID(PKTMON).bytes_le
    dns_guid = uuid.UUID(DNS_CLIENT).bytes_le
    marks = {"api": NAME_API.split(".")[0].encode("ascii"), "direct": NAME_DIRECT.split(".")[0].encode("ascii"),
             "sni": SNI_HOST.encode("ascii")}
    wide = {key: value.decode("ascii").encode("utf-16-le") for key, value in marks.items()}
    phase = {"name": "before capture"}
    counts: dict = {"before capture": Counter(), "during capture": Counter()}
    seen_in_packets: Counter = Counter()
    seen_in_dns_events: Counter = Counter()
    samples: dict = {}

    def on_event(provider: bytes, event_id: int, _pid: int, data: bytes) -> None:
        if provider == pktmon_guid:
            counts[phase["name"]][f"pktmon:{event_id}"] += 1
            if event_id == 160 and len(data) > 34:
                payload = data[34:]
                for key, mark in marks.items():
                    if mark in payload:
                        seen_in_packets[key] += 1
                        samples.setdefault(key, {"logged_bytes": len(payload), "head_hex": payload[:64].hex()})
        elif provider == dns_guid:
            counts[phase["name"]][f"dns:{event_id}"] += 1
            for key, mark in wide.items():
                if mark in data:
                    seen_in_dns_events[key] += 1

    etl = OUT / "pktmon.etl"
    text_file = OUT / "pktmon.txt"
    for stale in (etl, text_file):
        if stale.exists():
            stale.unlink()
    started = False
    try:
        with LiveSession(SESSION, [PKTMON, DNS_CLIENT], on_event) as live:
            time.sleep(1)
            info["traffic_before"] = make_traffic(dns_server)
            time.sleep(2)
            phase["name"] = "during capture"
            info["filter_dns"] = base.last_line(base.run(["pktmon", "filter", "add", "AppAuditDns", "-p", "53"]))
            for index, address in enumerate(addresses[:6]):
                base.run(["pktmon", "filter", "add", f"AppAuditTls{index}", "-i", address, "-p", "443"])
            out = base.run(["pktmon", "start", "--capture", "--comp", "nics", "--pkt-size", "512",
                            "--file-name", str(etl), "--file-size", "16", "--log-mode", "circular"])
            info["pktmon_start"] = out[:300]
            started = True
            time.sleep(1)
            info["traffic_during"] = make_traffic(dns_server)
            time.sleep(3)
            info["live_session"] = live.status
    finally:
        if started:
            info["pktmon_stop"] = base.last_line(base.run(["pktmon", "stop"]))
        info["filter_remove"] = base.last_line(base.run(["pktmon", "filter", "remove"]))
        info["after"] = {"status": base.last_line(base.run(["pktmon", "status"])),
                         "filters": base.last_line(base.run(["pktmon", "filter", "list"]))}

    info["live_event_counts"] = {key: dict(value) for key, value in counts.items()}
    info["live_packets_containing"] = dict(seen_in_packets)
    info["dns_client_events_containing"] = dict(seen_in_dns_events)
    info["live_samples"] = samples

    if etl.exists():
        info["etl_bytes"] = etl.stat().st_size
        info["etl2txt"] = base.last_line(base.run(["pktmon", "etl2txt", str(etl), "--out", str(text_file)]))
        if text_file.exists():
            text = text_file.read_text(encoding="utf-8", errors="replace")
            lines = text.splitlines()
            info["text_lines"] = len(lines)
            found = {}
            for key, mark in marks.items():
                needle = mark.decode("ascii")
                hits = [line.strip()[:260] for line in lines if needle in line]
                found[key] = {"lines": len(hits), "example": hits[0] if hits else None}
            info["text_file_contains"] = found
            text_file.unlink()
        etl.unlink()


def main() -> None:
    RESULT["elevated"] = bool(ctypes.windll.shell32.IsUserAnAdmin())
    for name, part in (("sessions", session_owners), ("packets", packet_test)):
        try:
            part()
        except Exception:  # noqa: BLE001
            RESULT.setdefault(name + "_error", traceback.format_exc())
        save()
    RESULT["finished"] = time.strftime("%Y-%m-%d %H:%M:%S")
    save()


if __name__ == "__main__":
    main()
