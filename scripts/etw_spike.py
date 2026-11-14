"""Elevated, read-only feasibility test for live activity capture.

Part A  Record about 30 seconds of events with the built-in `logman`, from the tracing
        providers the product would rely on, into .spike/etw/capture.etl, then decode
        it with the built-in `tracerpt`.
Part B  Start a real-time tracing session from Python (ctypes, no extra packages) and
        measure how fast Python can consume events while this process downloads a
        known amount of data.
Part C  Read-only inventory of telemetry plumbing: trace sessions, the Diagnosis folder,
        packet monitor state, firewall platform state.

Nothing on the system is changed. Both trace sessions are stopped at the end.
Run elevated:  .venv\\Scripts\\python.exe scripts\\etw_spike.py
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import json
import os
import shutil
import socket
import sqlite3
import struct
import subprocess
import threading
import time
import traceback
import urllib.request
import uuid
import winreg
from collections import Counter, defaultdict
from pathlib import Path

import psutil

OUT = Path(__file__).resolve().parents[1] / ".spike" / "etw"
OUT.mkdir(parents=True, exist_ok=True)
LOG = OUT / "spike.log"
RESULT: dict = {"started": time.strftime("%Y-%m-%d %H:%M:%S"), "pid": os.getpid()}

SESSION_A = "appaudit-spike-a"
SESSION_B = "appaudit-spike-b"
CAPTURE_SECONDS = 30
PROVIDERS_A = [
    ("Microsoft-Windows-Kernel-Network", "0xffffffffffffffff", "5"),
    ("Microsoft-Windows-Kernel-Process", "0x10", "5"),
    ("Microsoft-Windows-DNS-Client", "0xffffffffffffffff", "5"),
    ("Microsoft-Windows-WebIO", "0xffffffffffffffff", "5"),
    ("Microsoft-Windows-WinHttp", "0xffffffffffffffff", "5"),
    ("Microsoft-Windows-WinINet", "0xffffffffffffffff", "5"),
]
HKLM = winreg.HKEY_LOCAL_MACHINE


def log(message: str) -> None:
    with LOG.open("a", encoding="utf-8") as handle:
        handle.write(f"{time.strftime('%H:%M:%S')} {message}\n")


def save() -> None:
    (OUT / "result.json").write_text(json.dumps(RESULT, indent=1, default=str), encoding="utf-8")


def run(args, timeout=180) -> str:
    try:
        out = subprocess.run(args, capture_output=True, text=True, timeout=timeout, errors="replace")
        return ((out.stdout or "") + (out.stderr or "")).strip()
    except Exception as error:  # noqa: BLE001
        return f"[failed] {error}"


def ps(command: str, timeout=180) -> str:
    return run(["powershell", "-NoProfile", "-NonInteractive", "-Command", command], timeout)


def last_line(text: str) -> str:
    lines = [line for line in text.splitlines() if line.strip()]
    return lines[-1] if lines else ""


def snapshot_pids() -> dict:
    services = defaultdict(list)
    for service in psutil.win_service_iter():
        try:
            pid = service.pid()
        except Exception:  # noqa: BLE001
            continue
        if pid:
            services[pid].append(service.name())
    table = {}
    for proc in psutil.process_iter(["pid", "name", "exe"]):
        table[str(proc.info["pid"])] = {
            "name": proc.info["name"], "exe": proc.info["exe"], "services": services.get(proc.info["pid"], []),
        }
    return table


# --- recognisable test traffic through four different network stacks -----------------

def make_traffic() -> dict:
    done: dict = {}
    try:
        done["getaddrinfo"] = len(socket.getaddrinfo("example.org", 443))
    except Exception as error:  # noqa: BLE001
        done["getaddrinfo"] = repr(error)

    try:  # WinHTTP: the stack most Windows components use
        import pythoncom
        import win32com.client

        pythoncom.CoInitialize()
        request = win32com.client.Dispatch("WinHttp.WinHttpRequest.5.1")
        request.Open("POST", "https://example.com/appaudit-winhttp-marker", False)
        request.SetRequestHeader("X-AppAudit-Marker", "header-marker-1")
        request.Send("appaudit-body-marker-winhttp")
        done["winhttp_status"] = request.Status
    except Exception as error:  # noqa: BLE001
        done["winhttp_status"] = repr(error)

    try:  # WinINet: older apps and some shell components
        wininet = ctypes.WinDLL("wininet", use_last_error=True)
        wininet.InternetOpenW.restype = ctypes.c_void_p
        wininet.InternetOpenW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.LPCWSTR, wt.LPCWSTR, wt.DWORD]
        wininet.InternetOpenUrlW.restype = ctypes.c_void_p
        wininet.InternetOpenUrlW.argtypes = [ctypes.c_void_p, wt.LPCWSTR, wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p]
        wininet.InternetReadFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD)]
        wininet.InternetCloseHandle.argtypes = [ctypes.c_void_p]
        session = wininet.InternetOpenW("appaudit-spike", 0, None, None, 0)
        handle = wininet.InternetOpenUrlW(session, "https://example.com/?appaudit-wininet-marker=1", None, 0,
                                          0x80000000 | 0x04000000, None)
        read = wt.DWORD(0)
        if handle:
            buffer = ctypes.create_string_buffer(4096)
            wininet.InternetReadFile(handle, buffer, 4096, ctypes.byref(read))
            wininet.InternetCloseHandle(handle)
        if session:
            wininet.InternetCloseHandle(session)
        done["wininet_bytes"] = read.value if handle else f"open failed {ctypes.get_last_error()}"
    except Exception as error:  # noqa: BLE001
        done["wininet_bytes"] = repr(error)

    try:  # Python's bundled TLS: stands in for apps that ship their own networking code
        request = urllib.request.Request("https://example.net/?appaudit-openssl-marker=1", headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(request, timeout=15) as response:
            done["urllib_bytes"] = len(response.read())
    except Exception as error:  # noqa: BLE001
        done["urllib_bytes"] = repr(error)
    return done


# --- Part A: logman capture --------------------------------------------------------

def part_a() -> None:
    info: dict = {"providers": {}}
    RESULT["part_a"] = info
    etl = OUT / "capture.etl"
    for stale in (etl, OUT / "capture.xml"):
        if stale.exists():
            stale.unlink()
    run(["logman", "stop", SESSION_A, "-ets"])
    pids = snapshot_pids()
    started = False
    for name, keywords, level in PROVIDERS_A:
        if not started:
            out = run(["logman", "start", SESSION_A, "-p", name, keywords, level, "-o", str(etl), "-ets",
                       "-bs", "256", "-nb", "32", "128"])
            started = "successfully" in out.lower()
        else:
            out = run(["logman", "update", SESSION_A, "-p", name, keywords, level, "-ets"])
        info["providers"][name] = last_line(out)
        log(f"A provider {name}: {last_line(out)}")
    if not started:
        info["error"] = "no provider could be started"
        return
    try:
        time.sleep(1)
        info["traffic"] = make_traffic()
        log(f"A traffic: {info['traffic']}")
        time.sleep(CAPTURE_SECONDS)
        pids.update(snapshot_pids())
    finally:
        info["stop"] = last_line(run(["logman", "stop", SESSION_A, "-ets"]))
    (OUT / "pidmap.json").write_text(json.dumps(pids), encoding="utf-8")
    info["etl_bytes"] = etl.stat().st_size if etl.exists() else 0
    started_at = time.perf_counter()
    out = run(["tracerpt", str(etl), "-o", str(OUT / "capture.xml"), "-of", "XML", "-y"], timeout=900)
    info["tracerpt"] = last_line(out)
    info["tracerpt_seconds"] = round(time.perf_counter() - started_at, 1)
    xml = OUT / "capture.xml"
    info["xml_bytes"] = xml.stat().st_size if xml.exists() else 0
    log(f"A done: etl {info['etl_bytes']} bytes, xml {info['xml_bytes']} bytes")


# --- Part B: real-time session from Python via ctypes ------------------------------------

class GUID(ctypes.Structure):
    _fields_ = [("Data1", ctypes.c_uint32), ("Data2", ctypes.c_uint16), ("Data3", ctypes.c_uint16),
                ("Data4", ctypes.c_ubyte * 8)]


def make_guid(text: str) -> GUID:
    return GUID.from_buffer_copy(uuid.UUID(text).bytes_le)


class WNODE_HEADER(ctypes.Structure):
    _fields_ = [("BufferSize", ctypes.c_uint32), ("ProviderId", ctypes.c_uint32),
                ("HistoricalContext", ctypes.c_uint64), ("TimeStamp", ctypes.c_int64), ("Guid", GUID),
                ("ClientContext", ctypes.c_uint32), ("Flags", ctypes.c_uint32)]


class EVENT_TRACE_PROPERTIES(ctypes.Structure):
    _fields_ = [("Wnode", WNODE_HEADER), ("BufferSize", ctypes.c_uint32), ("MinimumBuffers", ctypes.c_uint32),
                ("MaximumBuffers", ctypes.c_uint32), ("MaximumFileSize", ctypes.c_uint32),
                ("LogFileMode", ctypes.c_uint32), ("FlushTimer", ctypes.c_uint32), ("EnableFlags", ctypes.c_uint32),
                ("AgeLimit", ctypes.c_int32), ("NumberOfBuffers", ctypes.c_uint32), ("FreeBuffers", ctypes.c_uint32),
                ("EventsLost", ctypes.c_uint32), ("BuffersWritten", ctypes.c_uint32),
                ("LogBuffersLost", ctypes.c_uint32), ("RealTimeBuffersLost", ctypes.c_uint32),
                ("LoggerThreadId", ctypes.c_void_p), ("LogFileNameOffset", ctypes.c_uint32),
                ("LoggerNameOffset", ctypes.c_uint32)]


class EVENT_TRACE_HEADER(ctypes.Structure):
    _fields_ = [("Size", ctypes.c_uint16), ("FieldTypeFlags", ctypes.c_uint16), ("Version", ctypes.c_uint32),
                ("ThreadId", ctypes.c_uint32), ("ProcessId", ctypes.c_uint32), ("TimeStamp", ctypes.c_int64),
                ("Guid", GUID), ("ProcessorTime", ctypes.c_uint64)]


class EVENT_TRACE(ctypes.Structure):
    _fields_ = [("Header", EVENT_TRACE_HEADER), ("InstanceId", ctypes.c_uint32),
                ("ParentInstanceId", ctypes.c_uint32), ("ParentGuid", GUID), ("MofData", ctypes.c_void_p),
                ("MofLength", ctypes.c_uint32), ("ClientContext", ctypes.c_uint32)]


class TRACE_LOGFILE_HEADER(ctypes.Structure):
    _fields_ = [("BufferSize", ctypes.c_uint32), ("Version", ctypes.c_uint32), ("ProviderVersion", ctypes.c_uint32),
                ("NumberOfProcessors", ctypes.c_uint32), ("EndTime", ctypes.c_int64),
                ("TimerResolution", ctypes.c_uint32), ("MaximumFileSize", ctypes.c_uint32),
                ("LogFileMode", ctypes.c_uint32), ("BuffersWritten", ctypes.c_uint32), ("LogInstanceGuid", GUID),
                ("LoggerName", ctypes.c_void_p), ("LogFileName", ctypes.c_void_p), ("TimeZone", ctypes.c_byte * 172),
                ("BootTime", ctypes.c_int64), ("PerfFreq", ctypes.c_int64), ("StartTime", ctypes.c_int64),
                ("ReservedFlags", ctypes.c_uint32), ("BuffersLost", ctypes.c_uint32)]


EVENT_RECORD_CALLBACK = ctypes.WINFUNCTYPE(None, ctypes.c_void_p)


class EVENT_TRACE_LOGFILEW(ctypes.Structure):
    _fields_ = [("LogFileName", ctypes.c_wchar_p), ("LoggerName", ctypes.c_wchar_p), ("CurrentTime", ctypes.c_int64),
                ("BuffersRead", ctypes.c_uint32), ("ProcessTraceMode", ctypes.c_uint32),
                ("CurrentEvent", EVENT_TRACE), ("LogfileHeader", TRACE_LOGFILE_HEADER),
                ("BufferCallback", ctypes.c_void_p), ("BufferSize", ctypes.c_uint32), ("Filled", ctypes.c_uint32),
                ("EventsLost", ctypes.c_uint32), ("EventRecordCallback", EVENT_RECORD_CALLBACK),
                ("IsKernelTrace", ctypes.c_uint32), ("Context", ctypes.c_void_p)]


KERNEL_NETWORK = "7dd42a49-5329-4832-8dfd-43d979153a88"
DNS_CLIENT = "1c95126e-7eea-49a9-a3fe-a378b03ddb4d"
RECEIVE_IDS = {11, 27, 43, 59}
SEND_IDS = {10, 26, 42, 58}


def make_properties(session: str):
    size = ctypes.sizeof(EVENT_TRACE_PROPERTIES) + 2 * 2 * 1024
    buffer = ctypes.create_string_buffer(size)
    props = EVENT_TRACE_PROPERTIES.from_buffer(buffer)
    props.Wnode.BufferSize = size
    props.Wnode.Flags = 0x00020000        # WNODE_FLAG_TRACED_GUID
    props.Wnode.ClientContext = 1         # timestamps from the performance counter
    props.LogFileMode = 0x00000100        # EVENT_TRACE_REAL_TIME_MODE
    props.BufferSize = 256                # KB per buffer
    props.MinimumBuffers = 32
    props.MaximumBuffers = 128
    props.FlushTimer = 1
    props.LoggerNameOffset = ctypes.sizeof(EVENT_TRACE_PROPERTIES)
    return buffer, props


def download(megabytes: int):
    url = f"https://speed.cloudflare.com/__down?bytes={megabytes * 1_000_000}"
    request = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    total = 0
    started = time.perf_counter()
    with urllib.request.urlopen(request, timeout=40) as response:
        while chunk := response.read(1 << 16):
            total += len(chunk)
    return total, time.perf_counter() - started


def part_b() -> None:
    info: dict = {"struct_sizes": {
        "EVENT_TRACE_PROPERTIES": ctypes.sizeof(EVENT_TRACE_PROPERTIES),
        "EVENT_TRACE": ctypes.sizeof(EVENT_TRACE),
        "TRACE_LOGFILE_HEADER": ctypes.sizeof(TRACE_LOGFILE_HEADER),
        "EVENT_TRACE_LOGFILEW": ctypes.sizeof(EVENT_TRACE_LOGFILEW),
    }}
    RESULT["part_b"] = info
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi32.StartTraceW.argtypes = [ctypes.POINTER(ctypes.c_uint64), wt.LPCWSTR, ctypes.c_void_p]
    advapi32.StartTraceW.restype = ctypes.c_uint32
    advapi32.ControlTraceW.argtypes = [ctypes.c_uint64, wt.LPCWSTR, ctypes.c_void_p, ctypes.c_uint32]
    advapi32.ControlTraceW.restype = ctypes.c_uint32
    advapi32.EnableTraceEx2.argtypes = [ctypes.c_uint64, ctypes.POINTER(GUID), ctypes.c_uint32, ctypes.c_ubyte,
                                        ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint32, ctypes.c_void_p]
    advapi32.EnableTraceEx2.restype = ctypes.c_uint32
    advapi32.OpenTraceW.argtypes = [ctypes.POINTER(EVENT_TRACE_LOGFILEW)]
    advapi32.OpenTraceW.restype = ctypes.c_uint64
    advapi32.ProcessTrace.argtypes = [ctypes.POINTER(ctypes.c_uint64), ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p]
    advapi32.ProcessTrace.restype = ctypes.c_uint32
    advapi32.CloseTrace.argtypes = [ctypes.c_uint64]
    advapi32.CloseTrace.restype = ctypes.c_uint32

    stale, _ = make_properties(SESSION_B)
    advapi32.ControlTraceW(0, SESSION_B, stale, 1)

    buffer, _props = make_properties(SESSION_B)
    session = ctypes.c_uint64(0)
    status = advapi32.StartTraceW(ctypes.byref(session), SESSION_B, buffer)
    info["start_trace"] = status
    log(f"B StartTrace -> {status}")
    if status != 0:
        return

    kn = uuid.UUID(KERNEL_NETWORK).bytes_le
    dns = uuid.UUID(DNS_CLIENT).bytes_le
    events_by_key: Counter = Counter()
    received: Counter = Counter()
    sent: Counter = Counter()
    samples: dict = {}
    counters = {"events": 0, "callback_ns": 0, "errors": 0}
    string_at = ctypes.string_at
    unpack_from = struct.unpack_from
    clock = time.perf_counter_ns

    def on_event(record: int) -> None:
        began = clock()
        try:
            header = string_at(record, 112)
            provider = header[24:40]
            event_id = unpack_from("<H", header, 40)[0]
            length = unpack_from("<H", header, 86)[0]
            data = unpack_from("<Q", header, 96)[0]
            counters["events"] += 1
            source = "net" if provider == kn else "dns" if provider == dns else "other"
            key = f"{source}:{event_id}"
            events_by_key[key] += 1
            if source == "net" and length >= 8 and (event_id in RECEIVE_IDS or event_id in SEND_IDS):
                pid, size = struct.unpack("<II", string_at(data, 8))
                if event_id in RECEIVE_IDS:
                    received[pid] += size
                else:
                    sent[pid] += size
            if key not in samples and length:
                samples[key] = {"header_pid": unpack_from("<I", header, 12)[0], "version": header[42],
                                "length": length, "data_hex": string_at(data, min(length, 300)).hex()}
        except Exception:  # noqa: BLE001
            counters["errors"] += 1
        counters["callback_ns"] += clock() - began

    callback = EVENT_RECORD_CALLBACK(on_event)
    consumer_status: dict = {}
    trace = ctypes.c_uint64(0)
    worker = None
    try:
        for label, guid_text in (("kernel_network", KERNEL_NETWORK), ("dns_client", DNS_CLIENT)):
            guid = make_guid(guid_text)
            info[f"enable_{label}"] = advapi32.EnableTraceEx2(session, ctypes.byref(guid), 1, 5,
                                                              0xFFFFFFFFFFFFFFFF, 0, 0, None)
        log(f"B enable -> {info.get('enable_kernel_network')}, {info.get('enable_dns_client')}")

        logfile = EVENT_TRACE_LOGFILEW()
        logfile.LoggerName = SESSION_B
        logfile.ProcessTraceMode = 0x00000100 | 0x10000000   # real time | EVENT_RECORD callbacks
        logfile.EventRecordCallback = callback
        trace = ctypes.c_uint64(advapi32.OpenTraceW(ctypes.byref(logfile)))
        info["open_trace_ok"] = trace.value not in (0xFFFFFFFFFFFFFFFF, 0x00000000FFFFFFFF)
        if not info["open_trace_ok"]:
            info["open_trace_error"] = ctypes.get_last_error()
            return

        def pump() -> None:
            handles = (ctypes.c_uint64 * 1)(trace.value)
            consumer_status["process_trace"] = advapi32.ProcessTrace(handles, 1, None, None)

        worker = threading.Thread(target=pump, daemon=True)
        cpu_before = time.process_time()
        wall_before = time.perf_counter()
        worker.start()
        time.sleep(2)
        try:
            socket.getaddrinfo("example.org", 443)
            info["download_bytes"], info["download_seconds"] = download(20)
        except Exception as error:  # noqa: BLE001
            info["download_error"] = repr(error)
        time.sleep(3)
        info["wall_seconds"] = round(time.perf_counter() - wall_before, 2)
        info["cpu_seconds_whole_process"] = round(time.process_time() - cpu_before, 2)

        query, query_props = make_properties(SESSION_B)
        info["query_status"] = advapi32.ControlTraceW(session, None, query, 0)
        info["events_lost"] = query_props.EventsLost
        info["realtime_buffers_lost"] = query_props.RealTimeBuffersLost
        info["buffers_written"] = query_props.BuffersWritten
    finally:
        stop, _ = make_properties(SESSION_B)
        info["stop_status"] = advapi32.ControlTraceW(session, None, stop, 1)
        if worker is not None:
            worker.join(15)
            info["consumer_thread_ended"] = not worker.is_alive()
        if trace.value not in (0, 0xFFFFFFFFFFFFFFFF, 0x00000000FFFFFFFF):
            advapi32.CloseTrace(trace)
        info["process_trace_status"] = consumer_status.get("process_trace")

    events = counters["events"]
    info["events"] = events
    info["callback_errors"] = counters["errors"]
    info["callback_seconds"] = round(counters["callback_ns"] / 1e9, 3)
    info["microseconds_per_event"] = round(counters["callback_ns"] / 1e3 / events, 2) if events else None
    info["events_by_key"] = dict(events_by_key.most_common())
    info["own_pid_received_bytes"] = received.get(os.getpid(), 0)
    info["own_pid_sent_bytes"] = sent.get(os.getpid(), 0)
    info["pids_with_traffic"] = len(set(received) | set(sent))
    info["samples"] = samples
    log(f"B done: {events} events, {info['microseconds_per_event']} us/event, lost {info.get('events_lost')}")


# --- Part C: read-only inventory ------------------------------------------------------

def registry_tree(key_path: str, depth: int, lines: list, indent: int = 0) -> None:
    try:
        with winreg.OpenKey(HKLM, key_path) as handle:
            subkeys, values, _ = winreg.QueryInfoKey(handle)
            for index in range(values):
                name, value, kind = winreg.EnumValue(handle, index)
                shown = value if kind in (winreg.REG_DWORD, winreg.REG_QWORD) else (
                    value[:120] if isinstance(value, str) else f"<{kind}, {len(value) if value else 0} bytes>")
                lines.append(f"{' ' * indent}{name} = {shown}")
            names = [winreg.EnumKey(handle, index) for index in range(subkeys)]
    except OSError as error:
        lines.append(f"{' ' * indent}<{key_path.rsplit(chr(92), 1)[-1]}: error {error.winerror}>")
        return
    for name in names:
        lines.append(f"{' ' * indent}[{name}]")
        if depth > 0:
            registry_tree(key_path + "\\" + name, depth - 1, lines, indent + 2)


def part_c() -> None:
    info: dict = {}
    RESULT["part_c"] = info

    sessions = run(["logman", "query", "-ets"])
    (OUT / "sessions.txt").write_text(sessions, encoding="utf-8")
    info["trace_sessions_running"] = max(len([line for line in sessions.splitlines() if "Running" in line]), 0)
    listener = run(["logman", "query", "Diagtrack-Listener", "-ets"])
    (OUT / "diagtrack_listener.txt").write_text(listener, encoding="utf-8")
    info["diagtrack_listener_lines"] = len(listener.splitlines())
    info["diagtrack_listener_head"] = listener[:300]

    loggers = {}
    try:
        with winreg.OpenKey(HKLM, r"SYSTEM\CurrentControlSet\Control\WMI\Autologger") as root:
            for index in range(winreg.QueryInfoKey(root)[0]):
                name = winreg.EnumKey(root, index)
                try:
                    with winreg.OpenKey(root, name) as sub:
                        try:
                            start = winreg.QueryValueEx(sub, "Start")[0]
                        except OSError:
                            start = None
                        loggers[name] = {"start": start, "providers": winreg.QueryInfoKey(sub)[0]}
                except OSError as error:
                    loggers[name] = {"error": error.winerror}
    except OSError as error:
        loggers = {"error": error.winerror}
    info["autologgers"] = loggers

    lines: list = []
    registry_tree(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack", 2, lines)
    (OUT / "diagtrack_registry.txt").write_text("\n".join(lines), encoding="utf-8")
    info["diagtrack_registry_lines"] = len(lines)

    root = Path(r"C:\ProgramData\Microsoft\Diagnosis")
    listing = []
    total_bytes = 0
    try:
        for path in sorted(root.rglob("*")):
            relative = path.relative_to(root)
            try:
                stat = path.stat()
            except OSError as error:
                listing.append(f"? {relative} error {error.winerror}")
                continue
            if path.is_file():
                total_bytes += stat.st_size
            if len(relative.parts) <= 3:
                listing.append(f"{'d' if path.is_dir() else 'f'} {stat.st_size:>12} "
                               f"{time.strftime('%Y-%m-%d', time.localtime(stat.st_mtime))} {relative}")
    except OSError as error:
        listing.append(f"walk failed {error}")
    (OUT / "diagnosis_listing.txt").write_text("\n".join(listing), encoding="utf-8")
    info["diagnosis_entries"] = len(listing)
    info["diagnosis_total_mb"] = round(total_bytes / 2**20, 1)

    database = root / "EventTranscript" / "EventTranscript.db"
    if database.exists():
        transcript = {"bytes": database.stat().st_size,
                      "modified": time.strftime("%Y-%m-%d", time.localtime(database.stat().st_mtime))}
        try:
            copy = OUT / "EventTranscript_copy.db"
            shutil.copy2(database, copy)
            connection = sqlite3.connect(copy)
            tables = [row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")]
            transcript["tables"] = {table: connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
                                    for table in tables}
            connection.close()
            copy.unlink()
        except Exception as error:  # noqa: BLE001
            transcript["read_error"] = repr(error)
        info["event_transcript"] = transcript
    else:
        info["event_transcript"] = "database file not present"

    info["pktmon_status"] = run(["pktmon", "status"])[:600]
    info["pktmon_filters"] = run(["pktmon", "filter", "list"])[:300]
    info["audit_wfp_connection"] = last_line(run(["auditpol", "/get", "/subcategory:Filtering Platform Connection"]))
    wfp_file = OUT / "wfpstate.xml"
    info["wfp_dump"] = last_line(run(["netsh", "wfp", "show", "state", f"file={wfp_file}"]))
    info["wfp_dump_bytes"] = wfp_file.stat().st_size if wfp_file.exists() else 0
    info["defender_status"] = ps("Get-MpComputerStatus | Select-Object AMRunningMode, AntivirusEnabled, "
                                 "RealTimeProtectionEnabled, IsTamperProtected, AMProductVersion | ConvertTo-Json -Compress")
    info["defender_prefs"] = ps("Get-MpPreference | Select-Object EnableNetworkProtection, PUAProtection, "
                                "DisableRealtimeMonitoring | ConvertTo-Json -Compress")
    cache = ps("Get-DnsClientCache | Select-Object Entry, Data | ConvertTo-Json -Compress")
    (OUT / "dnscache.json").write_text(cache, encoding="utf-8")
    try:
        parsed = json.loads(cache)
        info["dns_cache_entries"] = len(parsed) if isinstance(parsed, list) else 1
    except Exception:  # noqa: BLE001
        info["dns_cache_entries"] = f"unparsed: {cache[:120]}"
    info["dns_operational_log"] = [line.strip() for line in
                                   run(["wevtutil", "gl", "Microsoft-Windows-DNS-Client/Operational"]).splitlines()
                                   if line.strip().startswith("enabled")]

    groups = run(["whoami", "/groups", "/fo", "csv"])
    info["integrity_high"] = "High Mandatory Level" in groups
    info["integrity_system"] = "System Mandatory Level" in groups
    info["user_rid"] = run(["whoami", "/user", "/fo", "csv", "/nh"]).strip().strip('"').rsplit("-", 1)[-1]

    bam = {}
    try:
        with winreg.OpenKey(HKLM, r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings") as root_key:
            for index in range(winreg.QueryInfoKey(root_key)[0]):
                sid = winreg.EnumKey(root_key, index)
                with winreg.OpenKey(root_key, sid) as sub:
                    bam[sid.rsplit("-", 1)[-1]] = winreg.QueryInfoKey(sub)[1]
    except OSError as error:
        bam = {"error": error.winerror}
    info["bam_entries_by_rid"] = bam

    total = with_exe = with_cmdline = 0
    hidden = []
    for proc in psutil.process_iter(["name", "exe", "cmdline"]):
        total += 1
        with_exe += bool(proc.info["exe"])
        with_cmdline += bool(proc.info["cmdline"])
        if not proc.info["cmdline"]:
            hidden.append(proc.info["name"])
    info["processes"] = {"total": total, "exe_readable": with_exe, "cmdline_readable": with_cmdline,
                         "cmdline_hidden": sorted(set(hidden))[:40]}


def main() -> None:
    LOG.write_text("", encoding="utf-8")
    RESULT["elevated"] = bool(ctypes.windll.shell32.IsUserAnAdmin())
    log(f"start, elevated={RESULT['elevated']}")
    for name, part in (("part_a", part_a), ("part_b", part_b), ("part_c", part_c)):
        try:
            part()
        except Exception:  # noqa: BLE001
            RESULT.setdefault(name, {})["exception"] = traceback.format_exc()
            log(f"{name} failed: {traceback.format_exc()}")
        save()
    RESULT["finished"] = time.strftime("%Y-%m-%d %H:%M:%S")
    save()
    log("finished")


if __name__ == "__main__":
    main()
