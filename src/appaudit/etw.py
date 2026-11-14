"""Real-time Windows event tracing through ctypes, plus a recorder so captured events can be
replayed in tests without administrator rights.

Starting a session needs an elevated process. Replaying a recording does not.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import struct
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator, NamedTuple

KERNEL_NETWORK = "7dd42a49-5329-4832-8dfd-43d979153a88"
KERNEL_PROCESS = "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716"
DNS_CLIENT = "1c95126e-7eea-49a9-a3fe-a378b03ddb4d"
WEBIO = "50b3e73c-9370-461d-bb9f-26f32d68887d"
WININET = "43d1a55c-76d6-4f7e-995c-64c711e5cafe"
PKTMON = "4d4f80d9-c8bd-4d73-bb5b-19c90402c5ac"
TASK_SCHEDULER = "de7b24ea-73c8-4a09-985d-5bdadcfa9017"

ALL_KEYWORDS = 0xFFFFFFFFFFFFFFFF
_INVALID_HANDLES = (0, 0xFFFFFFFFFFFFFFFF, 0x00000000FFFFFFFF)


class Event(NamedTuple):
    provider: bytes      # 16 bytes, little-endian GUID layout
    event_id: int
    version: int
    pid: int             # process in the event header (often 4 for kernel events)
    filetime: int        # 100 ns ticks since 1601, UTC
    data: bytes


def guid_bytes(text: str) -> bytes:
    return uuid.UUID(text).bytes_le


@dataclass(frozen=True)
class Provider:
    guid: str
    keywords: int = ALL_KEYWORDS
    level: int = 4


# --- ctypes structures (sizes confirmed on x64: 120, 448) -------------------------------

class GUID(ctypes.Structure):
    _fields_ = [("Data1", ctypes.c_uint32), ("Data2", ctypes.c_uint16), ("Data3", ctypes.c_uint16),
                ("Data4", ctypes.c_ubyte * 8)]


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


def _api():
    api = ctypes.WinDLL("advapi32", use_last_error=True)
    api.StartTraceW.argtypes = [ctypes.POINTER(ctypes.c_uint64), wt.LPCWSTR, ctypes.c_void_p]
    api.StartTraceW.restype = ctypes.c_uint32
    api.ControlTraceW.argtypes = [ctypes.c_uint64, wt.LPCWSTR, ctypes.c_void_p, ctypes.c_uint32]
    api.ControlTraceW.restype = ctypes.c_uint32
    api.EnableTraceEx2.argtypes = [ctypes.c_uint64, ctypes.POINTER(GUID), ctypes.c_uint32, ctypes.c_ubyte,
                                   ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint32, ctypes.c_void_p]
    api.EnableTraceEx2.restype = ctypes.c_uint32
    api.OpenTraceW.argtypes = [ctypes.POINTER(EVENT_TRACE_LOGFILEW)]
    api.OpenTraceW.restype = ctypes.c_uint64
    api.ProcessTrace.argtypes = [ctypes.POINTER(ctypes.c_uint64), ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p]
    api.ProcessTrace.restype = ctypes.c_uint32
    api.CloseTrace.argtypes = [ctypes.c_uint64]
    api.CloseTrace.restype = ctypes.c_uint32
    return api


def _properties(name: str):
    size = ctypes.sizeof(EVENT_TRACE_PROPERTIES) + 2 * 2 * 1024
    buffer = ctypes.create_string_buffer(size)
    props = EVENT_TRACE_PROPERTIES.from_buffer(buffer)
    props.Wnode.BufferSize = size
    props.Wnode.Flags = 0x00020000        # WNODE_FLAG_TRACED_GUID
    props.Wnode.ClientContext = 1         # performance-counter timestamps, converted for us
    props.LogFileMode = 0x00000100        # EVENT_TRACE_REAL_TIME_MODE
    props.BufferSize = 256                # KB per buffer
    props.MinimumBuffers = 32
    props.MaximumBuffers = 128
    props.FlushTimer = 1
    props.LoggerNameOffset = ctypes.sizeof(EVENT_TRACE_PROPERTIES)
    return buffer, props


class TraceSession:
    """One real-time session. `on_event` is called on a worker thread for every event."""

    def __init__(self, name: str, providers: list[Provider], on_event: Callable[[Event], None]) -> None:
        self.name = name
        self.providers = list(providers)
        self.on_event = on_event
        self.errors = 0
        self.events = 0
        self._api = _api()
        self._session = ctypes.c_uint64(0)
        self._trace = ctypes.c_uint64(0)
        self._worker: threading.Thread | None = None
        self._callback = EVENT_RECORD_CALLBACK(self._dispatch)
        self._logfile = None

    def _dispatch(self, record: int) -> None:
        try:
            header = ctypes.string_at(record, 112)
            length = struct.unpack_from("<H", header, 86)[0]
            address = struct.unpack_from("<Q", header, 96)[0]
            self.events += 1
            self.on_event(Event(
                header[24:40], struct.unpack_from("<H", header, 40)[0], header[42],
                struct.unpack_from("<I", header, 12)[0], struct.unpack_from("<q", header, 16)[0],
                ctypes.string_at(address, length) if length else b""))
        except Exception:  # noqa: BLE001 - an exception must never cross into the tracing thread
            self.errors += 1

    def start(self) -> None:
        stale, _ = _properties(self.name)
        self._api.ControlTraceW(0, self.name, stale, 1)        # clear a leftover session of ours
        buffer, _ = _properties(self.name)
        status = self._api.StartTraceW(ctypes.byref(self._session), self.name, buffer)
        if status == 5:
            raise PermissionError("starting a trace session needs administrator rights")
        if status != 0:
            raise OSError(f"StartTrace failed with error {status}")
        try:
            for provider in self.providers:
                self.enable(provider)
            logfile = EVENT_TRACE_LOGFILEW()
            logfile.LoggerName = self.name
            logfile.ProcessTraceMode = 0x00000100 | 0x10000000   # real time, EVENT_RECORD callbacks
            logfile.EventRecordCallback = self._callback
            self._logfile = logfile
            self._trace = ctypes.c_uint64(self._api.OpenTraceW(ctypes.byref(logfile)))
            if self._trace.value in _INVALID_HANDLES:
                raise OSError(f"OpenTrace failed with error {ctypes.get_last_error()}")
        except Exception:
            self.stop()
            raise
        self._worker = threading.Thread(target=self._pump, name=f"etw-{self.name}", daemon=True)
        self._worker.start()

    def enable(self, provider: Provider, on: bool = True) -> int:
        guid = GUID.from_buffer_copy(guid_bytes(provider.guid))
        return self._api.EnableTraceEx2(self._session, ctypes.byref(guid), 1 if on else 0, provider.level,
                                        provider.keywords, 0, 0, None)

    def _pump(self) -> None:
        handles = (ctypes.c_uint64 * 1)(self._trace.value)
        self._api.ProcessTrace(handles, 1, None, None)

    def lost(self) -> int:
        buffer, props = _properties(self.name)
        if self._api.ControlTraceW(self._session, None, buffer, 0) != 0:
            return -1
        return props.EventsLost + props.RealTimeBuffersLost

    def alive(self) -> bool:
        return self._worker is not None and self._worker.is_alive()

    def stop(self) -> None:
        buffer, _ = _properties(self.name)
        self._api.ControlTraceW(self._session, None, buffer, 1)
        if self._worker is not None:
            self._worker.join(15)
        if self._trace.value not in _INVALID_HANDLES:
            self._api.CloseTrace(self._trace)
            self._trace = ctypes.c_uint64(0)

    def __enter__(self) -> "TraceSession":
        self.start()
        return self

    def __exit__(self, *_exc) -> None:
        self.stop()


# --- recording and replay ------------------------------------------------------------

_RECORD = struct.Struct("<16sHBIqH")
MAGIC = b"AAEV1\n"


class Recorder:
    """Append events to a file in a small binary format."""

    def __init__(self, path: Path) -> None:
        self._file = open(path, "wb")
        self._file.write(MAGIC)
        self._lock = threading.Lock()

    def write(self, event: Event) -> None:
        with self._lock:
            self._file.write(_RECORD.pack(event.provider, event.event_id, event.version, event.pid,
                                          event.filetime, len(event.data)))
            self._file.write(event.data)

    def close(self) -> None:
        with self._lock:
            self._file.close()


def replay(path: Path) -> Iterator[Event]:
    with open(path, "rb") as file:
        if file.read(len(MAGIC)) != MAGIC:
            raise ValueError(f"{path} is not an event recording")
        while True:
            head = file.read(_RECORD.size)
            if len(head) < _RECORD.size:
                return
            provider, event_id, version, pid, filetime, length = _RECORD.unpack(head)
            yield Event(provider, event_id, version, pid, filetime, file.read(length))
