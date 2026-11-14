"""Fold the event stream into rows for the live database.

`Aggregator.feed()` runs on the tracing thread and only touches in-memory dictionaries.
`Aggregator.flush()` runs on a timer and writes one transaction.
"""

from __future__ import annotations

import ipaddress
import threading
import time
from urllib.parse import urlsplit

from .. import livestore
from ..etw import Event
from . import decode, packets


def is_local_only(address: str) -> bool:
    """Loopback, link-local and multicast traffic never leaves the PC or the local segment."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return True
    return ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified


def strip_query(url: str) -> str:
    """Keep scheme, host and path. Query strings often carry tokens and identifiers."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return url.split("?", 1)[0]
    if not parts.scheme or not parts.netloc:
        return url.split("?", 1)[0]
    return f"{parts.scheme}://{parts.netloc}{parts.path}"


class ProcessTable:
    """Maps a process id to a row in `procs`, creating rows for processes first seen mid-life."""

    def __init__(self, lookup=None) -> None:
        self._lookup = lookup or _psutil_lookup
        self.by_pid: dict[int, dict] = {}
        self.dirty: list[dict] = []
        self.ended: list[tuple[int, float]] = []

    def started(self, start: decode.ProcessStart, when: float) -> dict:
        parent = self.by_pid.get(start.parent) or (self.get(start.parent, when) if start.parent > 4 else None)
        image = _device_path_to_dos(start.image)
        row = {"pid": start.pid, "started": when, "exe": image, "name": image.rsplit("\\", 1)[-1],
               "parent_pid": start.parent, "parent_exe": parent["exe"] if parent else None,
               "package": start.package or None, "services": None, "task": None, "cmdline": None,
               "seen_start": 1, "id": None, "needs_detail": True}
        self.by_pid[start.pid] = row
        self.dirty.append(row)
        return row

    def stopped(self, pid: int, when: float) -> None:
        row = self.by_pid.pop(pid, None)
        if row is not None:
            row["ended"] = when
            self.ended.append((row, when))

    def get(self, pid: int, when: float) -> dict:
        row = self.by_pid.get(pid)
        if row is None:
            info = self._lookup(pid) or {}
            row = {"pid": pid, "started": info.get("started") or when, "exe": info.get("exe"),
                   "name": info.get("name") or ("System" if pid == 4 else f"pid {pid}"),
                   "parent_pid": info.get("parent_pid"), "parent_exe": info.get("parent_exe"), "package": None,
                   "services": None, "task": None, "cmdline": info.get("cmdline"), "seen_start": 0, "id": None,
                   "needs_detail": False}
            self.by_pid[pid] = row
            self.dirty.append(row)
        return row


_DEVICE_MAP: dict[str, str] = {}


def _device_path_to_dos(image: str) -> str:
    r"""\Device\HarddiskVolume3\Windows\x.exe -> C:\Windows\x.exe."""
    if not image.lower().startswith("\\device\\"):
        return image
    if not _DEVICE_MAP:
        try:
            import win32api
            import win32file

            for drive in win32api.GetLogicalDriveStrings().split("\x00"):
                if drive:
                    _DEVICE_MAP[win32file.QueryDosDevice(drive[:2]).split("\x00")[0].lower()] = drive[:2]
        except Exception:  # noqa: BLE001
            _DEVICE_MAP["\\device\\none"] = ""
    lowered = image.lower()
    for device, drive in _DEVICE_MAP.items():
        if lowered.startswith(device + "\\"):
            return drive + image[len(device):]
    return image


def _psutil_lookup(pid: int) -> dict | None:
    try:
        import psutil

        proc = psutil.Process(pid)
        with proc.oneshot():
            info = {"name": proc.name(), "started": proc.create_time(), "parent_pid": proc.ppid()}
            try:
                info["exe"] = proc.exe() or None
            except (psutil.Error, OSError):
                info["exe"] = None
            try:
                info["cmdline"] = " ".join(proc.cmdline())[:600] or None
            except (psutil.Error, OSError):
                info["cmdline"] = None
            try:
                info["parent_exe"] = proc.parent().exe() if proc.parent() else None
            except (psutil.Error, OSError, AttributeError):
                info["parent_exe"] = None
        return info
    except Exception:  # noqa: BLE001 - the process may already be gone
        return None


class Aggregator:
    def __init__(self, local_addresses=None, lookup=None) -> None:
        self.procs = ProcessTable(lookup)
        self.local = set(local_addresses or ())
        self._lock = threading.Lock()
        self._flows: dict[tuple, list] = {}
        self._names: dict[tuple, list] = {}
        self._lookups: dict[tuple, list] = {}
        self._requests: dict[tuple, list] = {}
        self._tasks: dict[int, str] = {}
        self.counts = {"events": 0, "net": 0, "dns": 0, "http": 0, "proc": 0, "packets": 0, "names_from_packets": 0}

    # -- tracing thread ---------------------------------------------------------------

    def feed(self, event: Event) -> None:
        provider = event.provider
        when = livestore.filetime_to_unix(event.filetime) if event.filetime > 0 else time.time()
        self.counts["events"] += 1
        with self._lock:
            if provider == decode.P_NETWORK:
                self._network(event, when)
            elif provider == decode.P_DNS:
                self._dns(event, when)
            elif provider == decode.P_PROCESS:
                self._process(event, when)
            elif provider == decode.P_WEBIO:
                self._http(decode.webio(event), when)
            elif provider == decode.P_WININET:
                self._http(decode.wininet(event), when)
            elif provider == decode.P_PKTMON:
                self._packet(event, when)
            elif provider == decode.P_TASKS:
                launch = decode.task_launch(event)
                if launch and launch.pid:
                    self._tasks[launch.pid] = launch.task
                    row = self.procs.by_pid.get(launch.pid)
                    if row is not None:
                        row["task"] = launch.task
                        self.procs.dirty.append(row)

    def _network(self, event: Event, when: float) -> None:
        net = decode.network(event)
        if net is None or net.kind in ("close",):
            return
        if net.daddr in self.local and net.saddr not in self.local:
            remote, port = net.saddr, net.sport
        elif net.saddr in self.local or net.daddr not in self.local:
            remote, port = net.daddr, net.dport
        else:
            return                                   # both ends are this PC
        if is_local_only(remote):
            return
        self.counts["net"] += 1
        row = self.procs.get(net.pid, when)
        key = (id(row), remote, port, net.proto, int(when // 3600) * 3600)
        flow = self._flows.get(key)
        if flow is None:
            flow = self._flows[key] = [row, 0, 0, 0, when, when]
        if net.kind == "send":
            flow[1] += net.size
        elif net.kind == "recv":
            flow[2] += net.size
        flow[3] += 1
        flow[5] = when

    def _dns(self, event: Event, when: float) -> None:
        answer = decode.dns(event)
        if answer is None:
            return
        self.counts["dns"] += 1
        for address in answer.addresses:
            self._name(address, answer.name, "dns", when)
        row = self.procs.get(answer.pid, when)
        key = (id(row), answer.name)
        item = self._lookups.get(key)
        if item is None:
            self._lookups[key] = [row, when, when, 1]
        else:
            item[2] = when
            item[3] += 1

    def _name(self, address: str, name: str, source: str, when: float) -> None:
        key = (address, name)
        item = self._names.get(key)
        if item is None:
            self._names[key] = [source, when, when]
        else:
            item[2] = when

    def _process(self, event: Event, when: float) -> None:
        start = decode.process_start(event)
        if start is not None:
            self.counts["proc"] += 1
            row = self.procs.started(start, when)
            task = self._tasks.pop(start.pid, None)
            if task:
                row["task"] = task
            return
        pid = decode.process_stop(event)
        if pid is not None:
            self.procs.stopped(pid, when)

    def _http(self, request: decode.HttpRequest | None, when: float) -> None:
        if request is None:
            return
        self.counts["http"] += 1
        row = self.procs.get(request.pid, when)
        key = (id(row), request.method, strip_query(request.url))
        item = self._requests.get(key)
        if item is None:
            self._requests[key] = [row, when, when, 1]
        else:
            item[2] = when
            item[3] += 1

    def _packet(self, event: Event, when: float) -> None:
        frame = decode.packet(event)
        if frame is None:
            return
        self.counts["packets"] += 1
        learned = packets.names_from_frame(frame)
        if learned:
            name, addresses, source = learned
            for address in addresses:
                if not is_local_only(address):
                    self.counts["names_from_packets"] += 1
                    self._name(address, name, source, when)

    # -- flush thread -----------------------------------------------------------------

    def flush(self, conn, detail=None) -> dict:
        """Write everything gathered since the last flush. `detail(row)` may fill in services."""
        with self._lock:
            flows, self._flows = self._flows, {}
            names, self._names = self._names, {}
            lookups, self._lookups = self._lookups, {}
            requests, self._requests = self._requests, {}
            dirty, self.procs.dirty = self.procs.dirty, []
            ended, self.procs.ended = self.procs.ended, []
        for row in dirty:
            if detail is not None:
                detail(row)
            if row["id"] is None:
                cursor = conn.execute(
                    "INSERT INTO procs (pid, started, exe, name, parent_pid, parent_exe, package, services, task, "
                    "cmdline, seen_start) VALUES (?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(pid, started) DO UPDATE SET "
                    "exe = COALESCE(excluded.exe, exe), services = COALESCE(excluded.services, services), "
                    "task = COALESCE(excluded.task, task) RETURNING id",
                    (row["pid"], row["started"], row["exe"], row["name"], row["parent_pid"], row["parent_exe"],
                     row["package"], row["services"], row["task"], row["cmdline"], row["seen_start"]))
                row["id"] = cursor.fetchone()[0]
            else:
                conn.execute("UPDATE procs SET services = COALESCE(?, services), task = COALESCE(?, task), "
                             "cmdline = COALESCE(?, cmdline) WHERE id = ?",
                             (row["services"], row["task"], row["cmdline"], row["id"]))
        for row, when in ended:
            if row["id"] is not None:
                conn.execute("UPDATE procs SET ended = ? WHERE id = ?", (when, row["id"]))
        conn.executemany(
            "INSERT INTO flows (proc_id, remote, port, proto, bucket, sent, received, events, first, last) "
            "VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT DO UPDATE SET sent = sent + excluded.sent, "
            "received = received + excluded.received, events = events + excluded.events, last = excluded.last",
            [(flow[0]["id"], key[1], key[2], key[3], key[4], flow[1], flow[2], flow[3], flow[4], flow[5])
             for key, flow in flows.items() if flow[0]["id"] is not None])
        conn.executemany(
            "INSERT INTO names (address, name, source, first, last) VALUES (?,?,?,?,?) "
            "ON CONFLICT DO UPDATE SET last = excluded.last",
            [(key[0], key[1], item[0], item[1], item[2]) for key, item in names.items()])
        conn.executemany(
            "INSERT INTO lookups (proc_id, name, first, last, count) VALUES (?,?,?,?,?) "
            "ON CONFLICT DO UPDATE SET last = excluded.last, count = count + excluded.count",
            [(item[0]["id"], key[1], item[1], item[2], item[3]) for key, item in lookups.items()
             if item[0]["id"] is not None])
        conn.executemany(
            "INSERT INTO requests (proc_id, method, url, first, last, count) VALUES (?,?,?,?,?,?) "
            "ON CONFLICT DO UPDATE SET last = excluded.last, count = count + excluded.count",
            [(item[0]["id"], key[1], key[2], item[1], item[2], item[3]) for key, item in requests.items()
             if item[0]["id"] is not None])
        conn.commit()
        return {"flows": len(flows), "names": len(names), "procs": len(dirty)}
