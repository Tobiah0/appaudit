"""Live capture: one trace session, an aggregator, and a flush loop."""

from __future__ import annotations

import subprocess
import threading
import time
from pathlib import Path

import psutil

from .. import etw, livestore
from ..capture.aggregate import Aggregator
from . import SESSION_NAME

FLUSH_SECONDS = 5

PROVIDERS = [
    etw.Provider(etw.KERNEL_NETWORK),
    etw.Provider(etw.KERNEL_PROCESS, keywords=0x10),
    etw.Provider(etw.DNS_CLIENT),
    # URL of each request only. Header and body events carry the "personal data" keyword
    # (0x20000000000) and are left off.
    etw.Provider(etw.WEBIO, keywords=0x4000000000),
    etw.Provider(etw.WININET, keywords=0x1),
    etw.Provider(etw.TASK_SCHEDULER),
]
WEBIO_URLS = PROVIDERS[3]
# With content capture on: the same URLs plus the events Windows marks as personal data
# (headers 100 and 101, body pieces 111). Body pieces are logged at the verbose level.
WEBIO_CONTENT = etw.Provider(etw.WEBIO, keywords=0x4000000000 | 0x20000000000, level=5)
PACKET_PROVIDER = etw.Provider(etw.PKTMON, keywords=0x10, level=5)
PACKET_FILTER = "AppAuditDns"
TLS_SAMPLE_SECONDS = 90
TLS_PACKET_SIZE = 2048                # enough for a whole ClientHello in one or two segments
TLS_SAMPLE_EVERY = None               # seconds between windows; off until Tobiah turns it on


def local_addresses() -> set[str]:
    found = set()
    for addresses in psutil.net_if_addrs().values():
        for address in addresses:
            found.add(address.address.split("%")[0].lower())
    return found


def _run(args: list[str]) -> str:
    try:
        out = subprocess.run(args, capture_output=True, text=True, timeout=60, errors="replace",
                             creationflags=subprocess.CREATE_NO_WINDOW)
        return ((out.stdout or "") + (out.stderr or "")).strip()
    except Exception as error:  # noqa: BLE001
        return f"failed: {error}"


class Capture:
    def __init__(self, record: Path | None = None, packets: bool = True, db: Path | None = None) -> None:
        self.aggregator = Aggregator(local_addresses())
        self.recorder = etw.Recorder(record) if record else None
        self.session = etw.TraceSession(SESSION_NAME, PROVIDERS, self._on_event)
        self.conn = livestore.connect(file=db)
        self.want_packets = packets
        self.packets_on = False
        self.packet_note = "off"
        self.started = time.time()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._services_at = 0.0
        self._services: dict[int, str] = {}
        self._addresses_at = time.time()

    def _on_event(self, event: etw.Event) -> None:
        if self.recorder is not None:
            self.recorder.write(event)
        self.aggregator.feed(event)

    # -- packet monitor ---------------------------------------------------------------

    def start_packets(self) -> str:
        """Read DNS packets through the built-in Packet Monitor. Leaves it alone if already in use."""
        if self.packets_on:
            return self.packet_note
        status = _run(["pktmon", "status"]).lower()
        filters = _run(["pktmon", "filter", "list"]).lower()
        if "not running" not in status or "none" not in filters:
            self.packet_note = "Packet Monitor is in use by something else; left untouched"
            return self.packet_note
        _run(["pktmon", "filter", "add", PACKET_FILTER, "-p", "53"])
        log = livestore.path().with_name("pktmon.etl")
        out = _run(["pktmon", "start", "--capture", "--comp", "nics", "--pkt-size", "512",
                    "--file-name", str(log), "--file-size", "4", "--log-mode", "circular"])
        if "logger" not in out.lower() and "collected" not in out.lower():
            _run(["pktmon", "filter", "remove"])
            self.packet_note = f"Packet Monitor did not start: {out[:120]}"
            return self.packet_note
        self.session.enable(PACKET_PROVIDER)
        self.packets_on = True
        self.packet_note = "reading DNS packets"
        return self.packet_note

    def stop_packets(self) -> None:
        if not self.packets_on:
            return
        self.session.enable(PACKET_PROVIDER, on=False)
        _run(["pktmon", "stop"])
        _run(["pktmon", "filter", "remove"])
        self.packets_on = False
        self.packet_note = "off"

    # -- server names from TLS handshakes: short sampling windows (BLOCKING-RESEARCH.md, R3) -------
    # Capturing every HTTPS packet all the time is too heavy. For a short window, Packet Monitor
    # also passes TCP port 443 at a size that holds a whole ClientHello; the server names read from
    # them name addresses that DNS did not. Then the DNS-only filter comes back.

    def _pktmon_start(self, size: int, with_tls: bool) -> str:
        _run(["pktmon", "filter", "add", PACKET_FILTER, "-p", "53"])
        if with_tls:
            _run(["pktmon", "filter", "add", PACKET_FILTER + " TLS", "-t", "TCP", "-p", "443"])
        log = livestore.path().with_name("pktmon.etl")
        return _run(["pktmon", "start", "--capture", "--comp", "nics", "--pkt-size", str(size),
                     "--file-name", str(log), "--file-size", "16" if with_tls else "4", "--log-mode", "circular"])

    def sample_tls(self, seconds: float = TLS_SAMPLE_SECONDS) -> str:
        """Widen the packet filter to TLS handshakes for `seconds`, then restore it."""
        if not self.packets_on:
            return "packets are off"
        if getattr(self, "_sampling", False):
            return "already sampling"
        self._sampling = True
        _run(["pktmon", "stop"])
        _run(["pktmon", "filter", "remove"])
        self._pktmon_start(TLS_PACKET_SIZE, with_tls=True)
        self.packet_note = "reading DNS packets and TLS server names (sampling)"

        def restore() -> None:
            _run(["pktmon", "stop"])
            _run(["pktmon", "filter", "remove"])
            self._pktmon_start(512, with_tls=False)
            self.packet_note = "reading DNS packets"
            self._sampling = False

        timer = threading.Timer(seconds, restore)
        timer.daemon = True
        timer.start()
        return f"sampling TLS server names for {int(seconds)} seconds"

    # -- request content (off unless the person at the PC switches it on) ---------------

    def set_content(self, on: bool) -> bool:
        """Ask Windows for request headers and bodies as well as URLs, or stop asking."""
        self.session.enable(WEBIO_CONTENT if on else WEBIO_URLS)
        self.aggregator.content = bool(on)
        livestore.set_meta(self.conn, content_capture=int(bool(on)))
        self.conn.commit()
        return bool(on)

    def clear_content(self) -> int:
        with self.aggregator._lock:
            self.aggregator._pending.clear()
        removed = self.conn.execute("DELETE FROM payloads").rowcount
        self.conn.commit()
        return removed

    # -- lifecycle --------------------------------------------------------------------

    def seed_names_from_cache(self) -> int:
        """Names Windows already resolved before we started listening."""
        import json

        raw = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                    "Get-DnsClientCache | Where-Object { $_.Type -in 1,28 } | "
                    "Select-Object Entry, Data | ConvertTo-Json -Compress"])
        try:
            items = json.loads(raw)
        except ValueError:
            return 0
        now = time.time()
        count = 0
        with self.aggregator._lock:
            for item in items if isinstance(items, list) else [items]:
                name, address = str(item.get("Entry") or "").lower().rstrip("."), str(item.get("Data") or "").lower()
                if name and address:
                    self.aggregator._name(address, name, "cache", now)
                    count += 1
        return count

    def start(self) -> None:
        self.session.start()
        if livestore.get_meta(self.conn).get("content_capture") == "1":     # the choice survives a restart
            self.set_content(True)
        if self.want_packets:
            self.start_packets()
        try:
            self.seed_names_from_cache()
        except Exception:  # noqa: BLE001 - a convenience, never a reason to fail
            pass
        self._thread = threading.Thread(target=self._loop, name="appaudit-flush", daemon=True)
        self._thread.start()

    def _detail(self, row: dict) -> None:
        """Fill in what the start event does not carry: hosted services and the command line."""
        name = (row.get("name") or "").lower()
        if name == "svchost.exe" and not row.get("services"):
            if time.time() - self._services_at > 20:
                self._services = {}
                for service in psutil.win_service_iter():
                    try:
                        pid = service.pid()
                    except Exception:  # noqa: BLE001
                        continue
                    if pid:
                        self._services[pid] = (self._services.get(pid, "") + "," + service.name()).lstrip(",")
                self._services_at = time.time()
            row["services"] = self._services.get(row["pid"])
        if row.pop("needs_detail", False) and not row.get("cmdline"):
            try:
                row["cmdline"] = " ".join(psutil.Process(row["pid"]).cmdline())[:600] or None
            except Exception:  # noqa: BLE001 - short-lived processes are often gone already
                pass

    def flush(self) -> None:
        if time.time() - self._addresses_at > 60:
            self.aggregator.local = local_addresses()
            self._addresses_at = time.time()
        self.aggregator.flush(self.conn, self._detail)
        livestore.set_meta(
            self.conn, heartbeat=time.time(), started=self.started, events=self.session.events,
            lost=self.session.lost(), callback_errors=self.session.errors, packets=self.packet_note,
            session_alive=int(self.session.alive()), **{f"count_{k}": v for k, v in self.aggregator.counts.items()})
        self.conn.commit()

    def _loop(self) -> None:
        while not self._stop.wait(FLUSH_SECONDS):
            try:
                self.flush()
            except Exception as error:  # noqa: BLE001 - keep capturing; report in the heartbeat
                try:
                    livestore.set_meta(self.conn, last_error=f"{type(error).__name__}: {error}")
                    self.conn.commit()
                except Exception:  # noqa: BLE001
                    pass

    def status(self) -> dict:
        return {"running": self.session.alive(), "since": self.started, "events": self.session.events,
                "lost": self.session.lost(), "packets": self.packet_note, "content": self.aggregator.content,
                "counts": dict(self.aggregator.counts)}

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(10)
        self.stop_packets()
        self.session.stop()
        try:
            self.aggregator.flush(self.conn, self._detail)
            livestore.set_meta(self.conn, stopped=time.time(), session_alive=0)
            self.conn.commit()
        finally:
            if self.recorder is not None:
                self.recorder.close()
