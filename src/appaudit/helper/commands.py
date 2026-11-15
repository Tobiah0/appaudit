"""The helper's fixed command list. Anything not named here is refused."""

from __future__ import annotations

from .. import history
from . import inspect


class Commands:
    def __init__(self, capture) -> None:
        self.capture = capture
        self.stop_requested = False
        self._table = {
            "status": self._status,
            "stop": self._stop,
            "packets": self._packets,
            "content": lambda request: {"content": self.capture.set_content(bool(request.get("on")))},
            "content_clear": lambda _request: {"removed": self.capture.clear_content()},
            "switch_apply": self._switch_apply,
            "switch_undo": self._switch_undo,
            "block_add": self._block_add,
            "block_remove": self._block_remove,
            "stop_address_add": self._stop_address_add,
            "stop_name_add": self._stop_name_add,
            "stop_remove": self._stop_remove,
            "stop_refresh": self._stop_refresh,
            "history_refresh": lambda _request: history.refresh(),
            "trace_sessions": lambda _request: inspect.trace_sessions(),
            "windows_telemetry": lambda _request: inspect.windows_telemetry(),
            "transcript": lambda request: inspect.transcript(min(int(request.get("limit", 200)), 1000)),
        }

    def register(self, name: str, handler) -> None:
        self._table[name] = handler

    def handle(self, request: dict) -> dict:
        handler = self._table.get(request.get("cmd"))
        if handler is None:
            return {"ok": False, "error": f"unknown command {request.get('cmd')!r}"}
        return {"ok": True, **(handler(request) or {})}

    def _status(self, _request: dict) -> dict:
        return {"status": self.capture.status(), "commands": sorted(self._table)}

    def _stop(self, _request: dict) -> dict:
        self.stop_requested = True
        return {"stopping": True}

    # The caller names a catalogue switch or a journal entry. The values written come from the
    # catalogue and the journal on this side, never from the request.
    def _switch_apply(self, request: dict) -> dict:
        from .. import switches

        switch = switches.load_catalogue().get(str(request.get("id")))
        if switch is None:
            raise KeyError("unknown switch")
        return switches.apply(switch, only_admin=True)

    def _switch_undo(self, request: dict) -> dict:
        from .. import switches

        return switches.undo(int(request["entry"]), only_admin=True)

    # The path is validated in blocks.add: a real .exe outside the Windows folder, nothing else.
    def _block_add(self, request: dict) -> dict:
        from .. import blocks

        return blocks.add(str(request.get("exe", "")))

    def _block_remove(self, request: dict) -> dict:
        from .. import blocks

        return blocks.remove(int(request["id"]))

    # Stopping one destination (STOPPING.md). The request names a program and a host this PC already
    # used; stops.py looks everything else up and checks it again. Refused while real stops are off.
    def _stop_address_add(self, request: dict) -> dict:
        from .. import livestore, stops

        backend = stops.backend_for_real()
        conn = livestore.connect(readonly=True)
        try:
            return stops.add_address_block(conn, str(request.get("exe", "")), str(request.get("name", "")), backend)
        finally:
            conn.close()

    def _stop_name_add(self, request: dict) -> dict:
        from .. import livestore, stops

        backend = stops.backend_for_real()
        conn = livestore.connect(readonly=True)
        try:
            return stops.add_name_block(conn, str(request.get("name", "")), backend)
        finally:
            conn.close()

    def _stop_remove(self, request: dict) -> dict:
        from .. import stops

        return stops.remove(int(request["id"]), stops.backend_for_real())

    def _stop_refresh(self, _request: dict) -> dict:
        from .. import livestore, stops

        backend = stops.backend_for_real()
        conn = livestore.connect(readonly=True)
        try:
            return {"refreshed": stops.refresh_addresses(conn, backend)}
        finally:
            conn.close()

    def _packets(self, request: dict) -> dict:
        if request.get("on"):
            return {"packets": self.capture.start_packets()}
        self.capture.stop_packets()
        return {"packets": "off"}
