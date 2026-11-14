"""The helper's fixed command list. Anything not named here is refused."""

from __future__ import annotations

from . import inspect


class Commands:
    def __init__(self, capture) -> None:
        self.capture = capture
        self.stop_requested = False
        self._table = {
            "status": self._status,
            "stop": self._stop,
            "packets": self._packets,
            "switch_apply": self._switch_apply,
            "switch_undo": self._switch_undo,
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

    def _packets(self, request: dict) -> dict:
        if request.get("on"):
            return {"packets": self.capture.start_packets()}
        self.capture.stop_packets()
        return {"packets": "off"}
