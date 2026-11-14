"""The helper's fixed command list. Anything not named here is refused."""

from __future__ import annotations


class Commands:
    def __init__(self, capture) -> None:
        self.capture = capture
        self.stop_requested = False
        self._table = {
            "status": self._status,
            "stop": self._stop,
            "packets": self._packets,
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

    def _packets(self, request: dict) -> dict:
        if request.get("on"):
            return {"packets": self.capture.start_packets()}
        self.capture.stop_packets()
        return {"packets": "off"}
