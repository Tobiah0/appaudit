"""Windows services set to start automatically."""

from __future__ import annotations

import psutil

from ..winutil import command_to_exe
from . import Evidence

NAME = "services"
TITLE = "Automatic services"


def collect() -> list[Evidence]:
    evidence: list[Evidence] = []
    for service in psutil.win_service_iter():
        try:
            start_type = service.start_type()
            if start_type != "automatic":
                continue
            binpath = service.binpath()
            evidence.append(Evidence(
                source=NAME,
                kind="autostart",
                exe=command_to_exe(binpath),
                label=service.display_name(),
                data={
                    "mechanism": "service",
                    "mechanism_title": "Automatic service",
                    "name": service.name(),
                    "display_name": service.display_name(),
                    "command": binpath,
                    "enabled": True,
                    "status": service.status(),
                    "account": service.username(),
                },
            ))
        except (psutil.Error, OSError):
            continue
    return evidence
