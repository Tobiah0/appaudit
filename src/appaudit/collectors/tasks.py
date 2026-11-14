"""Scheduled tasks that launch a program, with the last time each one ran.

The last run time is direct evidence that an app ran without the user starting it.
"""

from __future__ import annotations

from ..winutil import command_to_exe, local_naive_to_utc
from . import Evidence

NAME = "tasks"
TITLE = "Scheduled tasks"

TRIGGER_TITLES = {
    0: "on an event", 1: "at a set time", 2: "daily", 3: "weekly", 4: "monthly", 5: "monthly",
    6: "when idle", 7: "when created", 8: "at boot", 9: "at sign-in", 11: "on lock or unlock",
}
ACTION_EXEC = 0
INCLUDE_HIDDEN = 1


def collect() -> list[Evidence]:
    import pythoncom
    import win32com.client

    pythoncom.CoInitialize()
    scheduler = win32com.client.Dispatch("Schedule.Service")
    scheduler.Connect()

    evidence: list[Evidence] = []
    pending = [scheduler.GetFolder("\\")]
    while pending:
        folder = pending.pop()
        try:
            pending.extend(folder.GetFolders(0))
            tasks = list(folder.GetTasks(INCLUDE_HIDDEN))
        except Exception:  # noqa: BLE001 - some folders are not readable without admin
            continue
        for task in tasks:
            try:
                definition = task.Definition
                commands = [
                    (action.Path, action.Arguments or "")
                    for action in definition.Actions
                    if action.Type == ACTION_EXEC
                ]
                if not commands:
                    continue  # COM-handler tasks have no program to attribute
                triggers = sorted({TRIGGER_TITLES.get(t.Type, "on a trigger") for t in definition.Triggers})
                last_run = local_naive_to_utc(task.LastRunTime)
                next_run = local_naive_to_utc(task.NextRunTime)
                path = task.Path
                author = definition.RegistrationInfo.Author
                enabled = bool(task.Enabled)
            except Exception:  # noqa: BLE001 - a single unreadable task is skipped
                continue
            program, arguments = commands[0]
            evidence.append(Evidence(
                source=NAME,
                kind="autostart",
                exe=command_to_exe(program),
                label=task.Name,
                ts=last_run,
                data={
                    "mechanism": "task",
                    "mechanism_title": "Scheduled task",
                    "name": task.Name,
                    "path": path,
                    "command": f"{program} {arguments}".strip(),
                    "enabled": enabled,
                    "triggers": triggers,
                    "last_run": last_run,
                    "next_run": next_run,
                    "author": author,
                    "microsoft_path": path.lower().startswith("\\microsoft\\"),
                },
            ))
    return evidence
