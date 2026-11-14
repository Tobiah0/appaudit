"""Run the elevated helper:  python -m appaudit.helper  (from an elevated prompt).

`python -m appaudit.helper --launch` starts it elevated from a normal prompt.
"""

from __future__ import annotations

import argparse
import ctypes
import os
import sys
import time
import traceback
from pathlib import Path

from .. import livestore
from ..store import data_dir
from ..winutil import is_admin


def launch_elevated(extra: list[str]) -> int:
    """Start this module elevated, with no console window. Returns the ShellExecute result."""
    arguments = " ".join(["-m", "appaudit.helper", *extra])
    executable = sys.executable.replace("python.exe", "pythonw.exe")
    if not os.path.exists(executable):
        executable = sys.executable
    return ctypes.windll.shell32.ShellExecuteW(None, "runas", executable, arguments, str(Path.cwd()), 0)


def main() -> None:
    parser = argparse.ArgumentParser(prog="appaudit.helper", description=__doc__)
    parser.add_argument("--launch", action="store_true", help="start the helper elevated and return")
    parser.add_argument("--record", type=Path, help="also write raw events to this file")
    parser.add_argument("--no-packets", action="store_true", help="do not read DNS packets")
    parser.add_argument("--seconds", type=float, default=0, help="stop after this long (0 = until told)")
    args = parser.parse_args()

    if args.launch:
        extra = [arg for arg in sys.argv[1:] if arg != "--launch"]
        result = launch_elevated(extra)
        print("helper started" if result > 32 else f"could not start the helper (code {result})")
        return
    if not is_admin():
        raise SystemExit("The helper needs administrator rights. Use: python -m appaudit.helper --launch")

    log = data_dir() / "helper.log"

    def note(text: str) -> None:
        with log.open("a", encoding="utf-8") as handle:
            handle.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {text}\n")

    from . import pipe
    from .capture import Capture
    from .commands import Commands

    try:
        try:                                    # one helper at a time
            pipe.send({"cmd": "status"}, timeout_ms=300)
            note("another helper is already running; exiting")
            return
        except ConnectionError:
            pass
        capture = Capture(record=args.record, packets=not args.no_packets)
        capture.start()
        note(f"capture started, packets: {capture.packet_note}")
        commands = Commands(capture)
        deadline = time.time() + args.seconds if args.seconds else None
        if deadline:
            import threading

            def expire() -> None:
                commands.stop_requested = True
                try:
                    pipe.send({"cmd": "status"}, timeout_ms=500)     # wake the pipe loop
                except ConnectionError:
                    pass

            threading.Timer(args.seconds, expire).start()
        try:
            pipe.serve(commands.handle, lambda: commands.stop_requested)
        finally:
            capture.stop()
            note(f"capture stopped after {capture.session.events} events")
    except Exception:  # noqa: BLE001
        note("helper failed:\n" + traceback.format_exc())
        try:
            conn = livestore.connect()
            livestore.set_meta(conn, last_error=traceback.format_exc()[-400:], session_alive=0)
            conn.commit()
        except Exception:  # noqa: BLE001
            pass
        raise


if __name__ == "__main__":
    main()
