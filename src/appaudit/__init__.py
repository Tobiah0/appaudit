"""App Audit: shows what every app on this PC does when you are not using it."""

from __future__ import annotations

import argparse
import threading
import webbrowser

DEFAULT_PORT = 8756


def main() -> None:
    import uvicorn

    parser = argparse.ArgumentParser(prog="appaudit", description=__doc__)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--no-browser", action="store_true", help="do not open the dashboard automatically")
    args = parser.parse_args()

    url = f"http://127.0.0.1:{args.port}"
    if not args.no_browser:
        threading.Timer(1.0, webbrowser.open, args=(url,)).start()
    # Bound to loopback only: the dashboard exposes details of this PC.
    uvicorn.run("appaudit.api:app", host="127.0.0.1", port=args.port, log_level="warning")
