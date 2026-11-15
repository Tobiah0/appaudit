"""Read Firefox's own HTTP log: the address and headers of every request it made.

Firefox writes this log when started with MOZ_LOG=timestamp,nsHttp:3 and MOZ_LOG_FILE=<path>.
It holds each request's first line and headers between "http request [" and "]"; it does not hold
bodies. The main process and each content process write their own file (moz.log.moz_log,
moz.log.child-N.moz_log).

The report has the same shape as netlog.report, so the same page shows both.
"""

from __future__ import annotations

import re
from pathlib import Path

from . import netlog

_LINE = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+) UTC - \[[^\]]*\]: \w/nsHttp (.*)$")
MAX_FILE = 400 * 1024 * 1024


def _timestamp(text: str) -> float:
    from datetime import datetime, timezone

    return datetime.strptime(text, "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc).timestamp() * 1000


def requests_in(lines) -> list[dict]:
    found, block, started = [], None, None
    for raw in lines:
        match = _LINE.match(raw.rstrip("\r\n"))
        if not match:
            continue
        stamp, body = match.groups()
        if body.strip() == "http request [":
            block, started = [], stamp
            continue
        if block is None:
            continue
        if body.strip() == "]":
            if block:
                found.append(_request(block, started))
            block = None
            continue
        if body.strip():
            block.append(body.strip())
    return found


def _request(block: list[str], stamp: str) -> dict:
    method, path = (block[0].split(" ") + ["", ""])[:2]
    headers = block[1:]
    host = next((line.split(":", 1)[1].strip() for line in headers if line.lower().startswith("host:")), "")
    url = path if path.startswith("http") else f"https://{host}{path}"
    return {"time": _timestamp(stamp), "method": method, "url": netlog.safe_url(url), "host": host.split(":")[0],
            "status": None, "initiator": None, "request_headers": netlog._headers_text(headers), "response_headers": "",
            "body_size": 0, "body_decoded_size": 0, "body_note": "Firefox's log holds addresses and headers, not bodies",
            "body": "", "body_truncated": False, "summary": None}


def report_folder(folder: Path, stem: str = "moz.log") -> dict:
    requests = []
    for path in sorted(Path(folder).glob(f"{stem}*")):
        if path.stat().st_size > MAX_FILE:
            continue
        with open(path, encoding="utf-8", errors="replace") as handle:
            requests += requests_in(handle)
    requests.sort(key=lambda item: item["time"])
    return {**netlog.overview(requests), "engine": "firefox"}
