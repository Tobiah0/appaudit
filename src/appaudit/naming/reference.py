"""Public reference data kept outside the repository, in data/reference.

    python -m appaudit.naming.reference        downloads or refreshes everything

Sources and licences:
  iptoasn.com               address ranges to network owner   public domain (PDDL)
  hagezi/dns-blocklists     tracker and vendor-telemetry lists GPL-3.0
The files are used as data at run time and are not redistributed with the code.
"""

from __future__ import annotations

import urllib.request
from pathlib import Path

from ..store import data_dir

HAGEZI = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/"
FILES = {
    "ip2asn-combined.tsv.gz": "https://iptoasn.com/data/ip2asn-combined.tsv.gz",
    "trackers.txt": HAGEZI + "pro.txt",
    "native.winoffice.txt": HAGEZI + "native.winoffice.txt",
    "native.amazon.txt": HAGEZI + "native.amazon.txt",
    "native.apple.txt": HAGEZI + "native.apple.txt",
    "native.samsung.txt": HAGEZI + "native.samsung.txt",
    "native.tiktok.txt": HAGEZI + "native.tiktok.txt",
}


def folder() -> Path:
    target = data_dir() / "reference"
    target.mkdir(parents=True, exist_ok=True)
    return target


def fetch(force: bool = False) -> dict[str, str]:
    results = {}
    for name, url in FILES.items():
        target = folder() / name
        if target.exists() and target.stat().st_size > 0 and not force:
            results[name] = "present"
            continue
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(request, timeout=60) as response:
                target.write_bytes(response.read())
            results[name] = f"downloaded {target.stat().st_size} bytes"
        except Exception as error:  # noqa: BLE001 - the product works without reference data
            results[name] = f"failed: {error}"
    return results


if __name__ == "__main__":
    for name, outcome in fetch().items():
        print(f"{name}: {outcome}")
