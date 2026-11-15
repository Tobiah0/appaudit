"""What a destination is for: company, category and purpose from the knowledge map, plus
whether public blocklists call it a tracker."""

from __future__ import annotations

import ipaddress
from functools import lru_cache
from pathlib import Path

import yaml

from . import reference
from .owners import OWNERS

KNOWLEDGE = Path(__file__).resolve().parent.parent / "knowledge"
VENDOR_LISTS = {
    "native.winoffice.txt": "Microsoft", "native.amazon.txt": "Amazon", "native.apple.txt": "Apple",
    "native.samsung.txt": "Samsung", "native.tiktok.txt": "TikTok",
}
# Categories that mean "data about you or your device leaves the PC".
REPORTING = {"telemetry", "advertising"}


@lru_cache(maxsize=1)
def _domain_map() -> dict[str, dict]:
    entries = yaml.safe_load((KNOWLEDGE / "domains.yaml").read_text(encoding="utf-8"))
    table = {}
    for entry in entries:
        info = {key: entry.get(key) for key in ("company", "category", "purpose", "breaks", "blockable", "vendor_site")}
        for suffix in entry["suffixes"]:
            table.setdefault(suffix.lower(), info)
    return table


def _parents(name: str):
    parts = name.lower().rstrip(".").split(".")
    for index in range(len(parts)):
        yield ".".join(parts[index:])


def _read_list(path: Path) -> set[str]:
    found = set()
    try:
        with open(path, encoding="utf-8", errors="replace") as file:
            for line in file:
                if line.startswith("||"):
                    found.add(line[2:].split("^", 1)[0].strip().lower())
    except OSError:
        pass
    return found


@lru_cache(maxsize=1)
def _blocklists() -> tuple[set[str], dict[str, str]]:
    folder = reference.folder()
    general = _read_list(folder / "trackers.txt")
    vendor = {}
    for file, company in VENDOR_LISTS.items():
        for domain in _read_list(folder / file):
            vendor[domain] = company
    return general, vendor


DOC_PREFIXES = {"docs", "doc", "developer", "developers", "dev", "help", "support", "learn", "status", "blog",
                "community", "dashboard", "console", "academy", "university"}


def _is_website(name: str, info: dict) -> bool:
    """Documentation and websites of a reporting service are not reporting: a person reading
    docs.mixpanel.com is not sending analytics. Collector vendors' home pages too (www.datadoghq.com)."""
    if info.get("category") not in REPORTING:
        return False
    parts = name.lower().rstrip(".").split(".")
    if len(parts) >= 3 and parts[0] in DOC_PREFIXES:
        return True
    return bool(info.get("vendor_site")) and (parts[0] == "www" or ".".join(parts) == registrable(name))


@lru_cache(maxsize=20000)
def for_name(name: str) -> dict:
    """Label a host name. Always returns a dict; unknown fields are None."""
    table = _domain_map()
    general, vendor = _blocklists()
    label = {"company": None, "category": None, "purpose": None, "breaks": None, "tracker": None,
             "blockable": None, "site": registrable(name)}
    for candidate in _parents(name):
        info = table.get(candidate)
        if info:
            label.update({key: value for key, value in info.items() if key != "vendor_site"})
            if _is_website(name, info):
                label.update(category="developer", purpose=f"{info['company']}'s website or documentation", blockable=None)
                return label
            break
    for candidate in _parents(name):
        if candidate in vendor:
            label["tracker"] = f"{vendor[candidate]} built-in tracking (HaGeZi native list)"
            label["company"] = label["company"] or vendor[candidate]
            if label["category"] not in REPORTING:
                label["category"] = "telemetry"
                label["purpose"] = f"{vendor[candidate]} tracking endpoint"
            break
        if candidate in general:
            label["tracker"] = "Listed as tracking or advertising (HaGeZi Pro list)"
            if label["category"] is None:
                label["category"] = "advertising"
                label["purpose"] = "Tracking or advertising"
            break
    return label


_TWO_PART_TLDS = {"co.uk", "com.au", "co.jp", "com.br", "co.in", "com.cn", "org.uk", "co.kr", "com.mx"}


def registrable(name: str) -> str:
    """The site a host belongs to: a.b.example.com -> example.com (a small heuristic, no full list)."""
    parts = name.lower().rstrip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    if ".".join(parts[-2:]) in _TWO_PART_TLDS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def is_lan(address: str) -> bool:
    try:
        return ipaddress.ip_address(address).is_private
    except ValueError:
        return False


def for_destination(address: str, names: list[str]) -> dict:
    """Combine everything known about one remote address."""
    best = None
    for name in names:
        label = for_name(name)
        score = (label["category"] in REPORTING, label["tracker"] is not None, label["company"] is not None)
        if best is None or score > best[0]:
            best = (score, name, label)
    owner = None if is_lan(address) else OWNERS.lookup(address)
    result = {"address": address, "name": best[1] if best else None, "names": names[:6],
              "company": None, "category": None, "purpose": None, "breaks": None, "tracker": None, "site": None,
              "blockable": None,
              "owner": owner["owner"] if owner else None, "country": owner["country"] if owner else None,
              "network": owner["network"] if owner else None, "lan": is_lan(address)}
    if best:
        result.update(best[2])
    if result["lan"]:
        result.update(company="Your local network", category="local", purpose="A device on your own network")
    elif result["company"] is None and owner:
        result["company"] = owner["owner"]
        result["purpose"] = f"Address owned by {owner['owner']}; the service behind it is not known"
    return result
