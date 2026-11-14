"""Who owns an address: lookups in the iptoasn.com table (network owner and country)."""

from __future__ import annotations

import bisect
import gzip
import ipaddress
import re
import threading
from array import array

from . import reference

# Registry names are cryptic ("MICROSOFT-CORP-MSN-AS-BLOCK"); these are the ones people meet most.
FRIENDLY = [
    ("microsoft", "Microsoft"), ("google", "Google"), ("amazon", "Amazon"), ("cloudflare", "Cloudflare"),
    ("akamai", "Akamai"), ("fastly", "Fastly"), ("facebook", "Meta"), ("apple", "Apple"), ("valve", "Valve"),
    ("comcast", "Comcast"), ("netflix", "Netflix"), ("github", "GitHub"), ("digitalocean", "DigitalOcean"),
    ("ovh", "OVH"), ("hetzner", "Hetzner"), ("oracle", "Oracle"), ("alibaba", "Alibaba"), ("tencent", "Tencent"),
    ("zoom", "Zoom"), ("spotify", "Spotify"), ("discord", "Discord"), ("twitter", "X (Twitter)"),
    ("level3", "Lumen"), ("lumen", "Lumen"), ("cogent", "Cogent"), ("verizon", "Verizon"), ("att-", "AT&T"),
    ("charter", "Charter"), ("edgecast", "Edgio"), ("limelight", "Edgio"), ("linode", "Akamai (Linode)"),
    ("vultr", "Vultr"), ("adobe", "Adobe"), ("nvidia", "NVIDIA"), ("dropbox", "Dropbox"), ("slack", "Slack"),
    ("riot", "Riot Games"), ("blizzard", "Blizzard"), ("steam", "Valve"), ("zscaler", "Zscaler"),
    ("cdn77", "CDN77"), ("datacamp", "DataCamp/CDN77"), ("i3d", "i3D.net"), ("anthropic", "Anthropic"),
]


def friendly(description: str) -> str:
    lowered = description.lower()
    for needle, name in FRIENDLY:
        if needle in lowered:
            return name
    text = re.sub(r"[-_]", " ", description).strip()
    text = re.sub(r"\b(AS|ASN|NET|BLOCK|INC|LLC|LTD|CORP)\b\.?", "", text, flags=re.IGNORECASE)
    return re.sub(r"\s+", " ", text).strip().title() or description


class Owners:
    """Loads lazily on a background thread; lookups return None until it is ready."""

    def __init__(self) -> None:
        self._ready = threading.Event()
        self._started = False
        self._lock = threading.Lock()
        self._v4_start, self._v4_end, self._v4_org = array("Q"), array("Q"), array("I")
        self._v6_start, self._v6_end, self._v6_org = array("Q"), array("Q"), array("I")
        self._orgs: list[tuple[int, str, str]] = []
        self.available = False

    def load_in_background(self) -> None:
        with self._lock:
            if self._started:
                return
            self._started = True
        threading.Thread(target=self._load, name="owners-load", daemon=True).start()

    def wait(self, seconds: float = 30) -> bool:
        self.load_in_background()
        return self._ready.wait(seconds)

    def _load(self) -> None:
        path = reference.folder() / "ip2asn-combined.tsv.gz"
        try:
            index: dict[tuple[int, str, str], int] = {}
            with gzip.open(path, "rt", encoding="utf-8", errors="replace") as file:
                for line in file:
                    parts = line.rstrip("\n").split("\t")
                    if len(parts) < 5 or parts[2] == "0":
                        continue
                    key = (int(parts[2]), parts[3], parts[4])
                    org = index.get(key)
                    if org is None:
                        org = index[key] = len(self._orgs)
                        self._orgs.append(key)
                    if ":" in parts[0]:
                        self._v6_start.append(int(ipaddress.IPv6Address(parts[0])) >> 64)
                        self._v6_end.append(int(ipaddress.IPv6Address(parts[1])) >> 64)
                        self._v6_org.append(org)
                    else:
                        self._v4_start.append(int(ipaddress.IPv4Address(parts[0])))
                        self._v4_end.append(int(ipaddress.IPv4Address(parts[1])))
                        self._v4_org.append(org)
            self.available = bool(self._orgs)
        except Exception:  # noqa: BLE001 - missing or damaged file: owners stay unknown
            self.available = False
        finally:
            self._ready.set()

    def lookup(self, address: str) -> dict | None:
        if not self._ready.is_set():
            self.load_in_background()
            return None
        if not self.available:
            return None
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return None
        if ip.version == 4:
            value, starts, ends, orgs = int(ip), self._v4_start, self._v4_end, self._v4_org
        else:
            value, starts, ends, orgs = int(ip) >> 64, self._v6_start, self._v6_end, self._v6_org
        position = bisect.bisect_right(starts, value) - 1
        if position < 0 or value > ends[position]:
            return None
        number, country, description = self._orgs[orgs[position]]
        return {"asn": number, "country": country, "network": description, "owner": friendly(description)}


OWNERS = Owners()
