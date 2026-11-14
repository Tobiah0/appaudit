"""Processes running right now and their open network connections (a snapshot)."""

from __future__ import annotations

import ipaddress
import os
from collections import defaultdict
from datetime import datetime, timezone

import psutil

from . import Evidence

NAME = "processes"
TITLE = "Running processes and connections"

MAX_REMOTES = 40


def _remote(ip: str) -> dict | None:
    try:
        address = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return None
    if address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified:
        return None
    return {"ip": str(address), "lan": address.is_private}


def collect() -> list[Evidence]:
    connections: dict[int, list[dict]] = defaultdict(list)
    try:
        for conn in psutil.net_connections(kind="inet"):
            if not conn.raddr or not conn.pid:
                continue
            remote = _remote(conn.raddr.ip)
            if remote:
                remote["port"] = conn.raddr.port
                connections[conn.pid].append(remote)
    except psutil.AccessDenied:
        pass

    groups: dict[str, dict] = {}
    for proc in psutil.process_iter(["pid", "name", "exe", "create_time", "memory_info"]):
        info = proc.info
        if info["pid"] in (0, 4):
            continue
        exe = info.get("exe")
        if exe and not os.path.isabs(exe):
            exe = None  # kernel pseudo-processes such as Registry report a bare name
        name = info.get("name") or "unknown"
        group = groups.setdefault((exe or name).lower(), {
            "exe": exe, "name": name, "pids": [], "started": None, "rss": 0, "remotes": {}, "connections": 0,
        })
        group["pids"].append(info["pid"])
        created = info.get("create_time")
        if created and (group["started"] is None or created < group["started"]):
            group["started"] = created
        memory = info.get("memory_info")
        if memory:
            group["rss"] += memory.rss
        for remote in connections.get(info["pid"], []):
            group["connections"] += 1
            group["remotes"].setdefault((remote["ip"], remote["port"]), remote)

    evidence = []
    for group in groups.values():
        started = datetime.fromtimestamp(group["started"], tz=timezone.utc) if group["started"] else None
        evidence.append(Evidence(
            source=NAME,
            kind="process",
            exe=group["exe"],
            label=group["name"],
            ts=started,
            data={
                "process_count": len(group["pids"]),
                "pids": group["pids"][:20],
                "started": started,
                "memory_mb": round(group["rss"] / (1024 * 1024), 1),
                "connection_count": group["connections"],
                "remotes": list(group["remotes"].values())[:MAX_REMOTES],
                "path_hidden": group["exe"] is None,
            },
        ))
    return evidence
