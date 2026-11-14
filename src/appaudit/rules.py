"""Turn grouped evidence into one summary per app, with plain-language findings."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .collectors import Evidence
from .identity import AppRef, Resolver

RECENT_SELF_RUN = timedelta(days=7)
RECENT_SENSOR = timedelta(days=30)


def _ago(when: datetime, now: datetime) -> str:
    days = max((now - when).days, 0)
    if days == 0:
        return "today"
    if days == 1:
        return "yesterday"
    if days < 60:
        return f"{days} days ago"
    if days < 730:
        return f"{days // 30} months ago"
    return f"{days // 365} years ago"


def _usage(items: list[Evidence]) -> dict | None:
    if not items:
        return None
    # Launching through a shortcut is recorded twice (shortcut and executable), so
    # counts come from the executable entries whenever there are any.
    direct = [e for e in items if e.data.get("via") == "exe"] or items
    last_used = max((e.ts for e in items if e.ts), default=None)
    return {
        "last_used": last_used,
        "run_count": sum(e.data.get("run_count", 0) for e in direct),
        "focus_minutes": round(sum(e.data.get("focus_ms", 0) for e in direct) / 60000, 1),
    }


def _running(items: list[Evidence]) -> dict | None:
    if not items:
        return None
    remotes: dict[tuple, dict] = {}
    for e in items:
        for remote in e.data.get("remotes", []):
            remotes.setdefault((remote["ip"], remote["port"]), remote)
    return {
        "process_count": sum(e.data.get("process_count", 0) for e in items),
        "since": min((e.ts for e in items if e.ts), default=None),
        "memory_mb": round(sum(e.data.get("memory_mb", 0) for e in items), 1),
        "connection_count": sum(e.data.get("connection_count", 0) for e in items),
        "remotes": list(remotes.values()),
        "executables": sorted({e.exe for e in items if e.exe}),
    }


def _sensors(items: list[Evidence]) -> list[dict]:
    latest: dict[str, Evidence] = {}
    for e in items:
        capability = e.data["capability"]
        if capability not in latest or (e.ts and e.ts > latest[capability].ts):
            latest[capability] = e
    return [
        {
            "capability": capability,
            "title": e.data["title"],
            "last_start": e.data["last_start"],
            "last_stop": e.data["last_stop"],
            "in_use": e.data["in_use"],
            "allowed": e.data.get("allowed"),
        }
        for capability, e in sorted(latest.items())
    ]


def _summarize(ref: AppRef, evidence: list[Evidence], now: datetime, unused_days: int,
               launchable: bool) -> dict:
    usage = _usage([e for e in evidence if e.kind == "usage"])
    launchable = launchable or usage is not None
    running = _running([e for e in evidence if e.kind == "process"])
    sensors = _sensors([e for e in evidence if e.kind == "sensor"])
    autostart = [
        {**e.data, "exe": e.exe, "source": e.source}
        for e in evidence if e.kind == "autostart"
    ]
    enabled = [a for a in autostart if a.get("enabled")]

    last_used = usage["last_used"] if usage else None
    days_unused = (now - last_used).days if last_used else None
    # Focus time with no launch date means the app was used but started by something
    # other than Explorer (a game launcher, for example), so it is not treated as unused.
    used_undated = last_used is None and usage is not None and usage["focus_minutes"] > 0
    unused = not used_undated and (last_used is None or days_unused >= unused_days)
    if last_used:
        opened = f"you last opened it {_ago(last_used, now)}"
    elif launchable:
        opened = "there is no record of you opening it"
    else:
        opened = "it is a background component with no Start menu entry"

    task_runs = [a["last_run"] for a in autostart if a.get("mechanism") == "task" and a.get("last_run")]
    last_self_run = max(task_runs, default=None)

    findings = []
    score = 0
    if unused and enabled:
        kinds = sorted({a["mechanism_title"] for a in enabled})
        findings.append({
            "code": "starts_unused",
            "title": "Starts by itself",
            "detail": f"Starts through {', '.join(kinds).lower()}, but {opened}.",
        })
        score += 40
    if unused and running:
        findings.append({
            "code": "running_unused",
            "title": "Running now",
            "detail": f"{running['process_count']} process(es) running right now, but {opened}.",
        })
        score += 25
    elif unused and last_self_run and now - last_self_run <= RECENT_SELF_RUN:
        findings.append({
            "code": "ran_unused",
            "title": "Ran by itself",
            "detail": f"A scheduled task ran it {_ago(last_self_run, now)}, but {opened}.",
        })
        score += 20
    if unused and running and running["connection_count"]:
        findings.append({
            "code": "network_unused",
            "title": "Online now",
            "detail": f"{running['connection_count']} open network connection(s) right now, but {opened}.",
        })
        score += 15
    for sensor in sensors:
        start = sensor["last_start"]
        after_last_use = last_used is not None and start > last_used + timedelta(days=1)
        recent_while_unused = unused and now - start <= RECENT_SENSOR
        if after_last_use or recent_while_unused:
            findings.append({
                "code": "sensor_unused",
                "title": f"Used {sensor['title'].lower()}",
                "detail": f"Accessed your {sensor['title'].lower()} {_ago(start, now)}, but {opened}.",
            })
            score += 35
    if findings and days_unused is not None and days_unused >= 365:
        score += 10
    if findings and launchable:
        # An app meant to be opened that never is ranks above a background component.
        score += 20

    return {
        "id": ref.id,
        "name": ref.name,
        "publisher": ref.publisher,
        "kind": ref.kind,
        "is_system": ref.is_system,
        "launchable": launchable,
        "install_dir": ref.install_dir,
        "usage": usage,
        "used_undated": used_undated,
        "days_unused": days_unused,
        "autostart": autostart,
        "autostart_enabled": len(enabled),
        "last_self_run": last_self_run,
        "running": running,
        "sensors": sensors,
        "findings": findings,
        "score": score,
    }


def _merge_name_only(groups: dict[str, dict]) -> None:
    """Fold apps known only by a name into the single app that shares that name."""
    by_name: dict[str, list[str]] = {}
    for app_id, group in groups.items():
        if not app_id.startswith("name:"):
            by_name.setdefault(group["ref"].name.casefold(), []).append(app_id)
    for app_id in [key for key in groups if key.startswith("name:")]:
        matches = by_name.get(groups[app_id]["ref"].name.casefold(), [])
        if len(matches) == 1:
            groups[matches[0]]["evidence"].extend(groups.pop(app_id)["evidence"])


def build_apps(evidence: list[Evidence], resolver: Resolver, unused_days: int = 90,
               now: datetime | None = None) -> list[dict]:
    now = now or datetime.now(timezone.utc)
    groups: dict[str, dict] = {}
    for item in evidence:
        ref = resolver.resolve(item)
        groups.setdefault(ref.id, {"ref": ref, "evidence": []})["evidence"].append(item)
    _merge_name_only(groups)
    apps = [
        _summarize(g["ref"], g["evidence"], now, unused_days, g["ref"].id in resolver.launchable)
        for g in groups.values()
    ]
    apps.sort(key=lambda app: (-app["score"], app["name"].casefold()))
    return apps
