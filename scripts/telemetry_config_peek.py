"""Elevated, read-only: summarise the shape of the telemetry rule files Windows downloads from
Microsoft (C:\\ProgramData\\Microsoft\\Diagnosis\\DownloadedSettings). Prints counts and key
names only, never the values, into .spike/etw/telemetry_config.json."""

from __future__ import annotations

import json
import re
import time
from collections import Counter
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / ".spike" / "etw"
FOLDER = Path(r"C:\ProgramData\Microsoft\Diagnosis\DownloadedSettings")
GUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
LOOK_FOR = ["05ff9269-f73f-5d04-7f30-398bb2f6e5d0", "56a58b3e-455c-568a-07ce-93df282460c5",
            "usageandqualityinsights", "uqi", "1ds", "4f50731a-89cf-4782-b3e0-dce8c90476ba"]


def walk(node, path, stats):
    if isinstance(node, dict):
        for key, value in node.items():
            stats["keys"] += 1
            prefix = re.split(r"[.:]+", str(key))
            stats["key_prefixes"][":".join(prefix[:2])[:60]] += 1
            lowered = str(key).lower()
            for needle in LOOK_FOR:
                if needle in lowered and len(stats["found"][needle]) < 4:
                    stats["found"][needle].append(f"key {str(key)[:110]}")
            walk(value, path + [str(key)], stats)
    elif isinstance(node, list):
        stats["list_items"] += len(node)
        for item in node:
            walk(item, path, stats)
    elif isinstance(node, str):
        stats["strings"] += 1
        lowered = node.lower()
        for match in GUID.findall(node):
            stats["guids"].add(match.lower())
        for needle in LOOK_FOR:
            if needle in lowered and len(stats["found"][needle]) < 4:
                stats["found"][needle].append(f"value under key {(path[-1] if path else '?')[:110]}")


def main() -> None:
    report = {"read_at": time.strftime("%Y-%m-%d %H:%M:%S"), "files": {}}
    for path in sorted(FOLDER.glob("*.json")):
        entry = {"bytes": path.stat().st_size,
                 "modified": time.strftime("%Y-%m-%d", time.localtime(path.stat().st_mtime))}
        try:
            data = json.loads(path.read_text(encoding="utf-8-sig", errors="replace"))
            stats = {"keys": 0, "list_items": 0, "strings": 0, "guids": set(), "key_prefixes": Counter(),
                     "found": {needle: [] for needle in LOOK_FOR}}
            walk(data, [], stats)
            entry.update({
                "top_level": (list(data)[:10] if isinstance(data, dict) else f"list of {len(data)}"),
                "keys": stats["keys"], "list_items": stats["list_items"], "strings": stats["strings"],
                "distinct_guids": len(stats["guids"]),
                "key_prefixes": dict(stats["key_prefixes"].most_common(14)),
                "found": {needle: hits for needle, hits in stats["found"].items() if hits},
            })
        except Exception as error:  # noqa: BLE001
            entry["error"] = repr(error)[:200]
        report["files"][path.name] = entry
    (OUT / "telemetry_config.json").write_text(json.dumps(report, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
