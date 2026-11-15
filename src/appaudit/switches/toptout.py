"""Switches imported from toptout, a community database of telemetry opt-outs (MIT licence).

    python -m appaudit.switches.toptout        downloads or refreshes the data

toptout describes 160+ products, each with one or more telemetry channels and how to turn them
off: an environment variable, a registry value, a setting in a JSON or INI file, a command to
run, or manual instructions. This module turns each channel into a catalogue switch:

  env, registry, json_file, ini_file   -> checks the engine can apply, preview and undo
  noop (manual), exec, other files     -> steps the person follows themselves

The data is downloaded into data/reference/toptout and read at run time; it is not shipped with
the code. Imported switches are marked as such, never replace a hand-written switch, and appear
only when the product is found on this PC (its settings file exists, its command is on the path,
or its program has been seen running).

Source: https://github.com/beatcracker/toptout
"""

from __future__ import annotations

import io
import json
import re
import urllib.request
import zipfile
from pathlib import Path

from ..store import data_dir

ARCHIVE = "https://codeload.github.com/beatcracker/toptout/zip/refs/heads/master"
SOURCE = "https://github.com/beatcracker/toptout"
ANY_VALUE = "ANY_VALUE"          # toptout's placeholder for "any value turns it off"
HIVES = {"HKEY_CURRENT_USER": "HKCU", "HKEY_LOCAL_MACHINE": "HKLM"}
REGISTRY_KINDS = {"REG_DWORD": "dword", "REG_QWORD": "qword", "REG_SZ": "string"}
skipped: list[str] = []          # why channels were not imported, for diagnostics


def folder() -> Path:
    return data_dir() / "reference" / "toptout"


def fetch() -> str:
    """Download the current data files. Returns a one-line outcome."""
    request = urllib.request.Request(ARCHIVE, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(request, timeout=60) as response:
        archive = zipfile.ZipFile(io.BytesIO(response.read()))
    target = folder()
    target.mkdir(parents=True, exist_ok=True)
    count = 0
    for name in archive.namelist():
        parts = name.split("/")
        if len(parts) == 3 and parts[1] == "data" and parts[2].endswith(".json"):
            (target / parts[2]).write_bytes(archive.read(name))
            count += 1
    return f"{count} files in {target}"


def _exe(name: str) -> str:
    """Program file name: toptout lists some with ".exe" and some without."""
    return name if name.lower().endswith(".exe") else f"{name}.exe"


def _windows_path(path: dict | None) -> str | None:
    if not path:
        return None
    return path.get("windows") or path.get("default")


def _pointer_keys(pointer: str) -> list[str]:
    """JSON Pointer (RFC 6901) to a list of keys."""
    return [part.replace("~1", "/").replace("~0", "~") for part in pointer.split("/")[1:]]


def _ini_selector(dasel: str) -> tuple[str | None, str]:
    parts = [part.replace("\\.", ".") for part in _split_dasel(dasel.lstrip("."))]
    return (None, parts[0]) if len(parts) == 1 else (parts[0], parts[-1])


def _split_dasel(selector: str) -> list[str]:
    parts, current, escaped = [], "", False
    for char in selector:
        if escaped:
            current += char
            escaped = False
        elif char == "\\":
            current += char
            escaped = True
        elif char == ".":
            parts.append(current)
            current = ""
        else:
            current += char
    return parts + [current]


def _registry_value(value: str | None, kind: str):
    if value is None or kind != "dword":
        return value
    try:
        return int(value)
    except ValueError:
        return value


def _convert(product: dict, channel: dict, kind: str, body) -> tuple[list[dict], list[dict]]:
    """(checks, steps) for one target of one channel."""
    apps = [_exe(name) for name in product.get("executable_name") or []]
    if kind == "noop":
        return [], [{"name": item["name"], "description": item["description"], "link": item.get("link")}
                    for item in body if item.get("name") and item.get("description")]
    checks, steps = [], []
    for scope, props in (body.get("scope") or {}).items():
        if kind == "registry":                       # a registry key path, not a file path per OS
            path = props.get("path") if isinstance(props.get("path"), str) else None
        else:
            path = _windows_path(props.get("path")) if isinstance(props.get("path"), dict) else None
        if not path:
            continue
        value = props.get("value") or {}
        opt_out = value.get("opt_out")
        if kind == "env" and opt_out == ANY_VALUE:              # "set it to anything": any value counts
            checks.append({"type": "env", "name": path, "private": "1", "private_any": True})
        elif kind == "env" and opt_out is not None:
            checks.append({"type": "env", "name": path, "private": opt_out})
        elif kind == "registry" and props.get("root") in HIVES and opt_out is not None:
            reg_kind = REGISTRY_KINDS.get(props.get("type"), "string")
            checks.append({"type": "registry", "hive": HIVES[props["root"]], "key": props["path"],
                           "value": props["key"], "private": _registry_value(opt_out, reg_kind), "kind": reg_kind})
        elif kind == "json_file" and scope == "user" and opt_out is not None \
                and (props.get("selector") or {}).get("json_pointer"):
            checks.append({"type": "file", "format": "json", "path": path,
                           "keys": _pointer_keys(props["selector"]["json_pointer"]), "private": opt_out, "apps": apps})
        elif kind == "ini_file" and scope == "user" and opt_out is not None \
                and (props.get("selector") or {}).get("dasel"):
            section, key = _ini_selector(props["selector"]["dasel"])
            checks.append({"type": "file", "format": "ini", "path": path, "section": section, "key": key,
                           "private": opt_out, "apps": apps})
        elif kind == "exec" and isinstance(opt_out, list):
            command = " ".join([path, *opt_out])
            steps.append({"name": "Run a command", "description": f"Run this in a terminal: `{command}`"})
        elif props.get("display_value"):
            steps.append({"name": f"Edit {Path(path).name}",
                          "description": f"In `{path}`, set:\n{props['display_value']}"})
    return checks, steps


MARKETPLACE = re.compile(r"marketplace\.visualstudio\.com/items\?itemName=([\w.-]+)")


def _owns(product_id: str, sharers: set[str]) -> bool:
    """Whether a file or program shared by several products is evidence for this one.

    VS Code's settings.json and `code` command are listed for VS Code and for eleven extensions.
    They show that VS Code is installed, not that an extension is: only the main product (the one
    whose id the others extend, "vscode" for "vscode-julia") may use them as evidence.
    """
    if sharers == {product_id}:
        return True
    return all(other == product_id or other.startswith(product_id + "-") for other in sharers)


def _detect(product: dict, checks: list[dict], shared: dict[str, set[str]]) -> dict:
    found = [{"path": check["path"]} for check in checks
             if check["type"] == "file" and _owns(product["id"], shared.get("file:" + check["path"].lower(), {product["id"]}))]
    names = [name for name in product.get("executable_name") or []
             if _owns(product["id"], shared.get("exe:" + name.lower(), {product["id"]}))]
    if names:
        found.append({"command": names})
        found.append({"process": [_exe(name) for name in names]})
    for link in (product.get("links") or {}).values():           # a VS Code extension: its own folder
        match = MARKETPLACE.search(str(link))
        if match:
            found.append({"glob": f"%USERPROFILE%\\.vscode\\extensions\\{match.group(1)}-*"})
    return {"any": found} if found else {"path": "%SystemRoot%\\__never__"}


def _shared(products: list[dict]) -> dict[str, set[str]]:
    """Which products name each settings file and each program."""
    sharers: dict[str, set[str]] = {}
    for product in products:
        for name in product.get("executable_name") or []:
            sharers.setdefault("exe:" + name.lower(), set()).add(product["id"])
        for channel in product.get("telemetry") or []:
            for kind, body in (channel.get("target") or {}).items():
                if not kind.endswith("_file") or not isinstance(body, dict):
                    continue
                for props in (body.get("scope") or {}).values():
                    path = _windows_path(props.get("path")) if isinstance(props.get("path"), dict) else None
                    if path:
                        sharers.setdefault("file:" + path.lower(), set()).add(product["id"])
    return sharers


def _channel_switch(product: dict, channel: dict, covered: set, shared: dict[str, set[str]]) -> dict | None:
    from . import check_identity

    checks, steps = [], []
    for kind, body in (channel.get("target") or {}).items():
        more_checks, more_steps = _convert(product, channel, kind, body)
        checks += more_checks
        steps += more_steps
    try:
        new = [check for check in checks if check_identity(check) not in covered]
    except KeyError:
        new = checks
    if checks and not new:              # a catalogue switch already makes this change; its steps are extra
        skipped.append(f"{product['id']}/{channel['id']}: already in the catalogue")
        return None
    if not new and not steps:
        skipped.append(f"{product['id']}/{channel['id']}: nothing usable on Windows")
        return None
    links = channel.get("links") or {}
    product_links = product.get("links") or {}
    # Proof: the product's own programs sending to destinations the knowledge base calls reporting.
    own_programs = [_exe(name) for name in product.get("executable_name") or []
                    if _owns(product["id"], shared.get("exe:" + name.lower(), {product["id"]}))]
    expect = {"reporting_from": {"processes": own_programs}} if own_programs and new else {}
    return {
        "expect": expect,
        "id": f"toptout.{product['id']}.{channel['id']}",
        "title": f"{product['name']}: {channel['name']}",
        "group": f"{product.get('category_name', 'Other')} (from toptout)",
        "explain": channel.get("description") or product.get("description") or "",
        "source": links.get("main") or product_links.get("telemetry") or product_links.get("main") or SOURCE,
        "checks": new, "steps": steps, "detect": _detect(product, new, shared),
        "note": "Imported from the toptout community list. Check the exact change before applying it.",
    }


def load(covered: set) -> list:
    """Switches for every usable channel in the downloaded data. Empty when nothing is downloaded."""
    from . import build_switch

    skipped.clear()
    target = folder()
    if not target.is_dir():
        return []
    products = []
    for path in sorted(target.glob("*.json")):
        try:
            product = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            skipped.append(f"{path.name}: unreadable ({error})")
            continue
        if isinstance(product, dict) and isinstance(product.get("telemetry"), list) and product.get("id"):
            products.append(product)
    shared = _shared(products)
    switches = []
    for product in products:
        for channel in product.get("telemetry") or []:
            # Downloaded data must never stop the catalogue from loading: skip what does not fit.
            try:
                entry = _channel_switch(product, channel, covered, shared)
                if entry is not None:
                    switches.append(build_switch(entry, entry["group"], origin="toptout"))
            except Exception as error:  # noqa: BLE001
                skipped.append(f"{product['id']}/{channel.get('id')}: unusable ({type(error).__name__}: {error})")
    return switches


if __name__ == "__main__":
    print(fetch())
    from . import load_catalogue

    load_catalogue.cache_clear()
    imported = [item for item in load_catalogue().values() if item.origin == "toptout"]
    print(f"{len(imported)} switches imported, {len(skipped)} channels skipped")
