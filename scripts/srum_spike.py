"""Elevated spike: can the locked SRUDB.dat be copied and read on this PC?

Run elevated:  python scripts/srum_spike.py <output_dir>
Writes <output_dir>/result.json. Tries each copy method and records what worked.
"""

from __future__ import annotations

import ctypes
import json
import shutil
import subprocess
import sys
import time
import traceback
from pathlib import Path

SRC = Path(r"C:\Windows\System32\sru\SRUDB.dat")
MAX_RECORDS = 20000
MAX_SECONDS = 25


def attempt(name: str, fn, result: dict) -> bool:
    started = time.time()
    try:
        detail = fn()
        result["methods"][name] = {"ok": True, "seconds": round(time.time() - started, 2), "detail": detail}
        return True
    except Exception as exc:  # noqa: BLE001 - a spike records every failure
        result["methods"][name] = {"ok": False, "seconds": round(time.time() - started, 2), "error": repr(exc)}
        return False


def plain_copy(dst: Path):
    shutil.copyfile(SRC, dst)
    return f"{dst.stat().st_size} bytes"


def esentutl_copy(dst: Path):
    if dst.exists():
        dst.unlink()
    proc = subprocess.run(
        ["esentutl.exe", "/y", str(SRC), "/vss", "/d", str(dst)],
        capture_output=True, text=True, timeout=240,
    )
    if proc.returncode != 0 or not dst.exists():
        raise RuntimeError(f"exit {proc.returncode}: {(proc.stdout or '')[-400:]} {(proc.stderr or '')[-200:]}")
    return f"{dst.stat().st_size} bytes"


def shadow_copy(dst: Path):
    create = (
        "$r = Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName Create "
        "-Arguments @{Volume='C:\\'; Context='ClientAccessible'}; "
        "$s = Get-CimInstance Win32_ShadowCopy | Where-Object ID -eq $r.ShadowID; "
        "Write-Output ($r.ReturnValue.ToString() + '|' + $r.ShadowID + '|' + $s.DeviceObject)"
    )
    proc = subprocess.run(["powershell", "-NoProfile", "-Command", create], capture_output=True, text=True, timeout=240)
    code, shadow_id, device = (proc.stdout.strip().split("|") + ["", ""])[:3]
    if code != "0" or not device:
        raise RuntimeError(f"shadow create failed: {proc.stdout.strip()} {proc.stderr.strip()[-300:]}")
    try:
        shutil.copyfile(device + r"\Windows\System32\sru\SRUDB.dat", dst)
    finally:
        subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             f"Get-CimInstance Win32_ShadowCopy | Where-Object ID -eq '{shadow_id}' | Remove-CimInstance"],
            capture_output=True, text=True, timeout=120,
        )
    return f"{dst.stat().st_size} bytes via {device}"


def read_db(path: Path) -> dict:
    from dissect.esedb.tools.sru import NAME_TO_GUID_MAP, SRU

    info: dict = {}
    started = time.time()
    with path.open("rb") as fh:
        sru = SRU(fh)
        info["open_seconds"] = round(time.time() - started, 2)
        info["id_map_entries"] = len(sru.id_map)
        info["tables"] = [t.name for t in sru.esedb.tables()]
        for friendly in ("application", "network_data", "application_timeline"):
            table = sru.get_table(table_name=friendly)
            if table is None:
                info[friendly] = "table missing"
                continue
            t0 = time.time()
            count = 0
            first = last = None
            sample = None
            truncated = False
            for entry in sru.get_table_entries(table=table):
                count += 1
                ts = entry["TimeStamp"]
                if ts is not None:
                    first = ts if first is None or ts < first else first
                    last = ts if last is None or ts > last else last
                if sample is None:
                    sample = {c: str(entry[c])[:160] for c in table.column_names}
                if count >= MAX_RECORDS or time.time() - t0 > MAX_SECONDS:
                    truncated = True
                    break
            info[friendly] = {
                "guid": NAME_TO_GUID_MAP[friendly],
                "columns": list(table.column_names),
                "records_read": count,
                "truncated": truncated,
                "seconds": round(time.time() - t0, 2),
                "first_timestamp": str(first),
                "last_timestamp": str(last),
                "sample": sample,
            }
    return info


def main() -> None:
    out_dir = Path(sys.argv[1])
    out_dir.mkdir(parents=True, exist_ok=True)
    result: dict = {
        "elevated": bool(ctypes.windll.shell32.IsUserAnAdmin()),
        "source_size": None,
        "methods": {},
    }
    try:
        result["source_size"] = SRC.stat().st_size
    except Exception as exc:  # noqa: BLE001
        result["source_size"] = repr(exc)

    working: Path | None = None
    plain = out_dir / "SRUDB_plain.dat"
    vss = out_dir / "SRUDB_esentutl.dat"
    shadow = out_dir / "SRUDB_shadow.dat"
    if attempt("plain_copy", lambda: plain_copy(plain), result):
        working = plain
    if attempt("esentutl_vss", lambda: esentutl_copy(vss), result):
        working = working or vss
    if working is None and attempt("wmi_shadow_copy", lambda: shadow_copy(shadow), result):
        working = shadow

    if working is not None:
        result["read_from"] = working.name
        try:
            result["read"] = read_db(working)
        except Exception:  # noqa: BLE001
            result["read_error"] = traceback.format_exc()[-2000:]

    (out_dir / "result.json").write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")


if __name__ == "__main__":
    try:
        main()
    except Exception:  # noqa: BLE001
        Path(sys.argv[1]).mkdir(parents=True, exist_ok=True)
        (Path(sys.argv[1]) / "result.json").write_text(json.dumps({"fatal": traceback.format_exc()}), encoding="utf-8")
