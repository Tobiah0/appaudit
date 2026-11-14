"""Make captured request content safe to keep and show.

Content capture exists to answer "what kind of thing does this app send". It must not become a
store of passwords and sign-in tokens, so those are replaced before anything is written to disk.
"""

from __future__ import annotations

import re
import zlib

MAX_TEXT = 4000
_SECRET_HEADER = re.compile(r"auth|cookie|token|secret|key|session|signature|credential|password|sas", re.IGNORECASE)
_SECRET_FIELD = re.compile(
    r'("(?:[A-Za-z_\-]*(?:token|secret|password|passwd|authorization|api_?key|apikey|credential|cookie)[A-Za-z_\-]*)"'
    r'\s*:\s*")([^"]{4,})(")', re.IGNORECASE)
_SECRET_FORM = re.compile(
    r"((?:^|[&\s])[A-Za-z_\-]*(?:token|secret|password|passwd|api_?key|apikey|code|assertion)[A-Za-z_\-]*=)([^&\s]{4,})",
    re.IGNORECASE)
_BEARER = re.compile(r"\b(Bearer|Basic|Negotiate|NTLM)\s+[A-Za-z0-9+/_\-.=]{8,}")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*")


def hidden(value: str) -> str:
    return f"[hidden, {len(value)} characters]"


def headers(raw: bytes) -> str:
    """Header block as text, with the values of sign-in and cookie headers replaced."""
    lines = []
    for index, line in enumerate(raw.decode("latin-1", "replace").replace("\r\n", "\n").split("\n")):
        line = line.rstrip("\x00")
        if not line:
            continue
        name, colon, value = line.partition(":")
        if index and colon and _SECRET_HEADER.search(name):
            line = f"{name}: {hidden(value.strip())}"
        elif index == 0 and "?" in line:                 # request line: the query string often carries tokens
            parts = line.split(" ")
            if len(parts) >= 2:
                parts[1] = parts[1].split("?", 1)[0] + "?[query hidden]"
                line = " ".join(parts)
        lines.append(_JWT.sub("[hidden token]", _BEARER.sub(lambda m: f"{m.group(1)} [hidden]", line)))
    return "\n".join(lines)[:MAX_TEXT]


def _inflate(raw: bytes) -> bytes | None:
    """The start of a gzip or deflate stream can be read even when the rest was not captured."""
    for wbits in (47, -15):
        try:
            out = zlib.decompressobj(wbits).decompress(raw, MAX_TEXT * 4)
        except zlib.error:
            continue
        if out:
            return out
    return None


def _printable(text: str) -> float:
    if not text:
        return 0.0
    return sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t") / len(text)


def body(raw: bytes, encoding: str = "") -> str:
    """Request body as text when it is text; otherwise a short description of what it is."""
    if not raw:
        return ""
    data = raw
    if "gzip" in encoding or "deflate" in encoding or raw[:2] == b"\x1f\x8b":
        data = _inflate(raw) or raw
    text = data.decode("utf-8", "replace")
    if _printable(text) < 0.9:
        packed = "compressed or binary" if data is raw else "binary"
        return f"[{len(raw)} bytes of {packed} data; not readable as text]"
    text = _SECRET_FIELD.sub(lambda m: m.group(1) + hidden(m.group(2)) + m.group(3), text)
    text = _SECRET_FORM.sub(lambda m: m.group(1) + hidden(m.group(2)), text)
    text = _JWT.sub("[hidden token]", _BEARER.sub(lambda m: f"{m.group(1)} [hidden]", text))
    return text[:MAX_TEXT]


def header_value(block: str, name: str) -> str:
    for line in block.split("\n")[1:]:
        key, colon, value = line.partition(":")
        if colon and key.strip().lower() == name:
            return value.strip()
    return ""
