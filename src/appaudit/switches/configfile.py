"""Read and change one setting in an app's own config file, leaving everything else as it was.

Apps' JSON files often carry comments and trailing commas (VS Code's settings.json does), and
people format them by hand. Loading and re-saving the file would lose all of that, so these
functions edit the text itself: they replace, insert or remove only the one member or line, and
every other byte stays where it was.

JSON: the setting is named by a list of keys from the top object, e.g. ["telemetry.telemetryLevel"]
(keys may contain dots). INI: by an optional [section] and a key; a key before any section header
is section None, which also covers plain "key=value" files.

A file that cannot be read safely raises ConfigError and is left untouched.
"""

from __future__ import annotations

import json
import re

INDENT_FALLBACK = "    "


class ConfigError(ValueError):
    """The file is not in a shape this module can change safely."""


# --- JSON with comments ---------------------------------------------------------------------

class _Node:
    __slots__ = ("kind", "start", "end", "value", "members")

    def __init__(self, kind: str, start: int):
        self.kind, self.start, self.end, self.value = kind, start, start, None
        self.members: list[tuple[str, int, _Node]] = []      # (key, key_start, value) for objects


class _Parser:
    _NUMBER = re.compile(r"-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?")
    _STRING = re.compile(r'"(?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"')

    def __init__(self, text: str):
        self.text = text

    def skip(self, i: int) -> int:
        """Past whitespace and comments."""
        text = self.text
        while i < len(text):
            if text[i] in " \t\r\n﻿":
                i += 1
            elif text.startswith("//", i):
                end = text.find("\n", i)
                i = len(text) if end < 0 else end
            elif text.startswith("/*", i):
                end = text.find("*/", i + 2)
                if end < 0:
                    raise ConfigError("unterminated comment")
                i = end + 2
            else:
                break
        return i

    def value(self, i: int) -> _Node:
        i = self.skip(i)
        if i >= len(self.text):
            raise ConfigError("unexpected end of file")
        char = self.text[i]
        if char == "{":
            return self._object(i)
        if char == "[":
            return self._array(i)
        if char == '"':
            match = self._STRING.match(self.text, i)
            if not match:
                raise ConfigError(f"bad string at {i}")
            node = _Node("scalar", i)
            node.end, node.value = match.end(), json.loads(match.group())
            return node
        for word, value in (("true", True), ("false", False), ("null", None)):
            if self.text.startswith(word, i):
                node = _Node("scalar", i)
                node.end, node.value = i + len(word), value
                return node
        match = self._NUMBER.match(self.text, i)
        if match:
            node = _Node("scalar", i)
            node.end, node.value = match.end(), json.loads(match.group())
            return node
        raise ConfigError(f"unexpected {char!r} at {i}")

    def _object(self, i: int) -> _Node:
        node = _Node("object", i)
        node.value = {}
        i = self.skip(i + 1)
        while True:
            if i >= len(self.text):
                raise ConfigError("unterminated object")
            if self.text[i] == "}":
                node.end = i + 1
                return node
            match = self._STRING.match(self.text, i)
            if not match:
                raise ConfigError(f"expected a key at {i}")
            key, key_start = json.loads(match.group()), i
            i = self.skip(match.end())
            if i >= len(self.text) or self.text[i] != ":":
                raise ConfigError(f"expected ':' at {i}")
            child = self.value(i + 1)
            node.members.append((key, key_start, child))
            node.value[key] = child.value
            i = self.skip(child.end)
            if i < len(self.text) and self.text[i] == ",":
                i = self.skip(i + 1)
            elif i < len(self.text) and self.text[i] != "}":
                raise ConfigError(f"expected ',' or '}}' at {i}")

    def _array(self, i: int) -> _Node:
        node = _Node("array", i)
        node.value = []
        i = self.skip(i + 1)
        while True:
            if i >= len(self.text):
                raise ConfigError("unterminated array")
            if self.text[i] == "]":
                node.end = i + 1
                return node
            child = self.value(i)
            node.value.append(child.value)
            i = self.skip(child.end)
            if i < len(self.text) and self.text[i] == ",":
                i = self.skip(i + 1)
            elif i < len(self.text) and self.text[i] != "]":
                raise ConfigError(f"expected ',' or ']' at {i}")

    def document(self) -> _Node:
        root = self.value(0)
        if self.skip(root.end) != len(self.text):
            raise ConfigError("text after the end of the document")
        return root


def _parse(text: str) -> _Node | None:
    """The top object, or None for an empty file."""
    parser = _Parser(text)
    if parser.skip(0) >= len(text):
        return None
    root = parser.document()
    if root.kind != "object":
        raise ConfigError("the file does not hold an object at the top")
    return root


def _member(node: _Node, key: str) -> tuple[int, _Node] | None:
    found = None
    for name, key_start, child in node.members:          # the last duplicate wins, as when apps read it
        if name == key:
            found = (key_start, child)
    return found


def json_get(text: str, keys: list[str]):
    """The value at `keys`, or None when the file, a parent or the key is missing."""
    node = _parse(text)
    for key in keys:
        if node is None or node.kind != "object":
            return None
        found = _member(node, key)
        node = found[1] if found else None
    return None if node is None else node.value


def _newline(text: str) -> str:
    return "\r\n" if "\r\n" in text else "\n"


def _line_indent(text: str, position: int) -> str:
    start = text.rfind("\n", 0, position) + 1
    match = re.match(r"[ \t]*", text[start:position])
    return match.group() if match else ""


def _indent_unit(text: str) -> str:
    match = re.search(r"\n([ \t]+)\S", text)
    if not match:
        return INDENT_FALLBACK
    found = match.group(1)
    return "\t" if found.startswith("\t") else (found if len(found) <= 8 else INDENT_FALLBACK)


def _literal(keys: list[str], value, indent: str, unit: str, newline: str) -> str:
    """`"k": value`, with missing parent objects written out as nested objects."""
    head = json.dumps(keys[0])
    if len(keys) == 1:
        return f"{head}: {json.dumps(value, ensure_ascii=False)}"
    inner = _literal(keys[1:], value, indent + unit, unit, newline)
    return f"{head}: {{{newline}{indent}{unit}{inner}{newline}{indent}}}"


def _insert(text: str, node: _Node, keys: list[str], value) -> str:
    """Add a member to object `node`, matching the file's indentation and line endings."""
    newline, unit = _newline(text), _indent_unit(text)
    close = node.end - 1                                     # position of the closing brace
    base = _line_indent(text, node.start)

    if not node.members:
        inner = _literal(keys, value, base + unit, unit, newline)
        if not text[node.start + 1:close].strip():          # {} or { } or a blank multi-line object
            return f"{text[:node.start]}{{{newline}{base}{unit}{inner}{newline}{base}}}{text[node.end:]}"
        prefix = text[:close].rstrip(" \t")                 # only comments inside: add after them
        if not prefix.endswith("\n"):
            prefix += newline
        return f"{prefix}{base}{unit}{inner}{newline}{base}{text[close:]}"

    _key, key_start, last = node.members[-1]
    i = last.end
    while i < len(text) and text[i] in " \t":
        i += 1
    has_comma = i < len(text) and text[i] == ","

    if "\n" not in text[node.start:node.end]:               # a one-line object: stay on one line
        member = _literal(keys, value, "", "", " ")
        if has_comma:
            return f"{text[:i + 1]} {member}{text[i + 1:]}"
        return f"{text[:last.end]}, {member}{text[last.end:]}"

    indent = _line_indent(text, key_start)
    member = _literal(keys, value, indent, unit, newline)
    if has_comma:
        i += 1
        while i < len(text) and text[i] in " \t":
            i += 1
    if text.startswith("//", i):                           # a comment ends the last member's line
        end = text.find("\n", i)
        i = len(text) if end < 0 else end
    if i < len(text) and text[i] in "\r\n":
        line_end = i - 1 if text[i] == "\n" and i > 0 and text[i - 1] == "\r" else i
        updated = f"{text[:line_end]}{newline}{indent}{member}{',' if has_comma else ''}{text[line_end:]}"
        return updated if has_comma else f"{updated[:last.end]},{updated[last.end:]}"
    # Something else follows on the same line, usually the closing brace.
    if has_comma:
        return f"{text[:i]}{newline}{indent}{member},{text[i:]}"
    return f"{text[:last.end]},{newline}{indent}{member}{text[last.end:]}"


def json_set(text: str, keys: list[str], value) -> str:
    """The text with the value at `keys` set; missing parent objects are created."""
    if not keys:
        raise ConfigError("no key given")
    node = _parse(text)
    if node is None:
        newline = _newline(text) if text else "\n"
        return f"{{{newline}{INDENT_FALLBACK}{_literal(keys, value, INDENT_FALLBACK, INDENT_FALLBACK, newline)}{newline}}}{newline}"
    for depth, key in enumerate(keys):
        found = _member(node, key)
        if found is None:
            return _insert(text, node, keys[depth:], value)
        child = found[1]
        if depth == len(keys) - 1:
            return f"{text[:child.start]}{json.dumps(value, ensure_ascii=False)}{text[child.end:]}"
        if child.kind != "object":
            raise ConfigError(f"{key!r} is not an object in this file")
        node = child
    raise AssertionError("unreachable")


def json_delete(text: str, keys: list[str]) -> str:
    """The text without the member at `keys`. Unchanged when it is not there."""
    node = _parse(text)
    for key in keys[:-1]:
        found = _member(node, key) if node is not None and node.kind == "object" else None
        if found is None or found[1].kind != "object":
            return text
        node = found[1]
    if node is None:
        return text
    index = next((n for n in range(len(node.members) - 1, -1, -1) if node.members[n][0] == keys[-1]), None)
    if index is None:
        return text
    _key, key_start, child = node.members[index]
    parser = _Parser(text)
    after = parser.skip(child.end)
    if after < len(text) and text[after] == ",":            # a comma follows: remove member and comma
        end = after + 1
        line_start = text.rfind("\n", 0, key_start) + 1
        start = line_start if not text[line_start:key_start].strip() else key_start
        rest = re.match(r"[ \t]*(?://[^\n]*)?\r?\n", text[end:])
        if start == line_start and rest and "//" not in rest.group():
            end += rest.end()                               # the whole line goes
        elif start == line_start:                           # a comment stays, at the same indentation
            start = key_start
            end += len(re.match(r"[ \t]*", text[end:]).group())
        return text[:start] + text[end:]
    if index > 0:                                           # last member: remove the comma before it
        previous_end = node.members[index - 1][2].end
        comma = text.find(",", previous_end, key_start)
        return text[:comma] + text[child.end:] if comma >= 0 else text[:previous_end] + text[child.end:]
    line_start = text.rfind("\n", 0, key_start) + 1          # the only member
    start = line_start if not text[line_start:key_start].strip() else key_start
    end = child.end
    rest = re.match(r"[ \t]*\r?\n", text[end:])
    if start == line_start and rest:
        end += rest.end()
    return text[:start] + text[end:]


# --- INI and key=value files -------------------------------------------------------------------

_SECTION = re.compile(r"^\s*\[([^\]]+)\]\s*(?:[;#].*)?$")
_KEY = re.compile(r"^(\s*)([^=;#\[\s][^=]*?)(\s*=\s*)(.*?)(\s*)$")


def _ini_lines(text: str) -> list[str]:
    return text.splitlines(keepends=True)


def _ini_find(lines: list[str], section: str | None, key: str) -> tuple[int | None, int | None, int | None]:
    """(index of the key line, index of the section header, index of the last line in the section)."""
    current, header, last, found = None, None, None, None
    in_section = section is None
    if section is None:
        last = -1
    for index, line in enumerate(lines):
        match = _SECTION.match(line.rstrip("\r\n"))
        if match:
            current = match.group(1).strip()
            in_section = section is not None and current.lower() == section.lower()
            if in_section:
                header, last = index, index
            continue
        if not in_section:
            continue
        if line.strip():
            last = index
        key_match = _KEY.match(line.rstrip("\r\n"))
        if key_match and key_match.group(2).strip().lower() == key.lower():
            found = index
    return found, header, last


def ini_get(text: str, section: str | None, key: str):
    lines = _ini_lines(text)
    found, _header, _last = _ini_find(lines, section, key)
    if found is None:
        return None
    return _KEY.match(lines[found].rstrip("\r\n")).group(4)


def ini_set(text: str, section: str | None, key: str, value) -> str:
    value = _ini_value(value)
    newline = _newline(text)
    lines = _ini_lines(text)
    found, header, last = _ini_find(lines, section, key)
    if found is not None:
        line = lines[found]
        ending = line[len(line.rstrip("\r\n")):]
        match = _KEY.match(line.rstrip("\r\n"))
        lines[found] = f"{match.group(1)}{match.group(2)}{match.group(3)}{value}{ending}"
        return "".join(lines)
    entry = f"{key}={value}{newline}"
    if section is not None and header is None:
        prefix = "" if not text or text.endswith(("\n", "\r")) else newline
        gap = newline if text.strip() else ""
        return f"{text}{prefix}{gap}[{section}]{newline}{entry}"
    position = (last if last is not None else -1) + 1
    if position > 0 and not lines[position - 1].endswith(("\n", "\r")):
        lines[position - 1] += newline
    lines.insert(position, entry)
    return "".join(lines)


def ini_delete(text: str, section: str | None, key: str) -> str:
    lines = _ini_lines(text)
    found, _header, _last = _ini_find(lines, section, key)
    if found is None:
        return text
    del lines[found]
    return "".join(lines)


def _ini_value(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        raise ConfigError("an INI value cannot be empty; delete the key instead")
    text = str(value)
    if "\n" in text or "\r" in text:
        raise ConfigError("an INI value cannot span lines")
    return text


# --- one entry point for the switch engine ---------------------------------------------------

def read(text: str | None, check: dict):
    """The current value of a file check, None when the file or the setting is missing."""
    if text is None:
        return None
    if check["format"] == "json":
        return json_get(text, check["keys"])
    return ini_get(text, check.get("section"), check["key"])


def edit(text: str | None, check: dict, value) -> str:
    """The new text with the check's setting changed to `value` (None removes it)."""
    text = text or ""
    if check["format"] == "json":
        return json_delete(text, check["keys"]) if value is None else json_set(text, check["keys"], value)
    if value is None:
        return ini_delete(text, check.get("section"), check["key"])
    return ini_set(text, check.get("section"), check["key"], value)
