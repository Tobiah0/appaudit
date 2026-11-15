"""Config-file edits change one setting and leave every other byte of the file as it was."""

import json

import pytest

from appaudit.switches import configfile as cf

VSCODE = """{
\t// Editor
\t"editor.fontSize": 14,
\t"files.autoSave": "afterDelay", // save often
\t/* block
\t   comment */
\t"workbench.colorTheme": "Default Dark+",
}
"""


def strict(text: str):
    """The whole document as Python values, read with the module's own parser."""
    return cf._parse(text).value


def test_get_reads_through_comments_and_trailing_commas():
    assert cf.json_get(VSCODE, ["files.autoSave"]) == "afterDelay"
    assert cf.json_get(VSCODE, ["telemetry.telemetryLevel"]) is None
    assert cf.json_get("", ["a"]) is None


def test_set_existing_value_changes_only_that_value():
    out = cf.json_set(VSCODE, ["editor.fontSize"], 16)
    assert out == VSCODE.replace('"editor.fontSize": 14', '"editor.fontSize": 16')


def test_insert_into_file_with_trailing_comma_keeps_style_and_comments():
    out = cf.json_set(VSCODE, ["telemetry.telemetryLevel"], "off")
    assert cf.json_get(out, ["telemetry.telemetryLevel"]) == "off"
    assert '\t"telemetry.telemetryLevel": "off",\n}' in out          # tab indent, trailing comma kept
    assert out.replace('\t"telemetry.telemetryLevel": "off",\n', "") == VSCODE
    assert {k: v for k, v in strict(out).items() if k != "telemetry.telemetryLevel"} == strict(VSCODE)


def test_insert_after_line_comment_puts_comma_before_the_comment():
    text = '{\n    "a": 1 // one\n}\n'
    out = cf.json_set(text, ["b"], True)
    assert out == '{\n    "a": 1, // one\n    "b": true\n}\n'


def test_insert_keeps_windows_line_endings():
    text = '{\r\n  "a": 1\r\n}\r\n'
    out = cf.json_set(text, ["b"], "x")
    assert out == '{\r\n  "a": 1,\r\n  "b": "x"\r\n}\r\n'


def test_insert_into_empty_object_and_empty_file():
    assert json.loads(cf.json_set("{}", ["a"], False)) == {"a": False}
    assert json.loads(cf.json_set("", ["a"], False)) == {"a": False}
    assert json.loads(cf.json_set("  \n", ["a", "b"], 1)) == {"a": {"b": 1}}


def test_insert_into_one_line_object_stays_on_one_line():
    assert cf.json_set('{"a": 1}', ["b"], 2) == '{"a": 1, "b": 2}'


def test_nested_keys_create_missing_parents():
    text = '{\n  "telemetry": {\n    "x": 1\n  }\n}\n'
    out = cf.json_set(text, ["telemetry", "enabled"], False)
    assert json.loads(out) == {"telemetry": {"x": 1, "enabled": False}}
    out = cf.json_set('{\n  "a": 1\n}\n', ["privacy", "analytics", "enabled"], False)
    assert json.loads(out) == {"a": 1, "privacy": {"analytics": {"enabled": False}}}


def test_refuses_to_descend_into_a_non_object():
    with pytest.raises(cf.ConfigError):
        cf.json_set('{"telemetry": true}', ["telemetry", "enabled"], False)


@pytest.mark.parametrize("bad", ['{"a": 1', '{"a" 1}', '[1, 2]', '{"a": 1} trailing', '{"a": /* open'])
def test_unreadable_files_raise_and_are_not_changed(bad):
    with pytest.raises(cf.ConfigError):
        cf.json_set(bad, ["b"], 1)


def test_strings_containing_braces_and_comment_markers_are_not_confused():
    text = '{\n  "url": "http://x/{y}//z", "c": "/* not a comment */"\n}'
    out = cf.json_set(text, ["d"], 1)
    assert cf._parse(out).value == {"url": "http://x/{y}//z", "c": "/* not a comment */", "d": 1}


def test_last_duplicate_key_wins_for_read_and_write():
    text = '{"a": 1, "a": 2}'
    assert cf.json_get(text, ["a"]) == 2
    assert cf.json_set(text, ["a"], 3) == '{"a": 1, "a": 3}'


@pytest.mark.parametrize("text, expected", [
    ('{\n  "a": 1,\n  "b": 2\n}\n', '{\n  "b": 2\n}\n'),                 # first member
    ('{\n  "b": 2,\n  "a": 1\n}\n', '{\n  "b": 2\n}\n'),                 # last member
    ('{\n  "a": 1\n}\n', '{\n}\n'),                                       # only member
    ('{"b": 2, "a": 1}', '{"b": 2}'),
    ('{\n  "a": 1, // note\n  "b": 2\n}\n', '{\n  // note\n  "b": 2\n}\n'),
])
def test_delete_removes_member_and_its_comma(text, expected):
    out = cf.json_delete(text, ["a"])
    assert out == expected
    assert cf.json_get(out, ["a"]) is None


def test_set_then_delete_round_trips_to_the_original():
    keys = ["telemetry.telemetryLevel"]
    assert cf.json_delete(cf.json_set(VSCODE, keys, "off"), keys) == VSCODE
    # A parent created for a nested key stays behind, empty. Undo restores the backup instead
    # when the file has not changed since the switch wrote it.
    out = cf.json_delete(cf.json_set(VSCODE, ["new", "nested"], "off"), ["new", "nested"])
    assert cf._parse(out).value == {**cf._parse(VSCODE).value, "new": {}}


def test_bom_is_tolerated():
    assert cf.json_get("﻿{\"a\": 1}", ["a"]) == 1


# --- INI ------------------------------------------------------------------------------------

INI = "; settings\n[General]\nTheme = dark\nSendUsage=1\n\n[Other]\nx=1\n"


def test_ini_get_and_replace_keeps_spacing():
    assert cf.ini_get(INI, "General", "sendusage") == "1"
    out = cf.ini_set(INI, "General", "SendUsage", 0)
    assert out == INI.replace("SendUsage=1", "SendUsage=0")
    assert cf.ini_set(INI, "General", "Theme", "light") == INI.replace("Theme = dark", "Theme = light")


def test_ini_insert_in_section_section_creation_and_sectionless():
    out = cf.ini_set(INI, "General", "Crash", "off")
    assert "SendUsage=1\nCrash=off\n\n[Other]" in out
    out = cf.ini_set(INI, "Privacy", "Analytics", False)
    assert out.endswith("x=1\n\n[Privacy]\nAnalytics=false\n")
    assert cf.ini_set("a=1\n", None, "b", 2) == "a=1\nb=2\n"
    assert cf.ini_get("a=1\nb = 2\n", None, "b") == "2"


def test_ini_delete():
    assert cf.ini_delete(INI, "General", "SendUsage") == INI.replace("SendUsage=1\n", "")
    assert cf.ini_delete(INI, "General", "Missing") == INI


def test_entry_point_dispatches_by_format():
    check = {"format": "json", "keys": ["telemetry.telemetryLevel"]}
    assert cf.read(None, check) is None
    assert cf.read(cf.edit(None, check, "off"), check) == "off"
    assert cf.read(cf.edit(VSCODE, check, None), check) is None
    ini = {"format": "ini", "section": "General", "key": "SendUsage"}
    assert cf.read(cf.edit(INI, ini, "0"), ini) == "0"
