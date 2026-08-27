"""apk.strings descriptions must name the fields the parser actually returns."""

from __future__ import annotations

import ast
from pathlib import Path

from headless_re_mcp.backends.apk.client import _MAX_STRING_LEN, ApkClient
from headless_re_mcp.tools.apk import build_apk_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_apk_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            for keyword in decorator.keywords:
                if (
                    keyword.arg == "name"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value == name
                ):
                    return ast.get_docstring(node) or ""
    return ""


class _FakeString:
    def __init__(self, value: str) -> None:
        self._value = value

    def get_value(self) -> str:
        return self._value


class _FakeParsed:
    def __init__(self) -> None:
        self.analysis = self

    def get_strings(self) -> list[_FakeString]:
        return [_FakeString(f"s{index}") for index in range(25)]


def test_apk_strings_puts_the_page_in_strings_not_constants() -> None:
    """The catalog said pagination and never named the payload.

    Measured: 25 strings, limit 10 -> count 10, total 25, has_more True,
    field is strings not items or constants. Looking for those after a
    successful call reads as no DEX strings, and a full page with no
    has_more reads as the whole table.
    """
    client = ApkClient()
    client._parsed = lambda _path: _FakeParsed()  # type: ignore[method-assign]
    payload = client.strings(Path("dummy.apk"), offset=0, limit=10)
    assert "items" not in payload
    assert "constants" not in payload
    assert "values" not in payload
    assert payload["count"] == 10
    assert payload["total"] == 25
    assert len(payload["strings"]) == 10
    assert payload["has_more"] is True
    doc = _tool_docstring("apk.strings")
    assert "Answers with strings" in doc
    assert "has_more" in doc
    assert "values_truncated" in doc


def test_apk_strings_flags_a_value_cut_at_the_per_string_cap() -> None:
    """A constant longer than the cap is returned as a prefix; say so.

    A returned string cut at _MAX_STRING_LEN looks whole, and dedupe keys on
    that cut value, so two constants sharing the first _MAX_STRING_LEN chars
    collapse into one row -- a distinct string silently gone. values_truncated
    (with max_string_len) names it so a prefix is not read as the whole value.
    """
    long_value = "A" * (_MAX_STRING_LEN + 50)

    class _LongParsed:
        def __init__(self) -> None:
            self.analysis = self

        def get_strings(self) -> list[_FakeString]:
            return [_FakeString("short"), _FakeString(long_value)]

    client = ApkClient()
    client._parsed = lambda _path: _LongParsed()  # type: ignore[method-assign]
    payload = client.strings(Path("dummy.apk"), offset=0, limit=10)

    assert payload["values_truncated"] is True
    assert payload["max_string_len"] == _MAX_STRING_LEN
    assert all(len(value) <= _MAX_STRING_LEN for value in payload["strings"])


def test_apk_strings_short_values_carry_no_truncation_flag() -> None:
    """A table of short strings stays clean: no values_truncated field."""
    client = ApkClient()
    client._parsed = lambda _path: _FakeParsed()  # type: ignore[method-assign]
    payload = client.strings(Path("dummy.apk"), offset=0, limit=10)

    assert "values_truncated" not in payload
    assert "max_string_len" not in payload
