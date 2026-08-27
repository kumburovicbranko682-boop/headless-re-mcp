"""apk.strings descriptions must name the fields the parser actually returns."""

from __future__ import annotations

import ast
from pathlib import Path

from headless_re_mcp.backends.apk.client import ApkClient
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
    def __init__(self, values: list[str] | None = None) -> None:
        self.analysis = self
        self._values = values if values is not None else [f"s{index}" for index in range(25)]

    def get_strings(self) -> list[_FakeString]:
        return [_FakeString(value) for value in self._values]


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


def test_apk_strings_flags_a_value_cut_to_the_length_cap() -> None:
    """A string longer than the per-value cap must not read as the whole string.

    strings() cuts each value to _MAX_STRING_LEN before it lands in the set; a
    cut value used to be returned with no signal, so a caller read a 2000-char
    prefix as the complete constant. values_truncated says the page holds a cut
    value, and the note says the shown value is a prefix.
    """
    from headless_re_mcp.backends.apk import client as apk_client

    long_value = "A" * (apk_client._MAX_STRING_LEN + 500)
    client = ApkClient()
    client._parsed = lambda _path: _FakeParsed(["short", long_value])  # type: ignore[method-assign]
    payload = client.strings(Path("dummy.apk"), offset=0, limit=10)
    assert payload["values_truncated"] is True
    assert "prefix" in payload["note"]
    # The value is present but cut to the cap, never longer.
    cut = next(value for value in payload["strings"] if value.startswith("A"))
    assert len(cut) == apk_client._MAX_STRING_LEN


def test_apk_strings_does_not_flag_when_every_value_fits() -> None:
    client = ApkClient()
    client._parsed = lambda _path: _FakeParsed(["alpha", "beta", "gamma"])  # type: ignore[method-assign]
    payload = client.strings(Path("dummy.apk"), offset=0, limit=10)
    assert payload["values_truncated"] is False
    assert "note" not in payload
    assert payload["strings"] == ["alpha", "beta", "gamma"]
