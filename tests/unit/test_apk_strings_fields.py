"""apk.strings descriptions must name the fields the parser actually returns."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

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
    assert "name_filter" in doc


def test_apk_strings_name_filter_reaches_a_string_past_the_collect_cap(
    monkeypatch: Any,
) -> None:
    """Searching a >5000-string app for a fragment must reach it regardless of
    scan order; without filtering during the scan it is stranded past the cap.

    Measured: cap lowered to 3, target 's24' sits after 25 strings -> unfiltered
    it is not collected (scan_capped True), filtered on 's24' it is the only row.
    """
    from headless_re_mcp.backends.apk import client as mod

    monkeypatch.setattr(mod, "_MAX_STRINGS_COLLECT", 3)
    client = ApkClient()
    client._parsed = lambda _path: _FakeParsed()  # type: ignore[method-assign]
    unfiltered = client.strings(Path("dummy.apk"), offset=0, limit=2000)
    assert "s24" not in unfiltered["strings"]
    assert unfiltered["scan_capped"] is True
    filtered = client.strings(Path("dummy.apk"), offset=0, limit=2000, name_filter="s24")
    assert filtered["strings"] == ["s24"]
    assert filtered["total"] == 1
    assert filtered["scan_capped"] is False
