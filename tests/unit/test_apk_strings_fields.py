"""apk.strings descriptions must name the fields the parser actually returns."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apk.client import ApkClient, ApkError
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


class _NoisyParsed:
    """Short DEX noise up front, one long payload string behind it."""

    def __init__(self) -> None:
        self.analysis = self

    def get_strings(self) -> list[_FakeString]:
        noise = [_FakeString(v) for v in ("I", "V", "a", "b", "ok")]
        return [*noise, _FakeString("https://c2.example.com/collect")]


def test_apk_strings_min_len_drops_short_noise() -> None:
    """A length floor is the strings(1) idiom -- short pool entries go away."""
    client = ApkClient()
    client._parsed = lambda _path: _NoisyParsed()  # type: ignore[method-assign]
    payload = client.strings(Path("dummy.apk"), offset=0, limit=2000, min_len=6)
    assert payload["strings"] == ["https://c2.example.com/collect"]
    assert payload["total"] == 1
    doc = _tool_docstring("apk.strings")
    assert "min_len" in doc


def test_apk_strings_min_len_reaches_a_long_string_past_the_collect_cap(
    monkeypatch: Any,
) -> None:
    """Applying the floor during the scan (not after) is what makes a long
    string reachable when short noise would otherwise fill the collect cap."""
    from headless_re_mcp.backends.apk import client as mod

    monkeypatch.setattr(mod, "_MAX_STRINGS_COLLECT", 3)
    client = ApkClient()
    client._parsed = lambda _path: _NoisyParsed()  # type: ignore[method-assign]
    unfiltered = client.strings(Path("dummy.apk"), offset=0, limit=2000)
    assert "https://c2.example.com/collect" not in unfiltered["strings"]
    assert unfiltered["scan_capped"] is True
    floored = client.strings(Path("dummy.apk"), offset=0, limit=2000, min_len=6)
    assert floored["strings"] == ["https://c2.example.com/collect"]
    assert floored["scan_capped"] is False


def test_apk_strings_min_len_and_name_filter_combine() -> None:
    """Both narrowings must pass: a long string not matching the fragment is out."""
    client = ApkClient()
    client._parsed = lambda _path: _NoisyParsed()  # type: ignore[method-assign]
    payload = client.strings(
        Path("dummy.apk"), offset=0, limit=2000, min_len=6, name_filter="c2.example"
    )
    assert payload["strings"] == ["https://c2.example.com/collect"]
    none_match = client.strings(
        Path("dummy.apk"), offset=0, limit=2000, min_len=6, name_filter="nomatch"
    )
    assert none_match["strings"] == []
    assert none_match["total"] == 0


class _XrefMethod:
    def __init__(self, class_name: str, name: str) -> None:
        self.class_name = class_name
        self.name = name


class _XrefString:
    def __init__(self, value: str, methods: list[_XrefMethod]) -> None:
        self._value = value
        self._methods = methods

    def get_value(self) -> str:
        return self._value

    def get_xref_from(self, with_offset: bool = False) -> list[tuple[object, _XrefMethod]]:
        return [(object(), method) for method in self._methods]


class _XrefParsed:
    def __init__(self, strings: list[_XrefString]) -> None:
        self.analysis = self
        self._strings = strings

    def get_strings(self) -> list[_XrefString]:
        return self._strings


def test_apk_string_xrefs_lists_the_referencing_methods() -> None:
    """The companion to apk.strings: where is this constant used."""
    parsed = _XrefParsed(
        [
            _XrefString(
                "https://c2.example.com/collect",
                [
                    _XrefMethod("Lcom/evil/Net;", "beacon"),
                    _XrefMethod("Lcom/evil/Net;", "exfil"),
                ],
            )
        ]
    )
    client = ApkClient()
    client._parsed = lambda _path: parsed  # type: ignore[method-assign]
    payload = client.string_xrefs(Path("dummy.apk"), "c2.example.com")
    assert payload["matched_strings"] == 1
    assert payload["total"] == 2
    assert payload["callers"] == [
        {"class": "Lcom/evil/Net;", "method": "beacon", "string": "https://c2.example.com/collect"},
        {"class": "Lcom/evil/Net;", "method": "exfil", "string": "https://c2.example.com/collect"},
    ]
    doc = _tool_docstring("apk.string_xrefs")
    assert "matched_strings" in doc


def test_apk_string_xrefs_requires_a_value() -> None:
    """An empty needle would match the whole pool; refuse it up front."""
    client = ApkClient()
    client._parsed = lambda _path: _XrefParsed([])  # type: ignore[method-assign]
    with pytest.raises(ApkError) as excinfo:
        client.string_xrefs(Path("dummy.apk"), "   ")
    assert excinfo.value.code == "invalid_params"


def test_apk_string_xrefs_substring_hits_several_strings_and_echoes_each() -> None:
    """A fragment can hit several constants; each caller row keeps its own
    string so the results stay disambiguable."""
    parsed = _XrefParsed(
        [
            _XrefString("Bearer token A", [_XrefMethod("La;", "one")]),
            _XrefString("refresh token B", [_XrefMethod("Lb;", "two")]),
        ]
    )
    client = ApkClient()
    client._parsed = lambda _path: parsed  # type: ignore[method-assign]
    payload = client.string_xrefs(Path("dummy.apk"), "token")
    assert payload["matched_strings"] == 2
    strings = {row["string"] for row in payload["callers"]}
    assert strings == {"Bearer token A", "refresh token B"}


def test_apk_string_xrefs_unreferenced_string_is_empty_not_an_error() -> None:
    """A dead constant (or one reached only via reflection) has no callers."""
    parsed = _XrefParsed([_XrefString("https://dead.example/x", [])])
    client = ApkClient()
    client._parsed = lambda _path: parsed  # type: ignore[method-assign]
    payload = client.string_xrefs(Path("dummy.apk"), "dead.example")
    assert payload["matched_strings"] == 1
    assert payload["callers"] == []
    assert payload["total"] == 0
