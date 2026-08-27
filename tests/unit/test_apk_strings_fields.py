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
        self._values = values

    def get_strings(self) -> list[_FakeString]:
        values = self._values if self._values is not None else [f"s{i}" for i in range(25)]
        return [_FakeString(value) for value in values]


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


def test_apk_strings_contains_filters_to_matches() -> None:
    """A substring filter must narrow the DEX strings, case-insensitively.

    Hunting a URL or key in a real app means not paging every constant. Assert
    contains keeps only the matching strings, folds case, and reports
    filtered/query so a small result is read as "few matches", not "few strings".
    """
    values = [
        "https://api.example.com/v1/login",
        "https://cdn.other.com/app.js",
        "AES/CBC/PKCS5Padding",
        "GET",
        "API_KEY",
    ]
    client = ApkClient()
    client._parsed = lambda _path: _FakeParsed(values)  # type: ignore[method-assign]

    hits = client.strings(Path("dummy.apk"), contains="EXAMPLE.com")
    assert hits["strings"] == ["https://api.example.com/v1/login"]
    assert hits["filtered"] is True
    assert hits["query"] == "EXAMPLE.com"
    assert hits["total"] == 1

    # An unfiltered call carries neither key, so a plain listing is not mistaken
    # for a filtered one.
    plain = client.strings(Path("dummy.apk"))
    assert "filtered" not in plain
    assert "query" not in plain
    assert plain["total"] == len(values)


def test_apk_strings_contains_finds_a_match_past_the_collection_cap() -> None:
    """The filter is applied during the scan, so the cap bounds matches.

    An unfiltered scan stops at the 5000-distinct cap and never sees a string
    beyond it. Bury one secret after more than that many non-matching strings
    and assert a contains filter still finds it -- proving the cap bounds
    matches, not scan position (an after-the-fact filter would miss it).
    """
    from headless_re_mcp.backends.apk.client import _MAX_STRINGS_COLLECT

    values = [f"nomatch-{index}" for index in range(_MAX_STRINGS_COLLECT + 1000)]
    values.append("buried://SECRET_TOKEN/xyz")
    client = ApkClient()
    client._parsed = lambda _path: _FakeParsed(values)  # type: ignore[method-assign]

    hits = client.strings(Path("dummy.apk"), contains="secret_token")
    assert hits["strings"] == ["buried://SECRET_TOKEN/xyz"]
    assert hits["total"] == 1
    assert hits["scan_capped"] is False

    doc = _tool_docstring("apk.strings")
    assert "contains" in doc
    assert "filtered" in doc
    assert "query" in doc
