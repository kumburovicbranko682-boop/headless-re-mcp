"""apk.string_search filters the DEX string pool by a case-insensitive fragment.

The fake parsed APK stands in for androguard's analysis.get_strings so the
substring filter, de-duplication, sorting, bounding, pagination and error path
are what actually get exercised.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import (
    _MAX_STRINGS_COLLECT,
    ApkClient,
    ApkError,
)
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
    def __init__(self, values: list[str]) -> None:
        self.analysis = self
        self._values = [_FakeString(v) for v in values]

    def get_strings(self) -> list[_FakeString]:
        return self._values


def _client(values: list[str]) -> ApkClient:
    client = ApkClient()
    client._parsed = lambda _path: _FakeParsed(values)  # type: ignore[method-assign]
    return client


def test_matches_substring_case_insensitively_deduped_sorted() -> None:
    """A fragment matches ignoring case, keeps the full string, dedupes, sorts.

    Measured: "pass" finds Password and reset_password but drops an unrelated
    string, duplicates collapse, and the field is strings with a query echo.
    """
    client = _client(
        [
            "Password required",
            "reset_password_url",
            "Password required",
            "unrelated value",
        ]
    )
    payload = client.search_strings(Path("dummy.apk"), "pass")
    assert payload["strings"] == ["Password required", "reset_password_url"]
    assert payload["query"] == "pass"
    assert payload["count"] == 2
    assert payload["total"] == 2
    assert payload["has_more"] is False
    assert payload["scan_capped"] is False


def test_paginates() -> None:
    """A full page reports has_more with a stable window."""
    values = [f"token_{i:03d}_value" for i in range(25)]
    client = _client(values)
    first = client.search_strings(Path("dummy.apk"), "token", offset=0, limit=10)
    assert first["count"] == 10
    assert first["total"] == 25
    assert first["has_more"] is True
    second = client.search_strings(Path("dummy.apk"), "token", offset=10, limit=10)
    assert second["offset"] == 10
    assert second["strings"][0] != first["strings"][0]


def test_scan_capped_over_collection_ceiling() -> None:
    """More matches than the collection ceiling sets scan_capped."""
    values = [f"hit_{i:05d}" for i in range(_MAX_STRINGS_COLLECT + 40)]
    payload = _client(values).search_strings(Path("dummy.apk"), "hit", limit=2000)
    assert payload["total"] == _MAX_STRINGS_COLLECT
    assert payload["scan_capped"] is True


def test_empty_when_no_match() -> None:
    payload = _client(["alpha", "beta"]).search_strings(Path("dummy.apk"), "zzz")
    assert payload["strings"] == []
    assert payload["total"] == 0
    assert payload["has_more"] is False


def test_requires_a_query() -> None:
    with pytest.raises(ApkError) as excinfo:
        _client(["alpha"]).search_strings(Path("dummy.apk"), "   ")
    assert excinfo.value.code == "invalid_params"


def test_string_search_docstring_names_shape() -> None:
    doc = _tool_docstring("apk.string_search")
    assert "Answers with strings" in doc
    assert "substring" in doc
    assert "scan_capped" in doc
