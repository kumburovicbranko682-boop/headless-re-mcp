"""apk.urls extracts URL tokens from the DEX string pool, deduped and paged.

The fake parsed APK stands in for androguard's analysis.get_strings so the URL
regex, de-duplication, sorting, bounding and pagination are what get exercised.
"""

from __future__ import annotations

import ast
from pathlib import Path

from headless_re_mcp.backends.apk.client import (
    _MAX_STRINGS_COLLECT,
    ApkClient,
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


def test_apk_urls_extracts_only_url_tokens_deduped_and_sorted() -> None:
    """URLs are pulled out of surrounding text, deduped, sorted.

    Measured: a URL embedded in a larger literal comes back bare, a non-URL
    string is dropped, duplicates collapse, and the field is urls (not strings
    or endpoints).
    """
    client = _client(
        [
            "base=https://api.example/v2 fallback",
            "https://api.example/v2",
            "plain string with no link",
            "ws://sock.example/rt",
            "ftp://files.example/pub",
            "http://a.example/x",
        ]
    )
    payload = client.urls(Path("dummy.apk"))
    assert payload["urls"] == [
        "ftp://files.example/pub",
        "http://a.example/x",
        "https://api.example/v2",
        "ws://sock.example/rt",
    ]
    assert payload["count"] == 4
    assert payload["total"] == 4
    assert payload["has_more"] is False
    assert payload["scan_capped"] is False
    assert "strings" not in payload
    assert "endpoints" not in payload


def test_apk_urls_paginates() -> None:
    """A page that fills the limit reports has_more with a stable window."""
    values = [f"https://h{i:03d}.example/p" for i in range(25)]
    client = _client(values)
    payload = client.urls(Path("dummy.apk"), offset=0, limit=10)
    assert payload["count"] == 10
    assert payload["total"] == 25
    assert payload["has_more"] is True
    nxt = client.urls(Path("dummy.apk"), offset=10, limit=10)
    assert nxt["offset"] == 10
    assert nxt["urls"][0] != payload["urls"][0]


def test_apk_urls_scan_capped_when_over_collection_cap() -> None:
    """More distinct URLs than the collection cap sets scan_capped."""
    values = [f"https://h{i:05d}.example/p" for i in range(_MAX_STRINGS_COLLECT + 50)]
    client = _client(values)
    payload = client.urls(Path("dummy.apk"), offset=0, limit=2000)
    assert payload["total"] == _MAX_STRINGS_COLLECT
    assert payload["scan_capped"] is True


def test_apk_urls_empty_when_no_urls() -> None:
    """A pool with no URLs answers with an empty list, not an error."""
    payload = _client(["just", "some", "words"]).urls(Path("dummy.apk"))
    assert payload["urls"] == []
    assert payload["total"] == 0
    assert payload["has_more"] is False
    assert payload["scan_capped"] is False


def test_apk_urls_docstring_names_shape() -> None:
    doc = _tool_docstring("apk.urls")
    assert "Answers with urls" in doc
    assert "scan_capped" in doc
    assert "has_more" in doc
