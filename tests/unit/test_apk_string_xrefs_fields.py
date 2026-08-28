"""apk.string_xrefs must return the string-to-code edges it promises.

This pivots from a DEX string constant to the methods that load it, via
androguard's StringAnalysis.get_xref_from (which yields (class, method) pairs
where method is a MethodAnalysis carrying class_name/name -- the same shape the
xrefs/callees rows read). The test fakes that analysis so no real DEX is
needed, and pins the contract the description promises: byte-exact matching
that never trims, a found flag that separates an unreferenced string from an
absent one, referrers rows of class/method, and a has_more that only trips when
the page actually dropped a row.
"""

from __future__ import annotations

import ast
from pathlib import Path

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


class _FakeMethod:
    def __init__(self, class_name: str, name: str) -> None:
        self.class_name = class_name
        self.name = name


class _FakeString:
    def __init__(self, value: str, referrers: list[_FakeMethod]) -> None:
        self._value = value
        self._referrers = referrers

    def get_value(self) -> str:
        return self._value

    def get_xref_from(self) -> list[tuple[object, _FakeMethod]]:
        # androguard yields (ClassAnalysis, MethodAnalysis); the backend reads
        # the second element, so the first can be anything.
        return [(None, method) for method in self._referrers]


class _FakeParsed:
    def __init__(self, strings: list[_FakeString]) -> None:
        self.analysis = self
        self._strings = strings

    def get_strings(self) -> list[_FakeString]:
        return self._strings


def _client(strings: list[_FakeString]) -> ApkClient:
    client = ApkClient()
    client._parsed = lambda _path: _FakeParsed(strings)  # type: ignore[method-assign]
    return client


def test_string_xrefs_lists_referring_methods() -> None:
    strings = [
        _FakeString(
            "https://api.example.com/login",
            [
                _FakeMethod("Lcom/app/Net;", "connect"),
                _FakeMethod("Lcom/app/Auth;", "login"),
            ],
        ),
        _FakeString("unrelated", [_FakeMethod("X", "y")]),
    ]
    payload = _client(strings).string_xrefs(
        Path("dummy.apk"), "https://api.example.com/login", limit=100
    )

    assert payload["value"] == "https://api.example.com/login"
    assert payload["found"] is True
    assert "callers" not in payload
    assert "callees" not in payload
    assert payload["referrers"] == [
        {"class": "Lcom/app/Net;", "method": "connect"},
        {"class": "Lcom/app/Auth;", "method": "login"},
    ]
    assert payload["count"] == 2
    assert payload["has_more"] is False


def test_string_present_but_unreferenced_is_found_with_no_referrers() -> None:
    strings = [_FakeString("dead-constant", [])]
    payload = _client(strings).string_xrefs(Path("dummy.apk"), "dead-constant")
    assert payload["found"] is True
    assert payload["referrers"] == []
    assert payload["count"] == 0
    assert payload["has_more"] is False


def test_absent_string_reports_found_false() -> None:
    strings = [_FakeString("something-else", [_FakeMethod("X", "y")])]
    payload = _client(strings).string_xrefs(Path("dummy.apk"), "not-in-module")
    assert payload["found"] is False
    assert payload["referrers"] == []
    assert payload["count"] == 0


def test_match_is_byte_exact_and_never_trimmed() -> None:
    # A value with significant surrounding whitespace must match only itself,
    # never its trimmed form -- the opposite of how method names are handled.
    strings = [
        _FakeString("  spaced  ", [_FakeMethod("L;", "a")]),
        _FakeString("spaced", [_FakeMethod("L;", "b")]),
    ]
    padded = _client(strings).string_xrefs(Path("dummy.apk"), "  spaced  ")
    assert padded["found"] is True
    assert padded["referrers"] == [{"class": "L;", "method": "a"}]

    trimmed = _client(strings).string_xrefs(Path("dummy.apk"), "spaced")
    assert trimmed["found"] is True
    assert trimmed["referrers"] == [{"class": "L;", "method": "b"}]


def test_has_more_trips_only_when_a_row_is_dropped() -> None:
    referrers = [_FakeMethod(f"L{i};", f"m{i}") for i in range(5)]
    strings = [_FakeString("hot", referrers)]

    full = _client(strings).string_xrefs(Path("dummy.apk"), "hot", limit=5)
    assert full["count"] == 5
    assert full["has_more"] is False

    clipped = _client(strings).string_xrefs(Path("dummy.apk"), "hot", limit=3)
    assert clipped["count"] == 3
    assert clipped["has_more"] is True


def test_empty_value_is_rejected() -> None:
    client = _client([])
    try:
        client.string_xrefs(Path("dummy.apk"), "", limit=10)
    except ApkError as exc:
        assert exc.code == "invalid_params"
    else:  # pragma: no cover - the call must raise
        raise AssertionError("empty value was accepted")


def test_string_xrefs_docstring_names_returned_fields() -> None:
    doc = _tool_docstring("apk.string_xrefs")
    assert "Answers with referrers" in doc
    assert "found" in doc
    assert "has_more" in doc
