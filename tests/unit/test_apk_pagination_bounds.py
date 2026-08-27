"""The androguard listings clamp hostile pagination at the backend.

The MCP schema pins offset>=0 and a limit range (test_apk_offset_schema), but
the backend is the real contract: the service layer forwards offset/limit
untouched and a direct or future internal caller can pass anything. A negative
offset used to slice ``names[-1:...]`` from the end and report ``has_more``
against a negative index; a non-positive limit produced an empty or reversed
page. These pin the same clamped, coherent window every sibling paginator
already guarantees.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from headless_re_mcp.backends.apk.client import ApkClient


class _FakeString:
    def __init__(self, value: str) -> None:
        self._value = value

    def get_value(self) -> str:
        return self._value


class _FakeMethod:
    def __init__(self, name: str) -> None:
        self.name = name
        self.descriptor = "()V"
        self.access = "public"


class _FakeClass:
    def __init__(self, name: str, *, external: bool = False, methods: Any = ()) -> None:
        self.name = name
        self._external = external
        self._methods = list(methods)

    def is_external(self) -> bool:
        return self._external

    def get_methods(self) -> list[_FakeMethod]:
        return self._methods


class _FakeAnalysis:
    def __init__(self, *, classes: Any = (), strings: Any = ()) -> None:
        self._classes = list(classes)
        self._strings = list(strings)

    def get_classes(self) -> list[_FakeClass]:
        return self._classes

    def get_strings(self) -> list[_FakeString]:
        return self._strings


class _FakeParsed:
    def __init__(self, analysis: _FakeAnalysis) -> None:
        self.analysis = analysis


def _client(analysis: _FakeAnalysis) -> ApkClient:
    client = ApkClient()
    client._parsed = lambda _path: _FakeParsed(analysis)  # type: ignore[method-assign]
    return client


def _classes(count: int) -> _FakeAnalysis:
    return _FakeAnalysis(classes=[_FakeClass(f"Lc{index:02d};") for index in range(count)])


class TestClassesPagination:
    def test_a_negative_offset_clamps_to_zero(self) -> None:
        payload = _client(_classes(10)).classes(Path("x.apk"), offset=-5, limit=3)

        assert payload["offset"] == 0
        assert payload["count"] == 3
        assert payload["classes"] == ["Lc00;", "Lc01;", "Lc02;"]
        assert payload["has_more"] is True

    def test_a_nonpositive_limit_clamps_to_one(self) -> None:
        for hostile in (0, -10):
            payload = _client(_classes(10)).classes(Path("x.apk"), offset=0, limit=hostile)
            assert payload["count"] == 1
            assert payload["classes"] == ["Lc00;"]
            assert payload["has_more"] is True

    def test_a_page_past_the_end_is_coherent(self) -> None:
        payload = _client(_classes(10)).classes(Path("x.apk"), offset=10_000, limit=100)

        assert payload["offset"] == 10_000
        assert payload["classes"] == []
        assert payload["count"] == 0
        assert payload["has_more"] is False

    def test_the_full_list_is_not_reported_as_partial(self) -> None:
        payload = _client(_classes(4)).classes(Path("x.apk"), offset=0, limit=100)

        assert payload["count"] == payload["total"] == 4
        assert payload["has_more"] is False


class TestStringsPagination:
    def test_a_negative_offset_clamps_to_zero(self) -> None:
        analysis = _FakeAnalysis(strings=[_FakeString(f"s{index:02d}") for index in range(20)])
        payload = _client(analysis).strings(Path("x.apk"), offset=-3, limit=5)

        assert payload["offset"] == 0
        assert payload["strings"] == ["s00", "s01", "s02", "s03", "s04"]
        assert payload["has_more"] is True


class TestMethodsPagination:
    def test_a_negative_offset_clamps_to_zero(self) -> None:
        klass = _FakeClass(
            "Lcom/example/Foo;",
            methods=[_FakeMethod(f"m{index:02d}") for index in range(8)],
        )
        payload = _client(_FakeAnalysis(classes=[klass])).methods(
            Path("x.apk"), "Lcom/example/Foo;", offset=-4, limit=2
        )

        assert payload["offset"] == 0
        assert payload["count"] == 2
        assert [m["name"] for m in payload["methods"]] == ["m00", "m01"]
        assert payload["has_more"] is True
