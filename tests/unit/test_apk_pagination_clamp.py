"""apk list backends must clamp offset/limit where the slice happens.

The tool schema refuses a negative offset (test_apk_offset_schema), but the
backend is also reachable by internal callers that never pass through pydantic
-- and it is the backend that pages with ``names[offset:offset+limit]``. Left
raw, offset=-1 is a tail slice that reads the end of the DEX as page zero, and
the echoed offset and has_more then describe a page that was never asked for.
The backend's own ``xrefs`` already clamps with ``max(1, int(limit))``; these
three now match it (and the web/proxy list backends).
"""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.backends.apk.client import ApkClient


class _FakeMethod:
    def __init__(self, name: str) -> None:
        self.name = name
        self.descriptor = "()V"
        self.access = "public"


class _FakeClass:
    def __init__(self, name: str, *, external: bool = False, methods: int = 0) -> None:
        self.name = name
        self._external = external
        self._methods = [_FakeMethod(f"m{index}") for index in range(methods)]

    def is_external(self) -> bool:
        return self._external

    def get_methods(self) -> list[_FakeMethod]:
        return self._methods


class _FakeString:
    def __init__(self, value: str) -> None:
        self._value = value

    def get_value(self) -> str:
        return self._value


class _FakeAnalysis:
    def __init__(
        self,
        classes: list[_FakeClass] | None = None,
        strings: list[_FakeString] | None = None,
    ) -> None:
        self._classes = classes or []
        self._strings = strings or []

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


def test_classes_negative_offset_is_page_zero_not_a_tail_slice() -> None:
    """The documented raw-slice bug: names[-1:-1+100] is the last name only."""
    names = [f"L{index};" for index in range(10)]
    # The old, unclamped behaviour this guards against.
    assert names[-1 : -1 + 100] == ["L9;"]
    client = _client(_FakeAnalysis(classes=[_FakeClass(n) for n in names]))
    payload = client.classes(Path("dummy.apk"), offset=-1, limit=100)
    assert payload["offset"] == 0
    assert payload["count"] == 10
    assert payload["classes"] == names
    assert payload["has_more"] is False


def test_classes_zero_limit_returns_one_row_not_an_empty_page() -> None:
    client = _client(_FakeAnalysis(classes=[_FakeClass(f"L{i};") for i in range(5)]))
    payload = client.classes(Path("dummy.apk"), offset=0, limit=0)
    assert payload["count"] == 1
    assert payload["offset"] == 0
    assert payload["has_more"] is True


def test_classes_valid_page_is_unchanged() -> None:
    client = _client(_FakeAnalysis(classes=[_FakeClass(f"L{i};") for i in range(10)]))
    payload = client.classes(Path("dummy.apk"), offset=3, limit=4)
    assert payload["offset"] == 3
    assert payload["count"] == 4
    assert payload["classes"] == ["L3;", "L4;", "L5;", "L6;"]
    assert payload["has_more"] is True


def test_methods_negative_offset_is_page_zero() -> None:
    analysis = _FakeAnalysis(classes=[_FakeClass("La;", methods=5)])
    client = _client(analysis)
    payload = client.methods(Path("dummy.apk"), "La;", offset=-2, limit=100)
    assert payload["offset"] == 0
    assert payload["count"] == 5
    assert payload["has_more"] is False
    zero_limit = client.methods(Path("dummy.apk"), "La;", offset=0, limit=0)
    assert zero_limit["count"] == 1
    assert zero_limit["has_more"] is True


def test_strings_negative_offset_is_page_zero() -> None:
    analysis = _FakeAnalysis(strings=[_FakeString(f"s{index}") for index in range(25)])
    client = _client(analysis)
    payload = client.strings(Path("dummy.apk"), offset=-5, limit=100)
    assert payload["offset"] == 0
    assert payload["count"] == 25
    assert payload["has_more"] is False
    zero_limit = client.strings(Path("dummy.apk"), offset=0, limit=0)
    assert zero_limit["count"] == 1
    assert zero_limit["has_more"] is True
