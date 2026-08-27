"""apk paging must clamp offset/limit, because a transport may not.

The MCP schema constrains apk.classes/methods/strings with
``Field(ge=0, le=...)``, but the agent transport dispatches straight to the
handler (``CommandCatalog.invoke`` calls ``spec.handler(**arguments)`` with
only a size/depth check), so a model-supplied ``offset=-1`` used to reach the
list slice and Python negative-indexing returned a wrong tail window instead of
an empty one. The sibling backends (proxy flows, jsre unpack, adb listings) all
clamp in the client; these pin that the apk pager now matches them: a negative
offset reads as 0, an oversized/negative limit is bounded, and the returned
``offset`` reflects the clamped start so a follow-up page is aimed correctly.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apk.client import ApkClient


class _FakeClass:
    def __init__(self, name: str) -> None:
        self.name = name

    def is_external(self) -> bool:
        return False


class _FakeString:
    def __init__(self, value: str) -> None:
        self._value = value

    def get_value(self) -> str:
        return self._value


class _FakeMethod:
    def __init__(self, index: int) -> None:
        self.name = f"m{index}"
        self.descriptor = "()V"
        self.access = "public"


class _FakeMethodClass:
    def __init__(self, count: int) -> None:
        self.name = "Lcom/example/Foo;"
        self._methods = [_FakeMethod(i) for i in range(count)]

    def get_methods(self) -> list[_FakeMethod]:
        return self._methods


class _FakeAnalysis:
    def __init__(self, *, classes: list[_FakeClass], strings: list[_FakeString],
                 method_classes: list[_FakeMethodClass]) -> None:
        self.analysis = self
        self._classes = classes
        self._strings = strings
        self._method_classes = method_classes

    def get_classes(self) -> list[Any]:
        # classes() and methods() both call get_classes(); return whichever the
        # test populated. A test never populates both.
        return self._classes or self._method_classes

    def get_strings(self) -> list[_FakeString]:
        return self._strings


def _patch(monkeypatch: Any, analysis: _FakeAnalysis) -> ApkClient:
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: analysis)
    return ApkClient()


@pytest.mark.parametrize("bad_offset", [-1, -5, -1000])
def test_classes_negative_offset_reads_as_the_head_not_a_tail(
    tmp_path: Path, monkeypatch: Any, bad_offset: int
) -> None:
    names = [f"Lpkg/C{i:03d};" for i in range(30)]
    client = _patch(monkeypatch, _FakeAnalysis(
        classes=[_FakeClass(n) for n in names], strings=[], method_classes=[]
    ))
    payload = client.classes(tmp_path / "app.apk", offset=bad_offset, limit=5)
    assert payload["offset"] == 0
    # sorted names, first five -- a negative index would have returned the tail.
    assert payload["classes"] == sorted(names)[:5]
    assert payload["count"] == 5
    assert payload["has_more"] is True


def test_classes_oversized_limit_is_bounded_but_returns_all_available(
    tmp_path: Path, monkeypatch: Any
) -> None:
    names = [f"Lpkg/C{i:03d};" for i in range(12)]
    client = _patch(monkeypatch, _FakeAnalysis(
        classes=[_FakeClass(n) for n in names], strings=[], method_classes=[]
    ))
    payload = client.classes(tmp_path / "app.apk", offset=0, limit=10_000_000)
    assert payload["count"] == 12
    assert payload["has_more"] is False


def test_methods_negative_offset_reads_as_the_head(
    tmp_path: Path, monkeypatch: Any
) -> None:
    client = _patch(monkeypatch, _FakeAnalysis(
        classes=[], strings=[], method_classes=[_FakeMethodClass(20)]
    ))
    payload = client.methods(tmp_path / "app.apk", "com.example.Foo", offset=-3, limit=4)
    assert payload["offset"] == 0
    assert payload["count"] == 4
    assert [m["name"] for m in payload["methods"]] == ["m0", "m1", "m2", "m3"]
    assert payload["has_more"] is True


def test_strings_negative_offset_reads_as_the_head(
    tmp_path: Path, monkeypatch: Any
) -> None:
    values = [f"str{i:03d}" for i in range(40)]
    client = _patch(monkeypatch, _FakeAnalysis(
        classes=[], strings=[_FakeString(v) for v in values], method_classes=[]
    ))
    payload = client.strings(tmp_path / "app.apk", offset=-7, limit=6)
    assert payload["offset"] == 0
    assert payload["strings"] == sorted(values)[:6]
    assert payload["count"] == 6
    assert payload["has_more"] is True
