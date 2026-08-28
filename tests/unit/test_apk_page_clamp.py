"""apk.classes/methods/strings/xrefs must clamp the page window at the client.

The apk.* tool schemas already bound ``offset >= 0`` and ``limit`` within range
(see test_apk_offset_schema.py), but only the MCP transport runs that pydantic
validation: the agent and OpenAI-bridge transports call the bound handler
directly (``CommandCatalog.invoke`` -> ``spec.handler(**arguments)``), so an
out-of-range page reaches the backend unchecked. Measured before the fix,
``classes(offset=-1, limit=10)`` over ten classes returned ``names[-1:9]`` --
an empty page that still reported ``has_more`` True -- and ``limit=-5`` returned
``names[0:-5]``, an all-but-the-tail slice read as page zero. These pin the
clamp so the pagination contract holds on every call path, like the web, proxy
and jsre list backends already do.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from headless_re_mcp.backends.apk.client import (
    _MAX_CLASSES_PAGE,
    _MAX_METHODS_PAGE,
    _MAX_STRINGS_PAGE,
    _MAX_XREFS_PAGE,
    ApkClient,
)
from headless_re_mcp.tools.apk import build_apk_tools
from headless_re_mcp.tools.binding import input_schema_for


class _FakeClass:
    def __init__(self, name: str) -> None:
        self.name = name

    def is_external(self) -> bool:
        return False


class _FakeClassParsed:
    def __init__(self, classes: list[_FakeClass]) -> None:
        self.analysis = self
        self._classes = classes

    def get_classes(self) -> list[_FakeClass]:
        return self._classes


class _FakeApkMethod:
    def __init__(self, index: int) -> None:
        self.name = f"m{index}"
        self.descriptor = "()V"
        self.access = "public"


class _FakeMethodClass:
    def __init__(self, count: int) -> None:
        self.name = "Lcom/example/Foo;"
        self._methods = [_FakeApkMethod(index) for index in range(count)]

    def get_methods(self) -> list[_FakeApkMethod]:
        return self._methods


class _FakeMethodParsed:
    def __init__(self, count: int) -> None:
        self.analysis = self
        self._classes = [_FakeMethodClass(count)]

    def get_classes(self) -> list[_FakeMethodClass]:
        return self._classes


class _FakeString:
    def __init__(self, value: str) -> None:
        self._value = value

    def get_value(self) -> str:
        return self._value


class _FakeStringParsed:
    def __init__(self, values: list[str]) -> None:
        self.analysis = self
        self._values = [_FakeString(value) for value in values]

    def get_strings(self) -> list[_FakeString]:
        return self._values


def _classes_client(monkeypatch: Any, count: int) -> ApkClient:
    monkeypatch.setattr(
        ApkClient,
        "_parsed",
        lambda self, path: _FakeClassParsed([_FakeClass(f"L{i:04d};") for i in range(count)]),
    )
    return ApkClient()


def test_negative_offset_returns_page_zero_not_a_tail_slice(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """offset=-1 used to be names[-1:9] -- an empty page claiming has_more."""
    client = _classes_client(monkeypatch, 10)
    payload = client.classes(tmp_path / "app.apk", offset=-1, limit=10)
    assert payload["offset"] == 0
    assert payload["count"] == 10
    assert payload["classes"][0] == "L0000;"
    assert payload["has_more"] is False


def test_negative_limit_clamps_to_one_row(tmp_path: Path, monkeypatch: Any) -> None:
    """limit=-5 used to be names[0:-5] -- ten classes read as five."""
    client = _classes_client(monkeypatch, 10)
    payload = client.classes(tmp_path / "app.apk", offset=0, limit=-5)
    assert payload["count"] == 1
    assert payload["classes"] == ["L0000;"]
    assert payload["has_more"] is True


def test_oversized_limit_is_capped_at_the_schema_maximum(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A page larger than the schema max must not read more than that many rows."""
    client = _classes_client(monkeypatch, _MAX_CLASSES_PAGE + 25)
    payload = client.classes(tmp_path / "app.apk", offset=0, limit=10**9)
    assert payload["count"] == _MAX_CLASSES_PAGE
    assert payload["has_more"] is True


def test_offset_past_total_is_an_empty_final_page(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """An offset beyond the collected rows is the end, not more to come."""
    client = _classes_client(monkeypatch, 10)
    payload = client.classes(tmp_path / "app.apk", offset=100, limit=10)
    assert payload["count"] == 0
    assert payload["has_more"] is False


def test_methods_clamp_negative_offset(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: _FakeMethodParsed(10))
    client = ApkClient()
    payload = client.methods(tmp_path / "app.apk", "com.example.Foo", offset=-3, limit=5)
    assert payload["offset"] == 0
    assert payload["count"] == 5
    assert payload["methods"][0]["name"] == "m0"


def test_methods_clamp_oversized_limit(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(
        ApkClient, "_parsed", lambda self, path: _FakeMethodParsed(_MAX_METHODS_PAGE + 5)
    )
    client = ApkClient()
    payload = client.methods(tmp_path / "app.apk", "com.example.Foo", offset=0, limit=10**9)
    assert payload["count"] == _MAX_METHODS_PAGE
    assert payload["has_more"] is True


def test_strings_clamp_negative_offset(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(
        ApkClient,
        "_parsed",
        lambda self, path: _FakeStringParsed([f"s{i:04d}" for i in range(10)]),
    )
    client = ApkClient()
    payload = client.strings(tmp_path / "app.apk", offset=-1, limit=10)
    assert payload["offset"] == 0
    assert payload["count"] == 10
    assert payload["has_more"] is False


class _FakeXrefCall:
    def __init__(self, index: int) -> None:
        self.class_name = f"Lcom/example/Caller{index};"
        self.name = "invoke"


class _FakeXrefMethod:
    def __init__(self, name: str, callers: int) -> None:
        self.name = name
        self._callers = callers

    def is_external(self) -> bool:
        return False

    def get_xref_from(self) -> list[tuple[object, _FakeXrefCall, int]]:
        return [(None, _FakeXrefCall(index), index) for index in range(self._callers)]


class _FakeXrefParsed:
    def __init__(self, methods: list[_FakeXrefMethod]) -> None:
        self.analysis = self
        self._methods = methods

    def get_methods(self) -> list[_FakeXrefMethod]:
        return self._methods


def test_xrefs_limit_is_capped_at_the_schema_maximum(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """xrefs clamped limit to >=1 but had no ceiling; the agent path could ask for all."""
    monkeypatch.setattr(
        ApkClient,
        "_parsed",
        lambda self, path: _FakeXrefParsed([_FakeXrefMethod("decrypt", _MAX_XREFS_PAGE + 20)]),
    )
    client = ApkClient()
    payload = client.xrefs(tmp_path / "app.apk", "decrypt", limit=10**9)
    assert payload["count"] == _MAX_XREFS_PAGE
    assert payload["has_more"] is True


class _PaddedXrefCall:
    def __init__(self, index: int) -> None:
        self.class_name = f"Lcom/example/Caller{index:03d};"
        self.name = "invoke"


class _OrderedXrefMethod:
    """Yields caller sites in a caller-controlled order, to pin sort-before-page."""

    def __init__(self, name: str, order: list[int]) -> None:
        self.name = name
        self._order = order

    def is_external(self) -> bool:
        return False

    def get_xref_from(self) -> list[tuple[object, _PaddedXrefCall, int]]:
        return [(None, _PaddedXrefCall(index), index) for index in self._order]


def _xrefs_client(monkeypatch: Any, order: list[int]) -> ApkClient:
    monkeypatch.setattr(
        ApkClient,
        "_parsed",
        lambda self, path: _FakeXrefParsed([_OrderedXrefMethod("decrypt", order)]),
    )
    return ApkClient()


def test_xrefs_page_is_the_sorted_prefix_and_a_later_offset_reaches_the_rest(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """Callers arrive reverse-ordered and overflow the page: the first page must
    be the alphabetical prefix, and a later offset must return the tail.

    That second call is the whole point of the change -- xrefs had no offset, so a
    method called from more than a page of sites returned an unsorted first slice
    with has_more set and the rest unreachable. Now it pages like classes/strings.
    """
    apk = tmp_path / "app.apk"
    client = _xrefs_client(monkeypatch, list(reversed(range(5))))  # 4,3,2,1,0
    first = client.xrefs(apk, "decrypt", offset=0, limit=3)
    assert first["total"] == 5
    assert first["offset"] == 0
    assert first["scan_capped"] is False
    assert [caller["class"] for caller in first["callers"]] == [
        "Lcom/example/Caller000;",
        "Lcom/example/Caller001;",
        "Lcom/example/Caller002;",
    ]
    assert first["has_more"] is True
    second = client.xrefs(apk, "decrypt", offset=3, limit=3)
    assert [caller["class"] for caller in second["callers"]] == [
        "Lcom/example/Caller003;",
        "Lcom/example/Caller004;",
    ]
    assert second["has_more"] is False


def test_xrefs_negative_offset_returns_page_zero(tmp_path: Path, monkeypatch: Any) -> None:
    client = _xrefs_client(monkeypatch, list(range(10)))
    payload = client.xrefs(tmp_path / "app.apk", "decrypt", offset=-1, limit=10)
    assert payload["offset"] == 0
    assert payload["count"] == 10
    assert payload["has_more"] is False


def test_xrefs_offset_past_total_is_an_empty_final_page(
    tmp_path: Path, monkeypatch: Any
) -> None:
    client = _xrefs_client(monkeypatch, list(range(5)))
    payload = client.xrefs(tmp_path / "app.apk", "decrypt", offset=100, limit=10)
    assert payload["count"] == 0
    assert payload["total"] == 5
    assert payload["has_more"] is False


def test_xrefs_flags_scan_capped_when_the_collection_ceiling_is_hit(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """More caller sites than the collect ceiling: the walk stops and scan_capped
    says total is a floor, not the true caller count -- the same signal
    classes/strings give when the scan is capped before paging."""
    monkeypatch.setattr("headless_re_mcp.backends.apk.client._MAX_XREFS_COLLECT", 2)
    client = _xrefs_client(monkeypatch, list(range(5)))
    payload = client.xrefs(tmp_path / "app.apk", "decrypt", offset=0, limit=10)
    assert payload["scan_capped"] is True
    assert payload["total"] == 2
    assert payload["count"] == 2
    assert payload["has_more"] is False


def _limit_schema(name: str) -> dict[str, object]:
    handler = next(
        binding.handler
        for binding in build_apk_tools(object())  # type: ignore[arg-type]
        if binding.name == name
    )
    return input_schema_for(handler)["properties"]["limit"]


def test_client_page_caps_match_the_tool_schema_maxima() -> None:
    """The clamp ceiling and the schema's declared maximum must not drift apart.

    If they did, the MCP path (schema-validated) and the agent path (clamped
    here) would disagree about the largest page, and the tighter of the two
    would silently win depending on which transport made the call.
    """
    assert _limit_schema("apk.classes")["maximum"] == _MAX_CLASSES_PAGE
    assert _limit_schema("apk.methods")["maximum"] == _MAX_METHODS_PAGE
    assert _limit_schema("apk.strings")["maximum"] == _MAX_STRINGS_PAGE
    assert _limit_schema("apk.xrefs")["maximum"] == _MAX_XREFS_PAGE
