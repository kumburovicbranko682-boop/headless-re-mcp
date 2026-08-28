"""Shared contract across the four apk.* xref tools.

apk.xrefs (callers), apk.callees (callees), apk.string_xrefs (referrers) and
apk.field_xrefs (accesses) each have their own field test, but those exercise
tiny limits (3-5), so three facts the four tools are supposed to share are
never actually locked:

* every row, whatever the list is called, is a class/method pair of strings --
  a future fifth xref tool that forgets one, or emits a non-string, must trip;
* they clamp to the same real page ceiling (_MAX_XREFS_PAGE = 1000), not the
  monkeypatched stand-in a per-tool test would use, and a collection sitting
  exactly on the ceiling is not misreported as partial;
* they clamp an out-of-range limit identically -- limit <= 0 down to one row,
  a huge limit down to the ceiling -- which matters because the agent and
  OpenAI-bridge transports reach these backends without the tool schema's
  pydantic bounds (the reason _clamp_page exists).

The androguard analysis each tool reads is faked, so no DEX or JRE is needed.
Note the two tuple shapes are honoured per tool: MethodAnalysis.get_xref_from/
to yield (class, method, offset) triples, while StringAnalysis/FieldAnalysis
xrefs yield (class, method) pairs.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apk.client import _MAX_XREFS_PAGE, ApkClient

_PATH = Path("dummy.apk")

_Payload = dict[str, Any]
_Call = Callable[[int], _Payload]
_Builder = Callable[[int], "tuple[_Call, str]"]


class _EdgeMethod:
    """A MethodAnalysis stand-in as it appears in a row."""

    def __init__(self, class_name: str, name: str) -> None:
        self.class_name = class_name
        self.name = name


class _QueryMethod:
    """The method apk.xrefs / apk.callees resolves the query name to."""

    def __init__(self, edges: list[_EdgeMethod]) -> None:
        self.name = "t"
        self._edges = edges

    def is_external(self) -> bool:
        return False

    def _triples(self) -> list[tuple[object, _EdgeMethod, int]]:
        return [(None, edge, 0) for edge in self._edges]

    def get_xref_from(self) -> list[tuple[object, _EdgeMethod, int]]:
        return self._triples()

    def get_xref_to(self) -> list[tuple[object, _EdgeMethod, int]]:
        return self._triples()


class _QueryString:
    def __init__(self, value: str, edges: list[_EdgeMethod]) -> None:
        self._value = value
        self._edges = edges

    def get_value(self) -> str:
        return self._value

    def get_xref_from(self) -> list[tuple[object, _EdgeMethod]]:
        return [(None, edge) for edge in self._edges]


class _EncodedField:
    def __init__(self, class_name: str) -> None:
        self._class_name = class_name

    def get_class_name(self) -> str:
        return self._class_name


class _QueryField:
    def __init__(self, name: str, class_name: str, edges: list[_EdgeMethod]) -> None:
        self.name = name
        self._encoded = _EncodedField(class_name)
        self._edges = edges

    def get_field(self) -> _EncodedField:
        return self._encoded

    def get_xref_read(self) -> list[tuple[object, _EdgeMethod]]:
        return [(None, edge) for edge in self._edges]

    def get_xref_write(self) -> list[tuple[object, _EdgeMethod]]:
        return []


class _Parsed:
    def __init__(
        self,
        *,
        methods: list[object] | None = None,
        strings: list[object] | None = None,
        fields: list[object] | None = None,
    ) -> None:
        self.analysis = self
        self._methods = methods or []
        self._strings = strings or []
        self._fields = fields or []

    def get_methods(self) -> list[object]:
        return self._methods

    def get_strings(self) -> list[object]:
        return self._strings

    def get_fields(self) -> list[object]:
        return self._fields


def _client(parsed: _Parsed) -> ApkClient:
    client = ApkClient()
    client._parsed = lambda _path: parsed  # type: ignore[method-assign]
    return client


def _edges(n: int) -> list[_EdgeMethod]:
    return [_EdgeMethod(f"L{i};", f"m{i}") for i in range(n)]


# For each xref tool: given an edge count, build a faked client and return the
# bound call (limit -> payload) plus the key its row list lives under.
def _case_xrefs(n: int) -> tuple[_Call, str]:
    client = _client(_Parsed(methods=[_QueryMethod(_edges(n))]))
    return (lambda limit: client.xrefs(_PATH, "t", limit=limit)), "callers"


def _case_callees(n: int) -> tuple[_Call, str]:
    client = _client(_Parsed(methods=[_QueryMethod(_edges(n))]))
    return (lambda limit: client.callees(_PATH, "t", limit=limit)), "callees"


def _case_string(n: int) -> tuple[_Call, str]:
    client = _client(_Parsed(strings=[_QueryString("t", _edges(n))]))
    return (lambda limit: client.string_xrefs(_PATH, "t", limit=limit)), "referrers"


def _case_field(n: int) -> tuple[_Call, str]:
    client = _client(_Parsed(fields=[_QueryField("t", "L;", _edges(n))]))
    return (lambda limit: client.field_xrefs(_PATH, "t", limit=limit)), "accesses"


_CASES: dict[str, _Builder] = {
    "apk.xrefs": _case_xrefs,
    "apk.callees": _case_callees,
    "apk.string_xrefs": _case_string,
    "apk.field_xrefs": _case_field,
}


@pytest.mark.parametrize("builder", _CASES.values(), ids=list(_CASES))
def test_rows_are_class_method_string_pairs(builder: _Builder) -> None:
    call, list_key = builder(3)
    payload = call(100)
    rows = payload[list_key]
    assert payload["count"] == len(rows) == 3
    assert type(payload["has_more"]) is bool
    for row in rows:
        assert type(row["class"]) is str
        assert type(row["method"]) is str


@pytest.mark.parametrize("builder", _CASES.values(), ids=list(_CASES))
def test_shared_page_ceiling(builder: _Builder) -> None:
    # Exactly on the ceiling: full, but nothing was dropped.
    call, list_key = builder(_MAX_XREFS_PAGE)
    at = call(10**9)
    assert at["count"] == _MAX_XREFS_PAGE == len(at[list_key])
    assert at["has_more"] is False

    # One past the ceiling: capped at the ceiling and flagged partial.
    call, list_key = builder(_MAX_XREFS_PAGE + 1)
    over = call(10**9)
    assert over["count"] == _MAX_XREFS_PAGE == len(over[list_key])
    assert over["has_more"] is True


@pytest.mark.parametrize("builder", _CASES.values(), ids=list(_CASES))
def test_out_of_range_limit_is_clamped(builder: _Builder) -> None:
    # 50 available edges, well under the ceiling, so clamping is observable.
    for bad_low in (0, -7):
        call, _ = builder(50)
        low = call(bad_low)
        assert low["count"] == 1, f"limit={bad_low} should clamp up to one row"
        assert low["has_more"] is True

    call, _ = builder(50)
    high = call(10**9)
    assert high["count"] == 50
    assert high["has_more"] is False
