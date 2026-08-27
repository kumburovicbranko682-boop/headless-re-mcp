"""apk list handlers must clamp a bad page window, not just the MCP schema.

The schema pins offset>=0 and a bounded limit, but the Agent transport calls
these handlers with the model's raw arguments and never runs that validation.
A model paging backwards then reaches ``names[-1:...]`` -- a tail slice, or an
empty page reported with a negative offset and has_more true, which a paging
loop reads as "no rows" or spins on. The client clamps for every transport.
"""

from __future__ import annotations

from pathlib import Path

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
    def __init__(self, name: str, *, external: bool = False) -> None:
        self.name = name
        self._external = external

    def is_external(self) -> bool:
        return self._external

    def get_methods(self) -> list[_FakeMethod]:
        return [_FakeMethod(f"m{index:03d}") for index in range(25)]


class _FakeParsed:
    def __init__(self, count: int) -> None:
        self.analysis = self
        self._count = count

    def get_strings(self) -> list[_FakeString]:
        return [_FakeString(f"s{index:03d}") for index in range(self._count)]

    def get_classes(self) -> list[_FakeClass]:
        return [_FakeClass(f"L{index:03d};") for index in range(self._count)]


def _client(count: int = 25) -> ApkClient:
    client = ApkClient()
    client._parsed = lambda _path: _FakeParsed(count)  # type: ignore[method-assign]
    return client


def test_negative_offset_is_read_as_page_zero_not_a_tail_slice() -> None:
    for name, call in (
        ("strings", lambda c: c.strings(Path("x.apk"), offset=-1, limit=10)),
        ("classes", lambda c: c.classes(Path("x.apk"), offset=-1, limit=10)),
    ):
        payload = call(_client())
        rows = payload[name]
        assert payload["offset"] == 0, f"{name}: negative offset must clamp to 0"
        assert len(rows) == 10, f"{name}: must return the first page, not an empty slice"
        assert "000" in rows[0], f"{name}: page zero must start at the first row"
        assert payload["count"] == 10
        assert payload["has_more"] is True


def test_negative_offset_on_methods_is_read_as_page_zero() -> None:
    client = _client()
    client._parsed = lambda _path: _FakeParsed(1)  # type: ignore[method-assign]
    # One class named "L000;", 25 methods on it.
    payload = client.methods(Path("x.apk"), "L000;", offset=-1, limit=10)
    assert payload["offset"] == 0
    assert payload["count"] == 10
    assert payload["methods"][0]["name"] == "m000"
    assert payload["has_more"] is True


def test_a_non_positive_limit_returns_one_row_rather_than_an_empty_or_inverted_page() -> None:
    for name, call in (
        ("strings", lambda c, lim: c.strings(Path("x.apk"), offset=0, limit=lim)),
        ("classes", lambda c, lim: c.classes(Path("x.apk"), offset=0, limit=lim)),
    ):
        zero = call(_client(), 0)
        assert zero["count"] == 1, f"{name}: limit 0 must not yield an empty page"
        negative = call(_client(), -5)
        assert negative["count"] == 1, f"{name}: negative limit must not invert the slice"


def test_an_in_range_page_is_unchanged_by_the_clamp() -> None:
    payload = _client(25).strings(Path("x.apk"), offset=5, limit=10)
    assert payload["offset"] == 5
    assert payload["count"] == 10
    assert payload["strings"][0] == "s005"
    assert payload["has_more"] is True
