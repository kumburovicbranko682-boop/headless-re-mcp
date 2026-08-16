"""IDA search pages that hit the cap used to look complete."""

from __future__ import annotations

import sys
from types import ModuleType

import pytest

from headless_re_mcp.backends.ida.worker import (
    _search_bytes,
    _search_immediate,
    _search_text,
)


def _install_ida(monkeypatch: pytest.MonkeyPatch, hits: list[int]) -> None:
    ida_ida = ModuleType("ida_ida")
    ida_ida.inf_get_min_ea = lambda: 0x1000  # type: ignore[attr-defined]
    ida_ida.inf_get_max_ea = lambda: 0x1000 + 100_000  # type: ignore[attr-defined]

    ida_idaapi = ModuleType("ida_idaapi")
    ida_idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF  # type: ignore[attr-defined]

    class _Vec:
        pass

    def bin_search(ea: int, end: int, patterns: object, flags: int) -> int:
        del patterns, flags
        for hit in hits:
            if ea <= hit < end:
                return hit
        return -1

    ida_bytes = ModuleType("ida_bytes")
    ida_bytes.compiled_binpat_vec_t = _Vec  # type: ignore[attr-defined]
    ida_bytes.parse_binpat_str = lambda *args, **kwargs: True  # type: ignore[attr-defined]
    ida_bytes.bin_search = bin_search  # type: ignore[attr-defined]
    ida_bytes.BIN_SEARCH_FORWARD = 1  # type: ignore[attr-defined]
    ida_bytes.BIN_SEARCH_NOSHOW = 2  # type: ignore[attr-defined]

    def _next(ea: int) -> int:
        for hit in hits:
            if hit >= ea:
                return hit
        return -1

    ida_search = ModuleType("ida_search")
    ida_search.SEARCH_DOWN = 1  # type: ignore[attr-defined]
    ida_search.find_text = lambda ea, x, y, text, flags: _next(ea)  # type: ignore[attr-defined]
    ida_search.find_imm = lambda ea, flags, value: _next(ea)  # type: ignore[attr-defined]

    idc = ModuleType("idc")
    idc.BADADDR = 0xFFFFFFFFFFFFFFFF  # type: ignore[attr-defined]

    for name, module in {
        "ida_ida": ida_ida,
        "ida_idaapi": ida_idaapi,
        "ida_bytes": ida_bytes,
        "ida_search": ida_search,
        "idc": idc,
    }.items():
        monkeypatch.setitem(sys.modules, name, module)


class TestIdaSearchSaysWhenItStopped:
    """A search page that hit the cap looks exactly like one that ended.

    Measured: 250 hits, limit 100, returned=100, total=100, has_more=false --
    the loop stopped at offset+limit, so the extra hit that would have
    proved the database continued was never asked for.
    """

    def test_byte_search_reports_the_cut(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        hits = list(range(0x1000, 0x1000 + 250))
        _install_ida(monkeypatch, hits)
        result = _search_bytes({"pattern": "90", "offset": 0, "limit": 100})
        assert result["returned"] == 100
        assert result["has_more"] is True

    def test_text_search_reports_the_cut(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        hits = list(range(0x1000, 0x1000 + 250))
        _install_ida(monkeypatch, hits)
        result = _search_text({"text": "foo", "offset": 0, "limit": 100})
        assert result["returned"] == 100
        assert result["has_more"] is True

    def test_immediate_search_reports_the_cut(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        hits = list(range(0x1000, 0x1000 + 250))
        _install_ida(monkeypatch, hits)
        result = _search_immediate({"value": 1, "offset": 0, "limit": 100})
        assert result["returned"] == 100
        assert result["has_more"] is True

    def test_a_short_search_is_complete(self, monkeypatch: pytest.MonkeyPatch) -> None:
        hits = list(range(0x1000, 0x1000 + 3))
        _install_ida(monkeypatch, hits)
        result = _search_bytes({"pattern": "90", "offset": 0, "limit": 100})
        assert result["returned"] == 3
        assert result["has_more"] is False

    def test_a_result_that_exactly_fills_the_page_is_complete(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        hits = list(range(0x1000, 0x1000 + 100))
        _install_ida(monkeypatch, hits)
        result = _search_bytes({"pattern": "90", "offset": 0, "limit": 100})
        assert result["returned"] == 100
        assert result["has_more"] is False
