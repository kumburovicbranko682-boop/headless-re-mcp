"""IDA function CFGs used to dump every block with no cut flag."""

from __future__ import annotations

import json
import sys
from types import ModuleType

import pytest

from headless_re_mcp.backends.ida.worker import _cfg


class _Block:
    def __init__(self, index: int, total: int) -> None:
        self.id = index
        self.start_ea = 0x1000 + index * 16
        self.end_ea = self.start_ea + 16
        self.type = 0
        self._total = total

    def succs(self) -> list[_Block]:
        if self.id + 1 < self._total:
            return [_Block(self.id + 1, self._total)]
        return []


class _Chart:
    def __init__(self, total: int) -> None:
        self._total = total

    def __iter__(self) -> object:
        return (_Block(index, self._total) for index in range(self._total))


class _Fn:
    start_ea = 0x1000
    end_ea = 0x1000 + 16


def _install(monkeypatch: pytest.MonkeyPatch, blocks: int) -> None:
    ida_gdl = ModuleType("ida_gdl")
    ida_gdl.FlowChart = lambda function: _Chart(blocks)  # type: ignore[attr-defined]
    ida_funcs = ModuleType("ida_funcs")

    def get_func(address: int) -> _Fn:
        del address
        return _Fn()

    ida_funcs.get_func = get_func  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "ida_gdl", ida_gdl)
    monkeypatch.setitem(sys.modules, "ida_funcs", ida_funcs)


class TestIdaCfgSaysWhenItStopped:
    """A huge function CFG used to look exactly like a complete one.

    Measured: 5000 blocks, 411 KiB, no truncated -- so a caller that only
    looks at the graph thinks the function ended.
    """

    def test_hitting_the_cap_is_reported(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install(monkeypatch, 5000)
        result = _cfg({"address": 0x1000})
        assert result["node_count"] == 1024
        assert result["truncated"] is True
        dumped = json.dumps(result)
        assert len(dumped.encode("utf-8")) < 200_000

    def test_a_complete_graph_is_not_labelled_partial(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install(monkeypatch, 3)
        result = _cfg({"address": 0x1000})
        assert result["node_count"] == 3
        assert result["truncated"] is False

    def test_a_result_that_exactly_fills_the_cap_is_complete(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install(monkeypatch, 1024)
        result = _cfg({"address": 0x1000})
        assert result["node_count"] == 1024
        assert result["truncated"] is False


class TestStaticCfgDescriptionMatchesTheCut:
    """static.cfg now cuts at 1024 nodes, but the tool text hid that.

    Measured: 5000 blocks, node_count=1024, truncated=true, while the
    description said "return function-local CFG" -- so a model treats the
    slice as the whole graph.
    """

    def test_the_tool_text_says_to_check_truncated(self) -> None:
        from headless_re_mcp.core.service import AnalysisService
        from headless_re_mcp.tools.core import build_static_extended_tools

        service = AnalysisService()
        try:
            tools = {item.name: item for item in build_static_extended_tools(service)}
            doc = tools["static.cfg"].handler.__doc__ or ""
        finally:
            service.close_all()
        assert "truncated" in doc
