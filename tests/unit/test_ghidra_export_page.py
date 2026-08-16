"""Ghidra export pages must say when the limit hid more items."""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.backends.ghidra.client import (
    _annotate_decompile_truncation,
    _annotate_export_page,
)
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.tools.ghidra import build_ghidra_tools


def _page_with_peek(values: list[int], limit: int) -> tuple[list[int], bool]:
    """Mirror ExportJson.py: stop at limit and mark the leftover item."""
    items: list[int] = []
    has_more = False
    for value in values:
        if len(items) >= limit:
            has_more = True
            break
        items.append(value)
    return items, has_more


class TestGhidraExportPage:
    def test_a_full_page_used_to_look_complete(self) -> None:
        """Measured: 300 functions, limit 256, count=256, no has_more."""
        items = []
        for index in range(300):
            if len(items) >= 256:
                break
            items.append({"name": f"f{index}"})
        payload = {"mode": "functions", "items": items, "count": len(items)}
        assert payload["count"] == 256
        assert "has_more" not in payload
        marked = _annotate_export_page(dict(payload), 256)
        assert marked["has_more"] is True

    def test_a_short_page_is_not_marked_incomplete(self) -> None:
        marked = _annotate_export_page(
            {"mode": "functions", "items": [{"name": "a"}], "count": 1},
            256,
        )
        assert marked["has_more"] is False

    def test_script_peek_is_trusted_when_exactly_at_limit(self) -> None:
        page, has_more = _page_with_peek(list(range(256)), 256)
        assert len(page) == 256
        assert has_more is False
        marked = _annotate_export_page(
            {"items": [{"name": str(i)} for i in page], "has_more": has_more},
            256,
        )
        assert marked["has_more"] is False

    def test_script_peek_marks_a_cut_list(self) -> None:
        page, has_more = _page_with_peek(list(range(300)), 256)
        assert len(page) == 256
        assert has_more is True

    def test_export_script_sets_has_more(self) -> None:
        script = (
            Path(__file__).resolve().parents[2]
            / "src"
            / "headless_re_mcp"
            / "backends"
            / "ghidra"
            / "scripts"
            / "ExportJson.py"
        )
        text = script.read_text(encoding="utf-8")
        assert 'payload["has_more"] = has_more' in text
        assert text.count("has_more = True") == 3

    def test_a_cut_decompile_used_to_look_complete(self) -> None:
        """Measured: 200019 characters came back as 200000 with no flag."""
        text = "int f(){\n" + ("x" * 200_010)
        payload = {
            "mode": "decompile",
            "decompiled": text[:200_000],
            "count": 0,
        }
        assert len(payload["decompiled"]) == 200_000
        assert "truncated" not in payload
        marked = _annotate_decompile_truncation(dict(payload))
        assert marked["truncated"] is True
        short = _annotate_decompile_truncation(
            {"mode": "decompile", "decompiled": "int f(){ return 0; }"}
        )
        assert short["truncated"] is False

    def test_export_script_marks_a_cut_decompile(self) -> None:
        script = (
            Path(__file__).resolve().parents[2]
            / "src"
            / "headless_re_mcp"
            / "backends"
            / "ghidra"
            / "scripts"
            / "ExportJson.py"
        )
        text = script.read_text(encoding="utf-8")
        assert 'payload["truncated"] = len(text) > cap' in text

    def test_tool_descriptions_tell_the_model_to_read_has_more(self) -> None:
        service = AnalysisService()
        try:
            tools = {item.name: item for item in build_ghidra_tools(service)}
            for name in ("ghidra.functions", "ghidra.symbols", "ghidra.xrefs"):
                doc = tools[name].handler.__doc__ or ""
                assert "has_more" in doc
            assert "truncated" in (tools["ghidra.decompile"].handler.__doc__ or "")
        finally:
            service.close_all()
