"""r2.disasm already cuts raw and items, but the tool text hid that."""

from __future__ import annotations


class TestR2DisasmDescriptionMatchesTheCut:
    """r2.disasm already sets truncated and items_truncated, but the text hid that.

    Measured: 1000050-byte raw plus 5000 items, truncated=true,
    items_truncated=true, count=4096, while the description said only
    "disassemble count instructions" -- so a model treats the slice as
    the whole listing.
    """

    def test_the_tool_text_says_to_check_truncated(self) -> None:
        from headless_re_mcp.core.service import AnalysisService
        from headless_re_mcp.tools.r2 import build_r2_tools

        service = AnalysisService()
        try:
            tools = {item.name: item for item in build_r2_tools(service)}
            doc = tools["r2.disasm"].handler.__doc__ or ""
        finally:
            service.close_all()
        assert "truncated" in doc
        assert "items_truncated" in doc
