"""static.disassemble now flags a cut line, but the tool text hid that."""

from __future__ import annotations


class TestStaticDisassembleDescriptionMatchesTheCut:
    """A 512-char disasm line already sets truncated, but the text hid that.

    Measured: 1000-char line, text length 512, truncated=true, while the
    description said only "bounded linear disassembly" -- so a model treats
    the slice as the whole mnemonic.
    """

    def test_the_tool_text_says_to_check_truncated(self) -> None:
        from headless_re_mcp.core.service import AnalysisService
        from headless_re_mcp.tools.core import build_static_extended_tools

        service = AnalysisService()
        try:
            tools = {item.name: item for item in build_static_extended_tools(service)}
            doc = tools["static.disassemble"].handler.__doc__ or ""
        finally:
            service.close_all()
        assert "truncated" in doc
