"""static.decompile already spills, but the tool text hid that."""

from __future__ import annotations


class TestStaticDecompileDescriptionMatchesTheSpill:
    """A spilled decompilation already sets truncated, but the text hid that.

    Measured: oversized C, truncated=true plus artifact_id, while the
    description said only "decompile the function" -- so a model treats
    the 1 KiB preview as the whole function.
    """

    def test_the_tool_text_says_to_check_truncated(self) -> None:
        from headless_re_mcp.core.service import AnalysisService
        from headless_re_mcp.tools.core import build_static_core_tools

        service = AnalysisService()
        try:
            tools = {item.name: item for item in build_static_core_tools(service)}
            doc = tools["static.decompile"].handler.__doc__ or ""
        finally:
            service.close_all()
        assert "truncated" in doc
