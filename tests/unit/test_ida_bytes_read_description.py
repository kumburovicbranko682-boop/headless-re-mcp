"""static.bytes.read now flags a short read, but the tool text hid that."""

from __future__ import annotations


class TestStaticBytesReadDescriptionMatchesTheCut:
    """A short read already sets truncated, but the description hid that.

    Measured: asked 64, got 10, truncated=true, while the description said
    only "bounded byte range" -- so a model treats size as the request.
    """

    def test_the_tool_text_says_to_check_truncated(self) -> None:
        from headless_re_mcp.core.service import AnalysisService
        from headless_re_mcp.tools.core import build_static_extended_tools

        service = AnalysisService()
        try:
            tools = {item.name: item for item in build_static_extended_tools(service)}
            doc = tools["static.bytes.read"].handler.__doc__ or ""
        finally:
            service.close_all()
        assert "truncated" in doc
