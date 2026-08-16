"""proxy.replay now waits, but the tool text hid that."""

from __future__ import annotations


class TestProxyReplayDescriptionMatchesTheWait:
    """A queued replay that never ran already times out, but the text hid that.

    Measured: call_soon_threadsafe queued the command, wait 0.2s, timeout,
    while the description said only "Replay" -- so a model treats enqueue
    as the request having left the process.
    """

    def test_the_tool_text_says_it_waits(self) -> None:
        from headless_re_mcp.core.service import AnalysisService
        from headless_re_mcp.tools.proxy import build_proxy_tools

        service = AnalysisService()
        try:
            tools = {item.name: item for item in build_proxy_tools(service)}
            doc = tools["proxy.replay"].handler.__doc__ or ""
        finally:
            service.close_all()
        assert "timeout" in doc
        assert "queued" in doc or "wait" in doc.lower()
