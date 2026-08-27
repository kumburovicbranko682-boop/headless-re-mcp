"""web.open's proxy option: empty means direct, a value passes through verbatim.

The proxy argument is what routes the browser through an intercepting proxy, so
the tool layer's contract matters: an empty string (the tool default) must reach
the service as ``None`` (direct), and a real server URL must arrive unchanged.
This pins that translation without launching a browser.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from headless_re_mcp.core.models import Result
from headless_re_mcp.tools.web import build_web_tools


class _RecordingAnalysis:
    """Captures the kwargs web.open forwards to the service layer."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def web_open(self, session_id: str, **kwargs: Any) -> Result[dict[str, Any]]:
        self.calls.append({"session_id": session_id, **kwargs})
        return Result(ok=True, data={"opened": True, "proxy": kwargs.get("proxy")})


def _web_open_handler(analysis: Any) -> Callable[..., dict[str, Any]]:
    tools = build_web_tools(analysis)
    handler = next(t.handler for t in tools if t.name == "web.open")
    return handler


def test_empty_proxy_reaches_the_service_as_none_direct() -> None:
    analysis = _RecordingAnalysis()
    handler = _web_open_handler(analysis)

    handler(session_id="s", url="http://example.test/")

    assert len(analysis.calls) == 1
    assert analysis.calls[0]["proxy"] is None

    analysis.calls.clear()
    handler(session_id="s", url="http://example.test/", proxy="")
    assert analysis.calls[0]["proxy"] is None


def test_proxy_url_passes_through_unchanged() -> None:
    analysis = _RecordingAnalysis()
    handler = _web_open_handler(analysis)

    handler(session_id="s", url="http://example.test/", proxy="http://127.0.0.1:8080")

    assert analysis.calls[0]["proxy"] == "http://127.0.0.1:8080"
