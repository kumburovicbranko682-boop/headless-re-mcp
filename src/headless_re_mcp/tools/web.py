"""Protocol-independent web.* tool definitions (browser dynamic analysis via CDP).

No arbitrary-JS ``web.evaluate`` is exposed, mirroring the debugger surface's
refusal to offer a generic ``dynamic.command``.
"""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import Field

from headless_re_mcp.core.models import Result
from headless_re_mcp.core.service import AnalysisService, JsonObject
from headless_re_mcp.tools.binding import BoundTool, ToolSetBuilder


def _dump(result: Result[JsonObject]) -> dict[str, Any]:
    value = result.model_dump(mode="json")
    if not isinstance(value, dict):
        raise TypeError("result envelope did not serialize to an object")
    return value


def build_web_tools(analysis: AnalysisService) -> tuple[BoundTool, ...]:
    tools = ToolSetBuilder()

    @tools.tool(name="web.open")
    def web_open(
        session_id: str,
        url: str = "",
        headless: bool = True,
        timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0,
    ) -> dict[str, Any]:
        """Launch a Chrome browser for the session and open a URL via CDP."""
        return _dump(analysis.web_open(session_id, url=url, headless=headless, timeout=timeout))

    @tools.tool(name="web.navigate")
    def web_navigate(
        session_id: str,
        url: str,
        timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0,
    ) -> dict[str, Any]:
        """Navigate the session's browser to a new URL."""
        return _dump(analysis.web_navigate(session_id, url, timeout=timeout))

    @tools.tool(name="web.close")
    def web_close(session_id: str) -> dict[str, Any]:
        """Close the session's browser and free its resources."""
        return _dump(analysis.web_close(session_id))

    @tools.tool(name="web.network.list")
    def web_network_list(
        session_id: str,
        offset: int = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """List captured network requests (url, method, status, type).

        The live window is capped. Read has_more and seen rather than treating
        total as every request the page ever made.
        """
        return _dump(analysis.web_network_list(session_id, offset=offset, limit=limit))

    @tools.tool(name="web.network.get")
    def web_network_get(session_id: str, request_id: str) -> dict[str, Any]:
        """Fetch one request's response body (large bodies spill to an artifact)."""
        return _dump(analysis.web_network_get(session_id, request_id))

    @tools.tool(name="web.console")
    def web_console(
        session_id: str, limit: Annotated[int, Field(ge=1, le=2000)] = 200
    ) -> dict[str, Any]:
        """Return recent browser console messages.

        This is a tail, not the whole log. Read has_more and total rather than
        treating count as every line the page ever printed.
        """
        return _dump(analysis.web_console(session_id, limit=limit))

    @tools.tool(name="web.scripts")
    def web_scripts(session_id: str, wasm_only: bool = False) -> dict[str, Any]:
        """List parsed scripts (JavaScript and WebAssembly) seen by the debugger.

        The live window is capped. Read has_more and total rather than treating
        count as the number of scripts the page ever parsed.
        """
        return _dump(analysis.web_scripts(session_id, wasm_only=wasm_only))

    @tools.tool(name="web.script.source")
    def web_script_source(session_id: str, script_id: str) -> dict[str, Any]:
        """Fetch one script's source (large sources spill to an artifact)."""
        return _dump(analysis.web_script_source(session_id, script_id))

    @tools.tool(name="web.wasm.list")
    def web_wasm_list(session_id: str) -> dict[str, Any]:
        """List WebAssembly modules loaded by the page.

        Shares the script window, so has_more means older scripts were evicted.
        """
        return _dump(analysis.web_wasm_list(session_id))

    @tools.tool(name="web.dom.snapshot")
    def web_dom_snapshot(session_id: str) -> dict[str, Any]:
        """Return the current page HTML, URL, and title.

        Oversized HTML is cut and marked truncated. Read that flag rather
        than treating html as the whole document.
        """
        return _dump(analysis.web_dom_snapshot(session_id))

    @tools.tool(name="web.screenshot")
    def web_screenshot(session_id: str, full_page: bool = False) -> dict[str, Any]:
        """Capture a screenshot of the current page to a PNG artifact.

        The write is checked on the way out: a save that did not produce a
        local file is an error, not a path.
        """
        return _dump(analysis.web_screenshot(session_id, full_page=full_page))

    @tools.tool(name="web.har.export")
    def web_har_export(session_id: str) -> dict[str, Any]:
        """Export captured network activity to a HAR artifact.

        The file is the retained window, not every request the page ever made.
        Read truncated and seen rather than treating entry_count as the whole
        capture.
        """
        return _dump(analysis.web_har_export(session_id))

    return tools.bindings
