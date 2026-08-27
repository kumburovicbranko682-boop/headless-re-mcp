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
        """Launch a Chrome browser for the session and open a URL via CDP.

        The url is limited to http://, https:// and data:; file://, chrome:// and
        other schemes are refused with invalid_params so the browser cannot be
        turned into a local-file reader. An empty url opens a blank browser.

        Answers with opened, url, title and headless. There is no session,
        browser, ok or page field.
        """
        return _dump(analysis.web_open(session_id, url=url, headless=headless, timeout=timeout))

    @tools.tool(name="web.navigate")
    def web_navigate(
        session_id: str,
        url: str,
        timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0,
    ) -> dict[str, Any]:
        """Navigate the session's browser to a new URL.

        Like web.open, the url is limited to http://, https:// and data:; other
        schemes are refused with invalid_params.

        Answers with url and title. There is no navigated, ok or page field.
        """
        return _dump(analysis.web_navigate(session_id, url, timeout=timeout))

    @tools.tool(name="web.close")
    def web_close(session_id: str) -> dict[str, Any]:
        """Close the session's browser and free its resources.

        Answers with closed. When a browser thread existed, also clean.
        When nothing was open or open was aborted, note. There is no ok,
        success or freed field.
        """
        return _dump(analysis.web_close(session_id))

    @tools.tool(name="web.network.list")
    def web_network_list(
        session_id: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """List captured network requests.

        Answers with requests (url, method, status, resourceType, started_at as
        an epoch time), count, total, offset, has_more, and dropped so a page
        that filled the limit is not read as the whole capture, and ring
        eviction is visible. A request blocked or aborted before any response
        carries failed with error_text and, for a policy block, blocked_reason
        (and canceled), so a failed load is not read as one still in flight.
        has_post_data marks a row whose request carried a POST body, which
        web.network.get can then fetch. metadata_truncated marks bounded
        oversized request fields. There is no type field.
        """
        return _dump(analysis.web_network_list(session_id, offset=offset, limit=limit))

    @tools.tool(name="web.network.get")
    def web_network_get(session_id: str, request_id: str) -> dict[str, Any]:
        """Fetch one request's response body (large bodies spill to an artifact).

        Answers with body, base64_encoded, plus body_truncated and body_path
        when the text was cut at the buffer. The cut flag is body_truncated,
        not truncated. A body over the capture cap is refused rather than
        written to disk. When the request carried a POST body (has_post_data on
        the row), request_body is included the same way -- request_body_truncated
        and request_body_path (registered as request_artifact_id) when it spills,
        or request_body_error when it could not be retrieved -- so the payload the
        page sent is recoverable, not just the response.
        """
        return _dump(analysis.web_network_get(session_id, request_id))

    @tools.tool(name="web.console")
    def web_console(
        session_id: str, limit: Annotated[int, Field(ge=1, le=2000)] = 200
    ) -> dict[str, Any]:
        """Return recent browser console messages.

        Answers with console, count, has_more, and dropped so a page that
        filled the limit is not read as the whole buffer, and ring
        eviction is visible. A line longer than the per-message cap is
        cut and marked text_truncated. Uncaught errors and unhandled
        promise rejections -- which never reach console.* -- are folded
        into the same buffer as error entries flagged uncaught, with the
        throw site url/line when the engine reported one.
        """
        return _dump(analysis.web_console(session_id, limit=limit))

    @tools.tool(name="web.scripts")
    def web_scripts(
        session_id: str,
        wasm_only: bool = False,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """List parsed scripts seen by the debugger, one page at a time.

        Answers with scripts (scriptId, url, language), count, total, offset,
        has_more and dropped. The session keeps at most 2000 scripts. A page
        of 100 typical URLs is ~22 KiB; the full list was 441 KiB. Read
        total and has_more rather than assuming the page is complete.
        metadata_truncated marks bounded oversized script fields.
        """
        return _dump(
            analysis.web_scripts(
                session_id, wasm_only=wasm_only, offset=offset, limit=limit
            )
        )

    @tools.tool(name="web.script.source")
    def web_script_source(session_id: str, script_id: str) -> dict[str, Any]:
        """Fetch one script's source (large sources spill to an artifact).

        Answers with scriptId, bytes and source, plus truncated and
        source_path when the text was cut at the buffer. There is no code
        or text field. A source over the capture cap is refused rather
        than written to disk.
        """
        return _dump(analysis.web_script_source(session_id, script_id))

    @tools.tool(name="web.wasm.list")
    def web_wasm_list(
        session_id: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """List WebAssembly modules loaded by the page, one page at a time.

        Answers with scripts (scriptId, url, language), count, total, offset,
        has_more and dropped. There is no modules field. Same buffer as
        web.scripts. Read total and has_more. metadata_truncated marks bounded
        oversized script fields.
        """
        return _dump(analysis.web_wasm_list(session_id, offset=offset, limit=limit))

    @tools.tool(name="web.wasm.get")
    def web_wasm_get(session_id: str, script_id: str) -> dict[str, Any]:
        """Fetch a live WebAssembly module's bytes to a .wasm artifact.

        web.wasm.list surfaces the modules; this pulls one module's raw
        bytecode (CDP Debugger.getWasmBytecode) and writes it to wasm_path so it
        can be handed to wasm.wat / wasm.info for disassembly -- web.script.source
        on a wasm id returns the engine's text, not the binary. Answers with
        scriptId, url, bytes and wasm_path, plus artifact_id when registered.
        The id must name a WebAssembly module (see language on web.wasm.list); a
        JavaScript id is invalid_params. There is no source or body field.
        """
        return _dump(analysis.web_wasm_get(session_id, script_id))

    @tools.tool(name="web.dom.snapshot")
    def web_dom_snapshot(session_id: str) -> dict[str, Any]:
        """Return the current page HTML, URL, and title.

        Answers with url, title and html. html at most 200000 bytes is inline;
        a larger DOM puts the full document (up to the capture cap) at dom_path
        with html holding a prefix, and truncated is set. There is no content,
        dom or body field.
        """
        return _dump(analysis.web_dom_snapshot(session_id))

    @tools.tool(name="web.screenshot")
    def web_screenshot(session_id: str, full_page: bool = False) -> dict[str, Any]:
        """Capture a screenshot of the current page to a PNG artifact.

        Answers with path and size, plus artifact_id when the PNG was
        registered. There is no screenshot or png field. A full-page capture
        over the cap is refused rather than left on disk.
        """
        return _dump(analysis.web_screenshot(session_id, full_page=full_page))

    @tools.tool(name="web.har.export")
    def web_har_export(session_id: str) -> dict[str, Any]:
        """Export captured network activity to a HAR artifact.

        The file is a spec-valid HAR 1.2 log that standard viewers (Chrome
        DevTools, HAR analyzers) can open; each entry carries the required
        request/response, timings and startedDateTime members, with unknown
        fields left as empty/`-1` rather than omitted. Answers with path and
        entry_count, plus artifact_id when the HAR was registered. There is no
        har, entries or artifact field.
        """
        return _dump(analysis.web_har_export(session_id))

    return tools.bindings
