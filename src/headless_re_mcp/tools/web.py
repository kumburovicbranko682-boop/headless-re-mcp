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

        Answers with opened, url, title and headless, plus status when a URL
        was given and produced an HTTP response. A 4xx/5xx page still opens, so
        read status to tell an error page from a hit. There is no session,
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

        Answers with url and title, plus status when the navigation produced an
        HTTP response. A 4xx/5xx page still counts as navigated, so read status
        to tell an error page from a hit. There is no navigated, ok or page
        field.
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

        Answers with requests, count, total, offset, has_more, and dropped
        so a page that filled the limit is not read as the whole capture,
        and ring eviction is visible. Each request row carries requestId,
        url, method, status, resourceType and mimeType; requestId is the id
        to pass to web.network.get (as request_id) to fetch that request's
        response body -- it is how this list and the body fetch join. A
        request row also carries started_at (the unix epoch, in
        seconds, when CDP saw the request begin) when the browser reported
        it -- the same instant the HAR export uses for startedDateTime. A row
        also carries timings (measured send/wait/receive durations in
        milliseconds, from CDP's response timing and loadingFinished; phases it
        could not measure are absent) --
        the same values the HAR export puts in each entry's timings, whose
        non-negative sum is that entry's time. A request the browser could not
        complete (DNS/connect failure, a CSP/mixed-content/client block, or a
        fetch a navigation superseded) carries error=true and error_msg (CDP's
        errorText) with a null status, the same shape the proxy uses;
        canceled=true marks a benign abort as distinct from a hard failure, and
        blocked_reason names why a block happened when CDP reports one. A
        completed request carries a numeric status and no error field.
        metadata_truncated marks bounded oversized request fields. There is no
        type field.
        """
        return _dump(analysis.web_network_list(session_id, offset=offset, limit=limit))

    @tools.tool(name="web.network.get")
    def web_network_get(session_id: str, request_id: str) -> dict[str, Any]:
        """Fetch one request's response body (large or binary bodies spill).

        Answers with body, base64_encoded, plus body_truncated and body_path
        when the text was cut at the buffer. The cut flag is body_truncated,
        not truncated. A binary body (base64_encoded true) is never inlined or
        base64-written to disk: it is decoded and body_path holds the raw
        bytes, body is empty, body_truncated is false, and body_bytes is the
        decoded size. When CDP has no body for the request (a redirect, or a
        body already evicted from its cache) body is empty and body_error says
        why, while body, base64_encoded and body_truncated stay present. A
        body over the capture cap is refused rather than written to disk.
        A spilled body (body_path set) is registered as an artifact and
        artifact_id names it, so artifacts.read can page the full bytes; if
        registering it failed (a full or locked artifact store) artifact_error
        is set instead and body_path still points at the file.
        """
        return _dump(analysis.web_network_get(session_id, request_id))

    @tools.tool(name="web.console")
    def web_console(
        session_id: str, limit: Annotated[int, Field(ge=1, le=2000)] = 200
    ) -> dict[str, Any]:
        """Return recent browser console messages.

        Answers with console, count, total, has_more, and dropped so a page
        that filled the limit is not read as the whole buffer: total is how
        many messages are buffered, and ring eviction is visible via dropped.
        console holds the newest messages; the max limit covers the whole ring,
        so there is no offset. A line longer than the per-message cap is cut
        and marked text_truncated.
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
        than written to disk. A spilled source (source_path set) is
        registered as an artifact and artifact_id names it, so
        artifacts.read can page the full text; if registering it failed
        (a full or locked artifact store) artifact_error is set instead and
        source_path still points at the file. When that spilled source is
        minified or obfuscated JavaScript, hand source_path to js.deobfuscate
        or js.beautify (they read a file path) to recover readable code. A
        WebAssembly script (the kind wasm.list surfaces) has no text source
        here: source is empty, is_wasm is true, and note points at the path
        that does yield the bytes -- fetch the module body with
        web.network.get, then run wasm.wat / wasm.info.
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

    @tools.tool(name="web.dom.snapshot")
    def web_dom_snapshot(session_id: str) -> dict[str, Any]:
        """Return the current page HTML, URL, and title.

        Answers with url, title, bytes and html, plus truncated when the HTML
        was cut at the buffer. When truncated is set the html field holds only
        the leading buffer and the complete document is written to html_path
        (registered under artifact_id), so the tail is recoverable in this same
        run rather than lost. A DOM past the capture cap is refused as too_large.
        There is no content, dom or body field.
        """
        return _dump(analysis.web_dom_snapshot(session_id))

    @tools.tool(name="web.screenshot")
    def web_screenshot(session_id: str, full_page: bool = False) -> dict[str, Any]:
        """Capture a screenshot of the current page to a PNG artifact.

        Answers with path and size, plus artifact_id when the PNG was
        registered (or artifact_error if that registration failed, with path
        still naming the file). There is no screenshot or png field. A full-page
        capture over the cap is refused rather than left on disk.
        """
        return _dump(analysis.web_screenshot(session_id, full_page=full_page))

    @tools.tool(name="web.har.export")
    def web_har_export(session_id: str) -> dict[str, Any]:
        """Export captured network activity to a spec-valid HAR 1.2 artifact.

        Answers with path, entry_count, truncated and size, plus artifact_id
        when the HAR was registered (or artifact_error if that registration
        failed, with path still naming the file). truncated is true when the
        oldest entries were dropped to keep the file under the capture cap; size
        is the HAR file's byte length. There is no har, entries or artifact field.
        """
        return _dump(analysis.web_har_export(session_id))

    return tools.bindings
