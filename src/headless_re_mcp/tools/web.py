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

        Each open holds a live Chromium; at most 8 may run at once, so an open
        past that ceiling is invalid_state (close one with web.close first)
        rather than a starved host.

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
        url_filter: str = "",
    ) -> dict[str, Any]:
        """List captured network requests.

        Answers with requests (url, method, status, resourceType, started_at as
        an epoch time, and remote_ip/remote_port -- the server the request
        actually reached, the C2/CDN host behind the domain, present once a
        response arrived over a real connection), count, total, offset,
        has_more, and dropped so a page
        that filled the limit is not read as the whole capture, and ring
        eviction is visible. A request blocked or aborted before any response
        carries failed with error_text and, for a policy block, blocked_reason
        (and canceled), so a failed load is not read as one still in flight.
        has_post_data marks a row whose request carried a POST body, which
        web.network.get can then fetch. metadata_truncated marks bounded
        oversized request fields. Headers are omitted from this index to keep it
        lean; fetch them per row with web.network.get. There is no type field.
        url_filter keeps only rows whose url contains that substring
        (case-insensitive), applied before paging so total is the match count --
        the way to find one endpoint on a page that captured hundreds.
        """
        return _dump(
            analysis.web_network_list(
                session_id, offset=offset, limit=limit, url_filter=url_filter
            )
        )

    @tools.tool(name="web.network.get")
    def web_network_get(session_id: str, request_id: str) -> dict[str, Any]:
        """Fetch one request's response body (large bodies spill to an artifact).

        Answers with body, base64_encoded, plus body_truncated and body_path
        when the text was cut at the buffer. The cut flag is body_truncated,
        not truncated. A body over the capture cap is refused rather than
        written to disk. request_headers and response_headers are lists of
        {name, value} in the order CDP reported them, each repeat kept as its own
        entry so every Set-Cookie survives. When the request carried a POST body
        (has_post_data on the row), request_body is included the same way --
        request_body_truncated and request_body_path (registered as
        request_artifact_id) when it spills, or request_body_error when it could
        not be retrieved -- so the payload the page sent is recoverable, not just
        the response.
        """
        return _dump(analysis.web_network_get(session_id, request_id))

    @tools.tool(name="web.console")
    def web_console(
        session_id: str,
        limit: Annotated[int, Field(ge=1, le=2000)] = 200,
        type_filter: str = "",
    ) -> dict[str, Any]:
        """Return recent browser console messages.

        Answers with console, count, has_more, and dropped so a page that
        filled the limit is not read as the whole buffer, and ring
        eviction is visible. type_filter keeps only entries whose type equals
        that value (case-insensitive, e.g. error or warning), applied before
        the tail, so failures can be pulled out of a log-flooded console; the
        uncaught throws folded in are typed error. A line longer than the
        per-message cap is
        cut and marked text_truncated. Object and array arguments are
        rendered from their members ({k: v}, [v, ...]) rather than a bare
        "Object", so a logged config or token survives. Each entry carries the
        call site url/line (0-based, as CDP reports) from the message's stack
        when one was present, so a logged line can be traced to its script.
        Uncaught errors and unhandled promise rejections -- which never reach
        console.* -- are folded into the same buffer as error entries flagged
        uncaught, with the throw site url/line when the engine reported one and
        a stack list ([{function, url, line}], top frames, 0-based lines) when
        the engine reported the call chain, so the failure can be placed in the
        code, not just named.
        """
        return _dump(analysis.web_console(session_id, limit=limit, type_filter=type_filter))

    @tools.tool(name="web.cookies")
    def web_cookies(
        session_id: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 200,
        domain_filter: str = "",
    ) -> dict[str, Any]:
        """Read the browser's whole cookie jar via CDP (Network.getAllCookies).

        Unlike the Set-Cookie headers captured per request, this returns the
        live jar as it stands now: cookies set by JavaScript, carried across
        redirects the request ring already evicted, and HttpOnly cookies a
        page's own document.cookie cannot see -- the session/auth tokens a web
        RE task is usually after. Answers with cookies (name, value, domain,
        path, http_only, secure, session, and expires/size/same_site when the
        browser reported them; value clipped with value_truncated when long),
        count, total, offset, has_more, and collection_truncated when the jar
        held more than the collection cap. domain_filter keeps only cookies
        whose domain contains that substring (case-insensitive), applied before
        paging, to separate the app's own cookies from third-party trackers.
        There is no set or delete; this is read-only.
        """
        return _dump(
            analysis.web_cookies(
                session_id, offset=offset, limit=limit, domain_filter=domain_filter
            )
        )

    @tools.tool(name="web.scripts")
    def web_scripts(
        session_id: str,
        wasm_only: bool = False,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        dynamic_only: bool = False,
        url_filter: str = "",
    ) -> dict[str, Any]:
        """List parsed scripts seen by the debugger, one page at a time.

        Answers with scripts (scriptId, url, language), count, total, offset,
        has_more and dropped. The session keeps at most 2000 scripts. A page
        of 100 typical URLs is ~22 KiB; the full list was 441 KiB. Read
        total and has_more rather than assuming the page is complete.
        metadata_truncated marks bounded oversized script fields. A script
        compiled at runtime (eval, new Function, injected <script>) carries a
        blank url and is flagged dynamic true -- a packer's unpacked payload
        lands there, so point web.script.source at it; length, when the engine
        reported it, is the script's character count for sizing which blank-url
        blob to pull. dynamic_only keeps just those runtime-generated scripts
        (which a url_filter cannot reach, their url being blank). url_filter
        keeps only scripts whose url contains that substring (case-insensitive);
        both are applied before paging, so total is the match count.
        """
        return _dump(
            analysis.web_scripts(
                session_id,
                wasm_only=wasm_only,
                offset=offset,
                limit=limit,
                dynamic_only=dynamic_only,
                url_filter=url_filter,
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
        request/response, timings and startedDateTime members, its queryString
        recovered from the request URL, the request/response headers CDP
        reported, the request body (as request.postData) for a row whose POST
        payload CDP inlined at send time, request/response cookies parsed from
        the Cookie/Set-Cookie headers, redirectURL recovered from the
        response Location header, request/response bodySize recovered from
        Content-Length, and serverIPAddress set to the server IP the response
        arrived from, with unknown fields left as empty/`-1` rather than
        omitted.
        Answers with path and entry_count, plus artifact_id when the HAR was
        registered. There is no har, entries or artifact field.
        """
        return _dump(analysis.web_har_export(session_id))

    return tools.bindings
