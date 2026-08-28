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
        method: str | None = None,
        url_contains: str | None = None,
        status: int | None = None,
        resource_type: str | None = None,
        failed: bool | None = None,
    ) -> dict[str, Any]:
        """List captured network requests.

        Answers with requests (url, method, status, resourceType), count,
        total, offset, has_more, and dropped so a page that filled the
        limit is not read as the whole capture, and ring eviction is
        visible. A finished response carries response_size (decoded body
        bytes), response_encoded_size (on-wire body bytes) and transfer_size
        (total transfer incl. headers), and is flagged finished -- so a large
        response is spottable without fetching its body. A request that carried
        a payload is flagged has_request_body,
        so web.network.get can be pointed at it to fetch request_body.
        A request the browser blocked or aborted (CSP, CORS, net::ERR_*,
        cancellation) is flagged failed with error_text (and blocked_reason
        or canceled when known) instead of a status, so it is not mistaken
        for one still pending. Headers are not in the list (it stays cheap);
        fetch them with web.network.get. metadata_truncated marks bounded
        oversized request fields. There is no type field.

        Pass any of method (exact, case-insensitive), url_contains (a
        case-insensitive substring of the URL -- a host or path fragment),
        status (exact int; a request with no status yet never matches),
        resource_type (exact, case-insensitive: xhr/fetch/script/document/
        image/...) or failed (true keeps only blocked/aborted requests, false
        only those not flagged failed) to narrow a large capture -- finding one
        XHR to an API host among thousands of requests otherwise meant paging
        the whole log. Filters combine (all must hold) and are applied before
        pagination, so total/count/has_more describe the matched subset; when
        any filter is set the reply also carries filtered true and
        unfiltered_total (the whole capture's size) so a small match is not
        read as a small capture. dropped stays the whole-capture eviction count.
        """
        return _dump(
            analysis.web_network_list(
                session_id,
                offset=offset,
                limit=limit,
                method=method,
                url_contains=url_contains,
                status=status,
                resource_type=resource_type,
                failed=failed,
            )
        )

    @tools.tool(name="web.network.stats")
    def web_network_stats(session_id: str) -> dict[str, Any]:
        """Fold the whole request capture into a triage summary.

        web.network.list is a paged listing; this folds the ring once so a
        caller can see what a busy page's capture holds before deciding what to
        filter for. Answers with total, by_method (a count per HTTP method),
        by_status_class (a count per 2xx/3xx/4xx/5xx; requests with no status
        yet are not counted here and show up in no_status instead),
        by_resource_type (a count per xhr/fetch/script/document/image/...),
        top_hosts and top_content_types (each a list of {host|content_type,
        count}, ranked and capped at 50 with host_count/content_type_count
        giving the distinct totals so a trimmed list is visible), and the counts
        failed, with_request_body, finished and no_status. dropped is the
        ring-eviction count, same as web.network.list. There is no requests,
        items or flows field here -- use web.network.list to list (and to
        filter), this to summarize.
        """
        return _dump(analysis.web_network_stats(session_id))

    @tools.tool(name="web.network.get")
    def web_network_get(session_id: str, request_id: str) -> dict[str, Any]:
        """Fetch one request's bodies (large bodies spill to an artifact).

        Answers with body, base64_encoded, plus body_truncated and body_path
        when the text was cut at the buffer. The cut flag is body_truncated,
        not truncated. A binary response (base64_encoded true: image, font,
        wasm, protobuf, any gzip'd body) is decoded to its real bytes: body is
        empty, body_path always holds the decoded bytes (not base64), body_bytes
        is the decoded length, and body_base64 carries a bounded base64 preview
        (body_base64_truncated when the preview was cut). When the request
        carried a payload (an XHR/fetch body, a form POST) it comes back as
        request_body, with request_body_truncated and request_body_path
        following the same rules; request_body_error replaces it when the
        browser no longer retains the payload.

        Both sides' headers come back as request_headers and response_headers
        (bounded maps: auth, cookies, content type, CORS), the metadata an API
        reverser needs alongside the body. metadata_truncated marks a header
        set that was capped or clipped.
        """
        return _dump(analysis.web_network_get(session_id, request_id))

    @tools.tool(name="web.console")
    def web_console(
        session_id: str,
        limit: Annotated[int, Field(ge=1, le=2000)] = 200,
        level: str | None = None,
        contains: str | None = None,
    ) -> dict[str, Any]:
        """Return recent browser console messages.

        Answers with console, count, has_more, and dropped so a page that
        filled the limit is not read as the whole buffer, and ring
        eviction is visible. A line longer than the per-message cap is
        cut and marked text_truncated.

        Uncaught page exceptions are captured too, as entries with type
        error and source exception (they never arrive as console.* calls),
        so an unhandled error and its stack are not silently lost.

        Each entry also carries its source location when the browser reports
        one: url, line, column (all 1-based, matching DevTools), and the
        enclosing function. This pins a log line or exception to the exact
        script site instead of leaving only the message text.

        Pass level to keep only one severity -- an exact, case-insensitive
        match on the entry's type (log/info/warning/error/debug/...); level=
        error also selects uncaught exceptions, since they carry type error.
        Pass contains to keep only messages whose text holds a case-insensitive
        substring. Filters are applied before the tail is taken, so console is
        the most recent matches and count/has_more describe the matched subset;
        when either is set the reply also carries filtered true and
        unfiltered_total (the whole ring's size) so a handful of matches is not
        read as a near-empty console. dropped stays the whole-ring eviction
        count. This turns a page flooding the console with debug lines into a
        readable error view without paging everything.
        """
        return _dump(
            analysis.web_console(session_id, limit=limit, level=level, contains=contains)
        )

    @tools.tool(name="web.cookies")
    def web_cookies(session_id: str) -> dict[str, Any]:
        """List the browser context's cookies (the auth/session jar).

        Answers with cookies, count, and has_more so a jar that filled the cap
        is not read as every cookie. Each entry carries name, value (the token
        or session id you are usually after, bounded like a header value),
        domain, path, http_only, secure, same_site when set, and expires only
        for a persistent cookie (a session cookie has none). A name or value
        cut to its cap is marked metadata_truncated. There is no jar or items
        field.
        """
        return _dump(analysis.web_cookies(session_id))

    @tools.tool(name="web.storage")
    def web_storage(session_id: str) -> dict[str, Any]:
        """Read the page's Web Storage (localStorage and sessionStorage).

        The cookie jar is only half the client-side state; SPAs keep JWTs,
        refresh tokens, feature flags and app state in Web Storage, which
        web.cookies never sees. Answers with origin and two areas, local and
        session, each carrying items (key, value), count, total and has_more so
        a store cut at the per-area cap (500) is not read as the whole store. A
        key or value cut to its byte cap is marked metadata_truncated. An area
        the origin refused (opaque origin, storage disabled) comes back empty
        with an error string rather than a silent empty store. Values are read
        in full up to the cap -- this is the token you are usually after.
        """
        return _dump(analysis.web_storage(session_id))

    @tools.tool(name="web.scripts")
    def web_scripts(
        session_id: str,
        wasm_only: bool = False,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        url_contains: str | None = None,
    ) -> dict[str, Any]:
        """List parsed scripts seen by the debugger, one page at a time.

        Answers with scripts (scriptId, url, language), count, total, offset,
        has_more and dropped. The session keeps at most 2000 scripts. A page
        of 100 typical URLs is ~22 KiB; the full list was 441 KiB. Read
        total and has_more rather than assuming the page is complete.
        metadata_truncated marks bounded oversized script fields.

        Pass url_contains to keep only scripts whose url holds a
        case-insensitive substring (an app-bundle name, a vendor, a path
        fragment) -- narrowing runs before pagination, so a real page's dozens
        of vendor/analytics scripts do not have to be paged by hand to find the
        one you want. When set the reply also carries filtered true and
        unfiltered_total (the whole list's size) so a handful of matches is not
        read as a near-empty session; total/count/has_more then describe the
        matched subset. dropped stays the whole-ring eviction count. Combines
        with wasm_only.
        """
        return _dump(
            analysis.web_scripts(
                session_id,
                wasm_only=wasm_only,
                offset=offset,
                limit=limit,
                url_contains=url_contains,
            )
        )

    @tools.tool(name="web.script.source")
    def web_script_source(session_id: str, script_id: str) -> dict[str, Any]:
        """Fetch one script's source (large sources spill to an artifact).

        Answers with scriptId, bytes and source, plus truncated and
        source_path when the text was cut at the buffer. There is no code
        or text field. A source over the capture cap is refused rather
        than written to disk.

        For a WebAssembly module (a scriptId from web.wasm.list) source is
        empty -- the bytes come back as is_wasm true, wasm_bytes and a
        wasm_path .wasm artifact you can hand to wasm.wat / wasm.info for
        offline analysis.
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

    @tools.tool(name="web.dom.query")
    def web_dom_query(
        session_id: str,
        selector: str,
        limit: Annotated[int, Field(ge=1, le=200)] = 50,
    ) -> dict[str, Any]:
        """Return elements matching a CSS selector, with their attributes and text.

        web.dom.snapshot dumps the whole document; this targets it. Answers with
        elements, each carrying tag (lowercased), attributes (a bounded name->
        value map -- href/src/name/value/data-*, the RE-relevant signals),
        attrs_truncated (true when the element had more attributes than the cap),
        and text (the trimmed textContent, bounded). Also selector, count, total
        (all matches in the page) and has_more, so pulling every ``<a href>``, an
        ``<input>`` CSRF token, or the ``<script src>`` list is one call rather
        than a snapshot plus a re-parse. The list is capped at 200 elements and
        each value is bounded. A malformed selector is invalid_params; an empty
        one is invalid_params too. There is no html or outerHTML field -- use
        web.dom.snapshot for the raw markup.
        """
        return _dump(analysis.web_dom_query(session_id, selector, limit=limit))

    @tools.tool(name="web.dom.snapshot")
    def web_dom_snapshot(session_id: str) -> dict[str, Any]:
        """Return the current page HTML, URL, and title.

        Answers with url, title, html and bytes (the full DOM length), plus
        truncated when the inline html is only a preview. When truncated, the
        complete document is written to a file and its path returned as
        html_path -- read that for the whole DOM rather than treating the
        inline html as complete. There is no content, dom or body field.
        """
        return _dump(analysis.web_dom_snapshot(session_id))

    @tools.tool(name="web.frames")
    def web_frames(session_id: str) -> dict[str, Any]:
        """List the page's frame tree: the main document and every (i)frame.

        Answers with frames, each carrying url, name, is_main (true for the main
        document) and parent_url (absent on the main frame), plus count, total
        and has_more. dom.snapshot returns only the main document and scripts/
        network are not grouped by frame, so this is the one view of the
        embedding structure -- a cross-origin iframe pulling remote content (a
        phishing embed, a third-party widget, a clickjack overlay) shows up here
        with its origin. The list is capped at 200 frames and each url/name is
        bounded. There is no html field -- use web.dom.snapshot for markup.
        """
        return _dump(analysis.web_frames(session_id))

    @tools.tool(name="web.forms")
    def web_forms(session_id: str) -> dict[str, Any]:
        """List the page's forms with their submit target and input controls.

        web.dom.query returns a flat element list and cannot say which inputs
        belong to which form, so a login/CSRF/search form -- its action URL, its
        method, and its fields including the hidden token -- was not
        reconstructible in one call. This groups each form with its controls.

        Answers with forms, each carrying action (the resolved submit URL),
        method (get/post), enctype, name and id, plus fields -- each field a
        {tag, type, name, value, hidden} record, where hidden is true for a
        type=hidden control (a CSRF token or a pre-filled id) so it stands out --
        and field_count, field_total and fields_truncated when a form had more
        controls than the per-form cap (200). Also count, total and has_more so a
        page capped at 100 forms is not read as all of them. Field values are
        bounded. There is no html field -- use web.dom.snapshot for raw markup.
        """
        return _dump(analysis.web_forms(session_id))

    @tools.tool(name="web.meta")
    def web_meta(session_id: str) -> dict[str, Any]:
        """The page head's identity: title/charset/base plus meta and link tags.

        web.dom.query returns a flat element list and web.dom.snapshot the raw
        HTML; neither assembles the head intelligence read first when triaging a
        page. This collects the document title, charset and any base href (which
        silently rebases every relative URL on the page), then every meta and
        link tag.

        Answers with url, title, charset, base, and two lists. metas holds each
        meta tag as {content, and whichever of name/property/http_equiv/charset
        it set} -- so og:*/twitter:* identity, a http_equiv=refresh client-side
        redirect, and a http_equiv=Content-Security-Policy all surface. links
        holds each link tag as {href, rel, type} -- canonical, manifest, icons,
        preload/prefetch. Also meta_count/meta_total/metas_truncated and
        link_count/link_total/links_truncated so a head capped at 200 of either
        is not read as all of them. Values are bounded; there is no html field --
        use web.dom.snapshot for raw markup.
        """
        return _dump(analysis.web_meta(session_id))

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

        Answers with path and entry_count, plus artifact_id when the HAR
        was registered, and truncated when oldest entries were dropped to fit
        the cap. There is no har, entries or artifact field. The log is
        conformant HAR 1.2 -- each entry carries startedDateTime, timings,
        cookies, queryString, cache and the captured request/response headers
        -- so DevTools Import HAR and HAR viewers accept it. response.content.size
        (decoded body bytes) and response.bodySize (on-wire body bytes) are
        populated from the captured sizes, with _transferSize on the entry.
        """
        return _dump(analysis.web_har_export(session_id))

    return tools.bindings
