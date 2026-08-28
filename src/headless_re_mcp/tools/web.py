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

        Answers with requests (url, method, status, resourceType), count,
        total, offset, has_more, and dropped so a page that filled the
        limit is not read as the whole capture, and ring eviction is
        visible. metadata_truncated marks bounded oversized request fields.
        There is no type field.
        """
        return _dump(analysis.web_network_list(session_id, offset=offset, limit=limit))

    @tools.tool(name="web.network.stats")
    def web_network_stats(
        session_id: str,
        top: Annotated[int, Field(ge=1, le=50)] = 10,
    ) -> dict[str, Any]:
        """Aggregate the captured network requests into a one-look summary.

        Folds the same rows web.network.list pages, so it needs no export.
        Answers with total and dropped (how many the ring already evicted -- a
        nonzero dropped means the tallies cover only the retained window),
        pending (requests still awaiting a response, with a null status),
        methods (a method->count map, busiest first), status_classes
        (2xx/3xx/4xx/5xx and pending), resource_types (document/script/xhr/
        image/... -> count), top_hosts and top_mime_types (each a ranked list
        capped at top, default 10) with host_count and mime_type_count behind
        them. host is parsed from each url; mime_type is the bare media type
        (the charset tail is dropped). There is no requests or items field here
        -- use web.network.list to read individual rows.
        """
        return _dump(analysis.web_network_stats(session_id, top=top))

    @tools.tool(name="web.network.failed")
    def web_network_failed(
        session_id: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """List the requests the browser reported as failed or blocked.

        The triage cut of the capture that web.network.list buries and
        web.network.stats only counts: requests that never completed. A row
        lands here when CDP fires Network.loadingFailed for it -- a DNS or TLS
        error, a connection reset, a CORS or mixed-content block, an ad/tracker
        killed by an extension, or a navigation the user aborted. Reading the
        failures directly is how you spot a blocked C2 beacon or a
        content-blocked exfil attempt without scrolling the whole log.

        Answers with requests (each an entry carrying url, method, resourceType,
        status -- usually null since no response arrived -- error_text (the CDP
        errorText, e.g. net::ERR_NAME_NOT_RESOLVED), canceled (true when it was
        aborted rather than errored) and blocked_reason when CDP gave one, e.g.
        mixed-content or a CSP violation), count, total, offset, has_more and
        dropped (rows the capture ring already evicted). A request still in
        flight is not failed and does not appear here; use web.network.list for
        the full set.
        """
        return _dump(analysis.web_network_failed(session_id, offset=offset, limit=limit))

    @tools.tool(name="web.redirects")
    def web_redirects(
        session_id: str,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """Reconstruct the redirect chains the page's requests went through.

        A redirect is invisible in web.network.list: CDP reuses one requestId
        across the whole chain and overwrites the row on each hop, so only the
        final landing survives there and every 3xx in between is lost. This
        captures those hops (from the redirectResponse CDP attaches to each new
        hop) and folds them back into ordered chains -- which is what you need to
        follow an OAuth dance, unmask a tracker's bounce chain, or catch a login
        flow that drops from https back to http mid-redirect.

        Answers with chains (ranked longest first), count, total, truncated,
        dropped (hops the capture ring evicted) and an aggregate (total_chains,
        total_hops, downgrades, cross_origin, max_length). Each chain carries
        requestId, start_url, final_url, length (hop count), statuses (the 3xx
        codes in order), three security flags -- downgrade (an https hop went to
        http), cross_host and cross_origin (the target left the starting
        host/origin) -- and hops, each with from_url, status, to_url, location
        (the Location header) and resource_type, with hops_truncated when a chain
        exceeded the per-chain hop cap. A request that was never redirected does
        not appear here; use web.network.list for the full request set.
        """
        return _dump(analysis.web_redirects(session_id, limit=limit))

    @tools.tool(name="web.network.headers")
    def web_network_headers(session_id: str, request_id: str) -> dict[str, Any]:
        """Read one request's captured request and response headers.

        web.network.list/failed keep the rows lean (url, method, status); this
        is where the headers live. The in-browser view proxy.security_headers /
        proxy.cookies cannot give you when traffic never crossed the proxy (a
        service worker, a WebSocket handshake, an HTTP/2 push): the Authorization
        or Cookie a request carried, the Set-Cookie, Content-Type, Location or
        Content-Security-Policy a response returned. Captured live off CDP for
        every request the page made.

        Answers with request_id, url, method, status, request_headers and
        response_headers (each a name->value map, repeated headers already folded
        by CDP), request_header_count, response_header_count, and
        headers_truncated (true when the header count, a value, or the whole map
        hit its bound). response_headers is empty for a request that never got a
        response (still in flight, or failed -- see web.network.failed). An
        unknown request_id is not_found.
        """
        return _dump(analysis.web_network_headers(session_id, request_id))

    @tools.tool(name="web.network.post_data")
    def web_network_post_data(session_id: str, request_id: str) -> dict[str, Any]:
        """Read one request's captured POST/PUT body (what the page sent up).

        web.network.get fetches the response body; this is the request side --
        the data the page uploaded, which is where credentials, telemetry and
        exfil actually ride. Captured live off CDP as each request was sent, so
        it sees form posts, JSON API calls and beacons even when nothing crossed
        the proxy. The body is what CDP exposed inline: large uploads are already
        capped by CDP and bounded again here.

        Answers with request_id, url, method, has_post_data (CDP saw a body on
        this request), content_type (from the request's Content-Type header when
        present), data (the captured body, possibly empty when CDP kept none
        inline even though has_post_data is true), size (bytes captured) and
        truncated (the body hit the capture bound). A request the page made with
        no body comes back has_post_data false with an empty data. An unknown
        request_id is not_found.
        """
        return _dump(analysis.web_network_post_data(session_id, request_id))

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

    @tools.tool(name="web.websockets")
    def web_websockets(
        session_id: str,
        limit: Annotated[int, Field(ge=1, le=256)] = 100,
        frames_limit: Annotated[int, Field(ge=1, le=500)] = 50,
    ) -> dict[str, Any]:
        """List captured WebSocket connections and their frames.

        Where web.network.list stops at the HTTP requests, this exposes the
        WebSocket traffic a modern app rides -- the live channel a chat, a
        trading feed, or a C2 uses -- captured over CDP from the page itself
        (the in-browser counterpart to what proxy.flows sees on the wire). Each
        connection is keyed by the request that upgraded it and carries its
        frames, so you can read the protocol without a proxy in the path.

        Answers with websockets, count, total, has_more and connections_dropped
        (the connection ring evicted the oldest). Each connection carries
        requestId, url, closed, error (when the socket errored), frames_sent,
        frames_received, bytes_sent, bytes_received, and frames -- the newest
        frames_returned of frames_retained kept (a busy socket's frame ring
        drops the oldest, counted in frames_dropped). Each frame carries
        direction (sent or received), opcode (1 text, 2 binary, 8 close, 9
        ping, 10 pong), data (the payload, truncated with truncated=true past
        the per-frame cap) and size (the original payload length). Binary frame
        data arrives base64-encoded from CDP and is not decoded here.
        """
        return _dump(
            analysis.web_websockets(
                session_id, limit=limit, frames_limit=frames_limit
            )
        )

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

    @tools.tool(name="web.dom.snapshot")
    def web_dom_snapshot(session_id: str) -> dict[str, Any]:
        """Return the current page HTML, URL, and title.

        Answers with url, title and html, plus truncated when the HTML was
        cut at the buffer. There is no content, dom or body field.
        """
        return _dump(analysis.web_dom_snapshot(session_id))

    @tools.tool(name="web.storage")
    def web_storage(session_id: str) -> dict[str, Any]:
        """Read the page's Web Storage (localStorage and sessionStorage).

        Where web.cookies reads the cookie jar, this reads the two key/value
        stores the page script owns -- often where a SPA stashes its auth token,
        feature flags, or a cached user profile.

        Answers with url and origin, then for each area a list of {key, value,
        value_truncated} plus a count and a *_truncated flag: local_storage /
        local_storage_count / local_storage_truncated and the session_storage
        trio likewise. A value clipped at the per-value cap carries
        value_truncated true; the *_truncated flag means the key list itself was
        capped. Each area is read defensively: an opaque origin (a sandboxed or
        data: page) makes the store throw, and that surfaces as
        local_storage_error / session_storage_error with the browser's error
        name, the other area still returning its entries.
        """
        return _dump(analysis.web_storage(session_id))

    @tools.tool(name="web.cookies")
    def web_cookies(session_id: str) -> dict[str, Any]:
        """Read the browser context's cookie jar (all cookies, all domains).

        Where web.storage reads the page's key/value stores, this reads the
        cookie jar -- session ids, CSRF tokens, tracking cookies -- across every
        domain the context has visited, not just the current page.

        Answers with url (the active page), cookies, count, total and truncated.
        Each cookie carries name, value (clipped with value_truncated when long),
        domain, path, http_only, secure, same_site (Strict/Lax/None or null when
        unset), expires (a Unix timestamp, or null for a session cookie) and
        session (true when it has no persistent expiry). http_only false plus
        secure false on a session id is the classic weakness worth flagging.
        Read truncated: a large jar is capped.
        """
        return _dump(analysis.web_cookies(session_id))

    @tools.tool(name="web.forms")
    def web_forms(session_id: str) -> dict[str, Any]:
        """List the page's HTML forms and their input fields.

        The auth/exfil triage view: where does this page POST, and what does it
        collect. Answers with url, forms, count, total and truncated. Each form
        carries name, id, action (the resolved absolute submit URL),
        action_external (the action posts to a different host than the page --
        worth a look), method, enctype, field_count, has_password, has_file, a
        fields list and fields_truncated. Each field carries tag, type, name,
        required and value -- value is captured only for hidden and submit
        inputs (CSRF tokens, action markers), never for password or text inputs,
        which come back with an empty value. Read truncated: a page with many
        forms is capped.
        """
        return _dump(analysis.web_forms(session_id))

    @tools.tool(name="web.performance")
    def web_performance(session_id: str) -> dict[str, Any]:
        """Read the page's load timing from the Navigation/Resource Timing API.

        The in-page view of how the navigation actually loaded, read straight
        from the browser's own performance entries rather than reconstructed
        from captured events. Where web.network.stats counts requests, this
        breaks the main navigation into phases (DNS, connect, TLS, time-to-first-
        byte, response, DOM ready, load) and surfaces the slowest subresources --
        the triage a slow or beaconing page needs, and a fingerprint (redirect
        count, transfer vs decoded size) for an interstitial or a padded payload.

        Answers with url, navigation (null when the page reports no navigation
        entry, e.g. about:blank), resources (slowest-first, capped), resource_
        count, resource_total and truncated. navigation carries type
        (navigate/reload/back_forward), redirect_count, the phase durations in ms
        (dns_ms, connect_ms, tls_ms, ttfb_ms, response_ms, dom_interactive_ms,
        dom_content_loaded_ms, load_ms) and the byte sizes (transfer_size,
        encoded_body_size, decoded_body_size). Each resource carries url,
        initiator_type, duration_ms and transfer_size.
        """
        return _dump(analysis.web_performance(session_id))

    @tools.tool(name="web.meta")
    def web_meta(session_id: str) -> dict[str, Any]:
        """Read the page head's identity: title, charset, meta tags, link rels.

        The phishing/redirect/CSP triage view -- what the page claims to be and
        where it points -- without dumping the whole DOM. Answers with url,
        title, charset, lang, base, plus metas, meta_count, meta_total,
        metas_truncated and links, link_count, link_total, links_truncated. Each
        meta row carries name, property (og:/twitter: cards), http_equiv, charset
        and content; each link row carries rel (canonical/icon/manifest/
        preconnect), href (resolved absolute) and type. refresh is the decoded
        meta-refresh redirect ({delay, url}) or null -- a meta refresh to another
        origin is a classic cloaked redirect. csp is the Content-Security-Policy
        declared via meta, or null. Read metas_truncated/links_truncated: a head
        stuffed with hundreds of tags is capped.
        """
        return _dump(analysis.web_meta(session_id))

    @tools.tool(name="web.links")
    def web_links(session_id: str) -> dict[str, Any]:
        """Map the page's outbound references: anchors and subresource origins.

        The exfil/third-party triage view -- where does this page point and whose
        code and assets does it pull -- built from the live DOM with URLs already
        resolved to absolute by the browser. Answers with url, then anchors,
        anchor_count, anchor_total, anchors_truncated; resources, resource_count,
        resource_total, resources_truncated; and origins, origin_count,
        external_origin_count. Each anchor carries href, text, target, rel, host
        and external (the host differs from the page's -- the outbound links worth
        a look). Each resource carries url, kind (script/link/img/iframe/source/
        video/audio/embed/object), host and external. origins rolls anchors and
        subresources up into distinct scheme://host entries ranked by count, each
        with origin, host, count and external, so a page loading script from a
        stranger's origin stands out. Read the truncated flags: a content-heavy
        page caps the anchor and resource lists.
        """
        return _dump(analysis.web_links(session_id))

    @tools.tool(name="web.frames")
    def web_frames(session_id: str) -> dict[str, Any]:
        """List the page's frame tree: the main document and every iframe.

        The embedded-content view -- an ad frame, a third-party payment iframe, a
        hidden clickjacking overlay, a sandboxed widget -- each of which loads and
        runs code the top page did not write. Answers with url (the main frame),
        frames, count, total, truncated and cross_origin_count (child frames whose
        host differs from the main document -- the third-party embeds worth a
        look). Each frame carries url, name (the frame/iframe name attribute),
        is_main (the top document), parent_url (the frame that hosts it, or null
        for the main frame), depth (0 for the main frame, deeper for nested
        iframes), host and external (its host differs from the main document's).
        The list is bounded; read truncated on an ad-heavy page.
        """
        return _dump(analysis.web_frames(session_id))

    @tools.tool(name="web.dom.query")
    def web_dom_query(
        session_id: str,
        selector: str,
        limit: Annotated[int, Field(ge=1, le=100)] = 50,
    ) -> dict[str, Any]:
        """Query the live DOM by CSS selector and return the matching elements.

        Targeted extraction where web.dom.snapshot dumps the whole page: pass a
        CSS selector (this runs document.querySelectorAll, not arbitrary JS) to
        pull just the nodes you want -- a login form's inputs, every script tag,
        the elements carrying a data-* attribute, a specific class. Answers with
        selector, elements (bounded), count, total (all matches on the page) and
        truncated (more matched than were returned). Each element carries tag,
        text (its trimmed textContent), attributes (a bounded name->value map),
        attr_count and html (a bounded outerHTML preview). An invalid selector is
        refused as invalid_params.
        """
        return _dump(analysis.web_dom_query(session_id, selector, limit=limit))

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
        """Export captured network activity to a spec-valid HAR 1.2 artifact.

        Answers with path, entry_count and truncated, plus artifact_id when
        the HAR was registered. truncated is true when the oldest entries were
        dropped to keep the file under the capture cap. There is no har,
        entries or artifact field.
        """
        return _dump(analysis.web_har_export(session_id))

    return tools.bindings
