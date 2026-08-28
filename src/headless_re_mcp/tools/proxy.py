"""Protocol-independent proxy.* tool definitions (mitmproxy interception)."""

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


def build_proxy_tools(analysis: AnalysisService) -> tuple[BoundTool, ...]:
    tools = ToolSetBuilder()

    @tools.tool(name="proxy.start")
    def proxy_start(
        session_id: str,
        host: str = "127.0.0.1",
        port: Annotated[int, Field(ge=1, le=65535)] = 8080,
    ) -> dict[str, Any]:
        """Start an HTTP(S) interception proxy bound to this session.

        Answers with running, host, port and endpoint. There is no ok,
        started or url field.
        """
        return _dump(analysis.proxy_start(session_id, host=host, port=port))

    @tools.tool(name="proxy.stop")
    def proxy_stop(session_id: str) -> dict[str, Any]:
        """Stop the session's interception proxy."""
        return _dump(analysis.proxy_stop(session_id))

    @tools.tool(name="proxy.status")
    def proxy_status(session_id: str) -> dict[str, Any]:
        """Report whether the proxy is running and how many flows it captured.

        Answers with running, and when running also host, port, flow_count
        retained_max, retained_bytes and retained_bytes_max. There is no
        count or flows field.         A session with no proxy answers running false
        and nothing else, which is not an empty capture.
        """
        return _dump(analysis.proxy_status(session_id))

    @tools.tool(name="proxy.stats")
    def proxy_stats(
        session_id: str,
        method: str = "",
        host: str = "",
        url_contains: str = "",
        content_type: str = "",
        status: Annotated[int, Field(ge=0, le=599)] = 0,
    ) -> dict[str, Any]:
        """Aggregate the capture into a triage summary instead of listing flows.

        Where proxy.flows lists individual exchanges, this answers "what is in
        this capture" on a busy target: it counts flows by HTTP method (methods),
        response status class 2xx/4xx/... (status_classes) and exact code
        (statuses), by host (hosts) and by media type (content_types, with the
        charset stripped so json does not split). hosts, content_types and
        statuses are count-descending ranked lists capped at 50, each with a
        matching hosts_truncated / content_types_truncated / statuses_truncated
        flag; methods and status_classes are small maps. Also answers with
        websocket_flows and body_omitted counts. captured is every flow in the
        ring, total is the counted subset and dropped is how many the ring already
        evicted. The same filters as proxy.flows (method exact verb; host,
        url_contains, content_type case-insensitive substrings; status exact code,
        0 means any; combined with AND) profile just one slice, echoed back as
        filter, so a filter narrows captured -> total visibly.
        """
        return _dump(
            analysis.proxy_stats(
                session_id,
                method=method,
                host=host,
                url_contains=url_contains,
                content_type=content_type,
                status=status,
            )
        )

    @tools.tool(name="proxy.endpoints")
    def proxy_endpoints(
        session_id: str,
        method: str = "",
        host: str = "",
        url_contains: str = "",
        content_type: str = "",
        status: Annotated[int, Field(ge=0, le=599)] = 0,
        normalize: bool = True,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """Collapse the capture into the target's API surface, grouped by route.

        proxy.stats counts flows by method/host/status/content-type but never by
        URL path, so it cannot answer "what endpoints does this app call". This
        groups the retained flows by (host, path) -- normalising id-like path
        segments (numeric, UUID, long hex, long mixed-alnum token) to {id} by
        default, so /users/1 and /users/2 fold into one /users/{id} route -- and
        reports each route's method set, request count, status-class mix,
        response content types and an example flow id to open with
        proxy.flow.get. It is the traffic-side analogue of an imports table: the
        backend routes the app depends on. Set normalize false to key on the
        exact path instead.

        Accepts the same filters as proxy.flows (method exact verb; host,
        url_contains, content_type case-insensitive substrings; status exact
        code, 0 means any; combined with AND), echoed back as filter. Answers
        with endpoints (host, path, count, methods, status_classes,
        content_types, example_id, plus websocket / has_query when seen), ranked
        by count then host then path and paged with count, total (distinct
        routes), offset and has_more; captured is every flow in the ring,
        dropped how many the ring evicted, and normalized whether {id} folding
        was applied. The list field is endpoints, not routes or results.
        """
        return _dump(
            analysis.proxy_endpoints(
                session_id,
                method=method,
                host=host,
                url_contains=url_contains,
                content_type=content_type,
                status=status,
                normalize=normalize,
                offset=offset,
                limit=limit,
            )
        )

    @tools.tool(name="proxy.search")
    def proxy_search(
        session_id: str,
        query: str,
        case_sensitive: bool = False,
        method: str = "",
        host: str = "",
        url_contains: str = "",
        content_type: str = "",
        status: Annotated[int, Field(ge=0, le=599)] = 0,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """Search captured request/response content for a literal string.

        Where proxy.flows and proxy.stats only see a flow's metadata, this reads
        the retained headers and bodies, so it answers which exchange actually
        carries a token, an endpoint, a marker or a leaked secret -- the
        traffic-side twin of static.search / r2.search. It is a literal
        substring search (case-insensitive unless case_sensitive is true) across,
        per flow, the response body, request body, response headers, request
        headers and the URL, in that priority order. The same filters as
        proxy.flows (method exact verb; host, url_contains, content_type
        case-insensitive substrings; status exact code, 0 means any; combined
        with AND) narrow the candidates first, echoed back as filter.

        Answers with matches, each carrying id, method, url, status,
        content_type, matched_in (locations that hit, priority-ordered),
        match_count (bounded occurrence tally), snippet (a one-line context
        window around the first hit) and snippet_from; plus count, total (the
        matching flows), offset and has_more for paging. captured is every flow
        in the ring, searched is how many candidates still had body/headers
        retained, and body_unavailable is how many were body-omitted or evicted
        so only their URL could be searched -- so a miss reads as "not present"
        rather than "not retained". The list field is matches, not flows or
        results, and there is no body field; fetch a hit's full body with
        proxy.flow.get by its id.
        """
        return _dump(
            analysis.proxy_search(
                session_id,
                query,
                case_sensitive=case_sensitive,
                method=method,
                host=host,
                url_contains=url_contains,
                content_type=content_type,
                status=status,
                offset=offset,
                limit=limit,
            )
        )

    @tools.tool(name="proxy.secrets")
    def proxy_secrets(
        session_id: str,
        kind: str = "",
        reveal: bool = False,
        method: str = "",
        host: str = "",
        url_contains: str = "",
        content_type: str = "",
        status: Annotated[int, Field(ge=0, le=599)] = 0,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
    ) -> dict[str, Any]:
        """Extract authentication and secret material from the capture.

        Where proxy.search finds a literal a caller already knows, this is the
        inverse -- it enumerates the credentials flowing through the capture
        without one: the Authorization/Proxy-Authorization request headers (with
        their scheme and, for a JWT bearer, the decoded header and registered
        claims), the common API-key and token request headers, the secret-ish URL
        query parameters, and the cookies from request Cookie and response
        Set-Cookie. It is the traffic analogue of a secret scan over a codebase.
        Identical secrets across flows collapse into one row whose count and hosts
        grow, so the reply is the set of distinct credentials, ranked by how
        widely each is used.

        Values are redacted to a first/last-few-chars preview by default -- with
        value_length and value_sha256 (a 16-hex prefix) so the same secret can be
        correlated across rows without exposing it; pass reveal true to return the
        full value for replay. Accepts the same filters as proxy.flows (method
        exact verb; host, url_contains, content_type case-insensitive substrings;
        status exact code, 0 means any), plus kind to keep only one category
        (authorization, api_key_header, query_param, cookie, set_cookie).

        Answers with secrets, each {kind, name, location (request/response),
        value, value_length, value_sha256, count (distinct flows it appeared in),
        hosts, example_id} -- plus scheme for an authorization, session and
        cookie_attributes for a cookie/set_cookie, jwt ({header, claims,
        claim_names}) for a decoded bearer, and value_clipped when the stored
        value hit the 4096-char cap. Ranked by count then kind then name and paged
        with count, total (distinct secrets), offset and has_more. captured is
        every flow in the ring, dropped how many it evicted, scanned how many
        flows still had headers retained and headers_unavailable how many were
        body-omitted or evicted so only their URL query could be read -- so a
        header secret's absence reads as "not present" versus "not retained".
        kind_counts tallies the categories and collect_capped marks the
        5000-distinct ceiling. The list field is secrets, not tokens or results;
        fetch a secret's flow with proxy.flow.get by its example_id.
        """
        return _dump(
            analysis.proxy_secrets(
                session_id,
                kind=kind,
                reveal=reveal,
                method=method,
                host=host,
                url_contains=url_contains,
                content_type=content_type,
                status=status,
                offset=offset,
                limit=limit,
            )
        )

    @tools.tool(name="proxy.flows")
    def proxy_flows(
        session_id: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        method: str = "",
        host: str = "",
        url_contains: str = "",
        content_type: str = "",
        status: Annotated[int, Field(ge=0, le=599)] = 0,
    ) -> dict[str, Any]:
        """List captured HTTP flows (method, url, status, content type), filterable.

        Answers with flows (id, seq, method, url, host, status, content_type),
        count, total, offset, has_more, dropped, and captured. body_omitted is set
        on a row whose request/response body was over the retain cap. A WebSocket
        flow (the 101 handshake) also carries websocket true and ws_messages,
        the retained frame count, plus ws_dropped once frames were evicted to
        stay under the per-flow retention cap; fetch the frames with
        proxy.flow.get or page them with proxy.ws.frames. The list
        field is flows, not items or requests, and the type column is
        content_type. dropped is how many the capture ring already evicted;
        a page that filled the limit is not the whole log. metadata_truncated
        marks bounded oversized summary fields.

        On a busy target, narrow the log instead of paging it all: method is an
        exact verb (GET, POST), host and url_contains and content_type are
        case-insensitive substrings (api.example.com, /login, json), and status
        is an exact code (0 means any). Filters combine with AND. When any filter
        is set the reply echoes it as filter, total becomes the number of matches
        (so offset/has_more page the matches), and captured still reports every
        flow in the ring -- so a small match set is never misread as a small
        capture. dropped always reflects ring eviction, filter or not.
        """
        return _dump(
            analysis.proxy_flows(
                session_id,
                offset=offset,
                limit=limit,
                method=method,
                host=host,
                url_contains=url_contains,
                content_type=content_type,
                status=status,
            )
        )

    @tools.tool(name="proxy.flow.get")
    def proxy_flow_get(
        session_id: str, flow_id: str, raw: bool = False
    ) -> dict[str, Any]:
        """Fetch one flow's headers and bodies (large bodies spill to an artifact).

        Answers with id, request (method, url, headers, size, body) and response
        (status, headers, size, body). Both bodies are served decoded of their
        HTTP content-encoding, so a gzip/br/deflate/zstd response comes back as
        the readable text it decompresses to -- not the compressed blob the wire
        carried, which is what proxy.search and the HAR export already read. The
        request body is included too (a POST's form/JSON/upload payload), which
        earlier flow fetches dropped. When a part was content-encoded the reply
        adds content_encoding (the header value) and decoded (false only when a
        malformed encoding could not be decompressed, so the bytes are still
        compressed). Pass raw=true to serve the exact on-wire bytes of both parts
        instead (decoded false), for inspecting the compression itself.

        A text body at most 200000 bytes is that part's body; a larger body -- or
        a binary body of any size (one holding a NUL byte or non-UTF-8 bytes, such
        as a captured .wasm, image or font) -- is that part's body_path with no
        body key, so the exact bytes survive for the static tools rather than
        being mangled into inline text; a spilled body is registered (artifact_id
        for the response, request_artifact_id for the request) so it is openable
        and reclaimable. There are no top-level headers or body fields. A
        WebSocket flow also carries websocket with the captured messages
        (direction sent or received, type text or binary, payload, payload_len,
        ts), count, total, offset, has_more, dropped and closed; a binary
        message's payload is base64 and an oversized one is cut and marked
        payload_truncated. dropped counts frames the per-flow retention cap
        evicted (a long socket cannot grow without bound). Only the first 500
        retained messages ride along here -- page the whole retained conversation
        with proxy.ws.frames.
        """
        return _dump(analysis.proxy_flow_get(session_id, flow_id, raw=raw))

    @tools.tool(name="proxy.ws.frames")
    def proxy_ws_frames(
        session_id: str,
        flow_id: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """Page the WebSocket frames captured for one flow.

        Answers with flow_id, url, frames (each direction sent or received, type
        text or binary, payload, payload_len, ts; a binary payload is base64 and
        an oversized one is cut and marked payload_truncated), count, total,
        offset, has_more, dropped and closed, plus close_code once the socket has
        closed. total is the retained frame count and dropped is how many the
        per-flow retention cap evicted, so the two together disclose a socket
        too long to keep whole. Unlike proxy.flow.get, which only inlines the
        first 500 retained messages, this walks the full retained conversation
        via offset/limit. A plain HTTP flow is rejected with invalid_state; a
        flow whose body was dropped is too_large.
        """
        return _dump(
            analysis.proxy_ws_frames(session_id, flow_id, offset=offset, limit=limit)
        )

    @tools.tool(name="proxy.ws.search")
    def proxy_ws_search(
        session_id: str,
        query: str,
        case_sensitive: bool = False,
        direction: str = "",
        flow_id: str = "",
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """Search captured WebSocket frames for a literal string, across flows.

        proxy.search reads HTTP bodies/headers/URLs but never the WebSocket
        conversation, and proxy.ws.frames needs a flow id and pages one socket at
        a time. Real-time protocols, auth tokens and RPC payloads ride the
        WebSocket, so this is the frame-level twin of proxy.search: a literal
        substring scan (case-insensitive unless case_sensitive) over the decoded
        content of every retained frame -- text and binary opcodes alike, so a
        JSON payload sent on a binary message is still found. Scope with flow_id
        (one socket) or direction (sent = client to server, received = server to
        client).

        Answers with matches, each carrying flow_id, url, frame_index (its
        position in that socket's retained frames, usable as a proxy.ws.frames
        offset), direction, type (text or binary), match_count (a bounded
        per-frame tally), snippet (a one-line context window) and payload_len/ts;
        plus count, total (matching frames), offset and has_more for paging.
        ws_flows is how many WebSocket flows were considered, frames_searched how
        many frames were scanned, and frames_capped / matches_capped disclose the
        50000-frame scan and 5000-match ceilings. The list field is matches (not
        frames or results). An unknown flow_id is not_found and a non-WebSocket
        one is invalid_state.
        """
        return _dump(
            analysis.proxy_ws_search(
                session_id,
                query,
                case_sensitive=case_sensitive,
                direction=direction,
                flow_id=flow_id,
                offset=offset,
                limit=limit,
            )
        )

    @tools.tool(name="proxy.replay")
    def proxy_replay(session_id: str, flow_id: str) -> dict[str, Any]:
        """Replay a captured request through the proxy.

        Answers with replayed and flow_id after the mitmproxy command has
        actually run, not merely after it was queued on the proxy thread.
        """
        return _dump(analysis.proxy_replay(session_id, flow_id))

    @tools.tool(name="proxy.export_har")
    def proxy_export_har(
        session_id: str,
        method: str = "",
        host: str = "",
        url_contains: str = "",
        content_type: str = "",
        status: Annotated[int, Field(ge=0, le=599)] = 0,
    ) -> dict[str, Any]:
        """Export captured flows to a spec-compliant HAR 1.2 artifact, filterable.

        Answers with path, entry_count and captured. There is no har, output or
        artifact field. path is the file; looking for har after a successful
        export reads as a missing capture. The file is valid HAR 1.2 that a HAR
        viewer or Chrome DevTools can import: each entry carries request and
        response headers, query string, request/response cookies (parsed from
        the Cookie and Set-Cookie headers), form postData.params (URL-encoded
        and multipart request bodies), a bounded body preview, status and
        real timings for every flow still retained. A WebSocket flow's frames
        ride along as DevTools' _webSocketMessages (with _resourceType
        websocket), so a captured socket re-imports into DevTools.

        The same filters as proxy.flows narrow what is exported instead of paging
        it: method is an exact verb, host and url_contains and content_type are
        case-insensitive substrings, status is an exact code (0 means any), and
        they combine with AND. When any filter is set the reply echoes it as
        filter and entry_count is the number of matching flows written; captured
        always reports every flow in the ring, so entry_count reads as "exported
        N of captured M" and a narrow export is never misread as a small capture.
        No filter exports the whole retained capture, as before.
        """
        return _dump(
            analysis.proxy_export_har(
                session_id,
                method=method,
                host=host,
                url_contains=url_contains,
                content_type=content_type,
                status=status,
            )
        )

    @tools.tool(name="proxy.ca.install_android")
    def proxy_ca_install_android(session_id: str, serial: str) -> dict[str, Any]:
        """Push the mitmproxy CA certificate onto a device via adb (best-effort).

        Answers with pushed_to and note. There is no installed, ok or path
        field. Envelope success means the PEM landed in device tmp, not that
        the system store trusts it.
        """
        return _dump(analysis.proxy_ca_install_android(session_id, serial))

    return tools.bindings
