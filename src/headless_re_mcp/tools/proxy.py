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
        ssl_insecure: bool = False,
    ) -> dict[str, Any]:
        """Start an HTTP(S) interception proxy bound to this session.

        Answers with running, host, port, endpoint and ssl_insecure. There is
        no ok, started or url field.

        Set ssl_insecure to intercept HTTPS to a server whose certificate does
        not chain to a public CA -- self-signed, private-CA or pinned, which is
        the common case for the apps and dev servers this tool targets. It maps
        to mitmproxy's --ssl-insecure (skip verification of the upstream
        server's certificate only; the proxy still presents its own CA to the
        client). With it off, such an upstream fails as a 502 with no flow
        recorded, so the capture looks empty rather than blocked.
        """
        return _dump(
            analysis.proxy_start(
                session_id, host=host, port=port, ssl_insecure=ssl_insecure
            )
        )

    @tools.tool(name="proxy.stop")
    def proxy_stop(session_id: str) -> dict[str, Any]:
        """Stop the session's interception proxy."""
        return _dump(analysis.proxy_stop(session_id))

    @tools.tool(name="proxy.status")
    def proxy_status(session_id: str) -> dict[str, Any]:
        """Report whether the proxy is running and how many flows it captured.

        Answers with running, and when running also host, port, flow_count
        retained_max, retained_bytes and retained_bytes_max. There is no
        count or flows field. A session with no proxy answers running false
        and nothing else, which is not an empty capture.
        """
        return _dump(analysis.proxy_status(session_id))

    @tools.tool(name="proxy.clear")
    def proxy_clear(session_id: str) -> dict[str, Any]:
        """Empty the capture without stopping the proxy.

        The proxy keeps listening on the same port and its CA stays installed;
        only the flows recorded so far (their summaries, retained bodies and
        WebSocket frames) are dropped. This is the triage move: clear the noise
        from setup/login, reproduce the one action you care about, then read a
        clean proxy.flows -- instead of paging past everything or stop/starting
        and losing the port and CA setup. Answers with cleared (how many flow
        summaries were discarded) and running true. After this proxy.flows and
        proxy.stats report only newly captured traffic, and dropped restarts
        from the cleared baseline. It errors invalid_state when no proxy is
        running for the session.
        """
        return _dump(analysis.proxy_clear(session_id))

    @tools.tool(name="proxy.stats")
    def proxy_stats(session_id: str) -> dict[str, Any]:
        """Aggregate the whole capture into a triage summary.

        proxy.flows is a paged listing; this folds the ring once so a caller can
        see what a large capture holds before deciding what to filter for.
        Answers with total, by_method (a count per HTTP method), by_status_class
        (a count per 2xx/3xx/4xx/5xx; flows with no status yet are not counted
        here and show up in no_status instead), top_hosts and top_content_types
        (each a list of {host|content_type, count}, ranked and capped at 50 with
        host_count/content_type_count giving the distinct totals so a trimmed
        list is visible), and the counts failed, websockets, with_request_body
        and no_status. dropped is the ring-eviction count, same as proxy.flows.
        There is no flows, items or requests field here -- use proxy.flows to
        list, this to summarize.
        """
        return _dump(analysis.proxy_stats(session_id))

    @tools.tool(name="proxy.endpoints")
    def proxy_endpoints(
        session_id: str,
        limit: Annotated[int, Field(ge=1, le=1000)] = 200,
    ) -> dict[str, Any]:
        """Fold the capture into distinct endpoints -- the app's API surface.

        proxy.flows is a per-request listing (every hit to /api/user is its own
        row) and proxy.stats aggregates only to the host level; neither answers
        "which distinct endpoints did this app talk to?" -- the site map you
        want when reversing a backend. This folds the ring into distinct
        method+host+path keys, with the query string stripped so /api/user?id=1
        and ?id=2 are one endpoint.

        Answers with endpoints, each carrying method, host, path, count (how many
        times it was hit), statuses (the distinct status codes seen, sorted;
        empty when every hit failed or is in flight), failed (how many hits had
        no response) and websocket (true when any hit was a WebSocket upgrade).
        Ranked by count, busiest first. Also count (endpoints returned), total
        (distinct endpoints), has_more (more than the limit exist), flows_folded
        (how many flows were folded) and dropped (ring evictions). There is no
        url or query field on a row -- the path is query-stripped by design; use
        proxy.flows or proxy.search to reach a specific request. It errors
        invalid_state when no proxy is running for the session.
        """
        return _dump(analysis.proxy_endpoints(session_id, limit=limit))

    @tools.tool(name="proxy.search")
    def proxy_search(
        session_id: str,
        query: str,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        include_bodies: bool = True,
    ) -> dict[str, Any]:
        """Search the whole capture for a case-insensitive substring.

        proxy.flows and proxy.stats find a flow by its metadata; neither answers
        "which request or response actually contains this token / endpoint /
        error string?" without pulling every flow with proxy.flow.get and
        reading it by hand. This greps the capture in one call and, per matching
        flow, says where the needle hit.

        Answers with matches, each carrying id, seq, method, url, host, status
        and where -- a list drawn from url, request_headers, response_headers,
        request_body, response_body and websocket naming every place the query
        was found in that flow. Also count (matches returned), total (all
        matching flows), scanned (flows examined), bodies_scanned,
        bodies_omitted (flows whose body was over the retain cap or evicted, so
        their bodies could not be searched), include_bodies, truncated (more
        matches exist beyond the limit) and dropped (ring evictions), so a
        partial result is never read as the whole answer.

        Bodies are the content-encoding-decoded payloads -- the same bytes
        proxy.flow.get returns, so a gzip/br/deflate/zstd response is searched
        decoded, not compressed. Pass a flow_id from a match to proxy.flow.get to
        read the surrounding request/response. Set include_bodies=false to scan
        only url/headers/WebSocket frames for a cheaper metadata pass. An empty
        query is rejected as invalid_params.
        """
        return _dump(
            analysis.proxy_search(
                session_id, query, limit=limit, include_bodies=include_bodies
            )
        )

    @tools.tool(name="proxy.flows")
    def proxy_flows(
        session_id: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        method: str | None = None,
        host: str | None = None,
        url_contains: str | None = None,
        status: Annotated[int | None, Field(ge=100, le=599)] = None,
    ) -> dict[str, Any]:
        """List captured HTTP flows (method, url, status, content type).

        Answers with flows (id, seq, method, url, host, status, content_type),
        count, total, offset, has_more, and dropped. A row that carried a
        request payload is flagged has_request_body, so flow.get can be pointed
        at the ones whose request body is the target. body_omitted is set on a
        row whose request/response body was over the retain cap. A WebSocket
        upgrade is flagged is_websocket with a websocket_messages count, so
        flow.get can be pointed at the sockets whose frames are the target.
        A flow whose upstream failed (connection refused, DNS failure, reset,
        a TLS handshake ssl_insecure cannot save) is flagged failed with an
        error message and a null status, so an attempted-but-failed request is
        recorded rather than vanishing from an otherwise-empty capture.
        The list field is flows, not items or requests, and the type column is
        content_type. dropped is how many the capture ring already evicted;
        a page that filled the limit is not the whole log. metadata_truncated
        marks bounded oversized summary fields.

        Narrow a large capture with the optional filters, applied before
        pagination: method (exact, case-insensitive), host and url_contains
        (case-insensitive substrings), and status (exact code). When any filter
        is set the reply also carries filtered true and unfiltered_total (the
        whole capture's size), and total/count/has_more describe the matched
        subset -- so a small match is not read as a small capture. A status
        filter never matches a failed or in-flight flow (one with a null
        status).
        """
        return _dump(
            analysis.proxy_flows(
                session_id,
                offset=offset,
                limit=limit,
                method=method,
                host=host,
                url_contains=url_contains,
                status=status,
            )
        )

    @tools.tool(name="proxy.flow.get")
    def proxy_flow_get(session_id: str, flow_id: str) -> dict[str, Any]:
        """Fetch one flow's headers and bodies (large bodies spill to an artifact).

        Answers with id, request and response. Each side carries method/url or
        status, headers, and size, plus its body. The request body (POST
        params, a JSON payload) is returned, not just the response. On each
        side a body at most 200000 bytes is that side's body; anything larger
        is that side's body_path and there is no body key. There are no
        top-level headers or body fields.

        Bodies are content-encoding decoded: a gzip/br/deflate/zstd response
        comes back as the real payload (the JSON), not compressed bytes, and
        size is the decoded length -- not the Content-Length header. When a
        side arrived compressed, that side also carries content_encoding (the
        wire encoding) so the decode is visible.

        For a WebSocket upgrade the reply also carries websocket with messages
        (each from_client, size, text, truncated and binary when non-UTF-8),
        returned, message_count and truncated -- the duplex frames that follow
        the 101, which are not in the response body.

        A flow whose upstream failed carries failed and error (the connection
        error) with an empty response, so flow.get on it reads as "the upstream
        failed", not "the response was empty".
        """
        return _dump(analysis.proxy_flow_get(session_id, flow_id))

    @tools.tool(name="proxy.replay")
    def proxy_replay(session_id: str, flow_id: str) -> dict[str, Any]:
        """Replay a captured request through the proxy.

        Answers with replayed and flow_id after the mitmproxy command has
        actually run, not merely after it was queued on the proxy thread.
        """
        return _dump(analysis.proxy_replay(session_id, flow_id))

    @tools.tool(name="proxy.export_har")
    def proxy_export_har(session_id: str) -> dict[str, Any]:
        """Export the captured flows to a conformant HAR 1.2 artifact.

        Answers with path, entry_count, truncated (true when oldest entries were
        dropped to fit the cap) and size, plus artifact_id when registered.
        There is no har, output or artifact field -- path is the file. Each
        entry is valid HAR 1.2: request and response headers (auth, cookies,
        content-type, CORS, with duplicates preserved), the parsed query string,
        per-flow start time and timings, status and the decoded response size,
        so the log loads in DevTools' Import HAR and other HAR viewers. Bodies
        are not inlined (a capture can be huge); use proxy.flow.get for a body.
        """
        return _dump(analysis.proxy_export_har(session_id))

    @tools.tool(name="proxy.ca.install_android")
    def proxy_ca_install_android(session_id: str, serial: str) -> dict[str, Any]:
        """Push the mitmproxy CA certificate onto a device via adb (best-effort).

        Answers with pushed_to and note. There is no installed, ok or path
        field. Envelope success means the PEM landed in device tmp, not that
        the system store trusts it.
        """
        return _dump(analysis.proxy_ca_install_android(session_id, serial))

    return tools.bindings
