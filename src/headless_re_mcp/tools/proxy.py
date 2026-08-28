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

        Each proxy holds a thread, a bound port, and captured-body buffers; at
        most 8 may run at once, so a start past that ceiling is invalid_state
        (stop one with proxy.stop first) rather than an accumulating background
        thread. Answers with running, host, port and endpoint. There is no ok,
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
        count or flows field. A session with no proxy answers running false
        and nothing else, which is not an empty capture.
        """
        return _dump(analysis.proxy_status(session_id))

    @tools.tool(name="proxy.flows")
    def proxy_flows(
        session_id: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        url_filter: str = "",
        content_type_filter: str = "",
        failed_only: bool = False,
    ) -> dict[str, Any]:
        """List captured HTTP flows (method, url, status, content type).

        Answers with flows (id, seq, method, url, host, status, content_type,
        started_at as an epoch time, and remote_ip/remote_port -- the upstream
        server the flow actually reached, the C2/CDN host behind the domain,
        present once a response arrived over a real connection), count, total,
        offset, has_more, and
        dropped. body_omitted is set on a
        row whose request/response body was over the retain cap. A flow that
        failed before any response (upstream reset, TLS handshake failure,
        timeout) has status null and carries failed with error_text, so a
        failed connection is not read as one still in flight. The list
        field is flows, not items or requests, and the type column is
        content_type. dropped is how many the capture ring already evicted;
        a page that filled the limit is not the whole log. metadata_truncated
        marks bounded oversized summary fields. Three filters narrow a busy
        capture, all applied before paging (so total is the match count) and
        combined with AND; dropped still counts every eviction. url_filter keeps
        only flows whose url contains that substring (case-insensitive).
        content_type_filter keeps only flows whose content_type contains that
        substring (case-insensitive) -- pass json to pull API traffic out from
        under image/script/css responses (substring, since the value is the raw
        header like "application/json; charset=utf-8"). failed_only true keeps
        only flows that failed before any response, the fastest way to surface
        the TLS-handshake/reset failures a pinned mobile app produces behind the
        proxy instead of reading each row's failed field.
        """
        return _dump(
            analysis.proxy_flows(
                session_id,
                offset=offset,
                limit=limit,
                url_filter=url_filter,
                content_type_filter=content_type_filter,
                failed_only=failed_only,
            )
        )

    @tools.tool(name="proxy.hosts")
    def proxy_hosts(
        session_id: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        host_filter: str = "",
    ) -> dict[str, Any]:
        """Roll the capture up per host: who the target talked to, at a glance.

        proxy.flows is one row per request; this aggregates the retained flows
        by host so the question "which hosts did this app reach, how often, did
        any fail" is one call instead of a page-by-page walk -- the way a
        C2/CDN/telemetry endpoint stands out in a busy capture. Answers with
        hosts, count, total (distinct hosts after the filter), offset, has_more,
        total_flows (flows aggregated, the whole retained capture), and dropped
        (ring evictions, same as proxy.flows). Each hosts row is {host, flows
        (request count), failed (flows that never got a response), methods
        (sorted), content_types (sorted response MIME types, the part before
        ';'), statuses (a {code: count} map)} plus remote_ips (the upstream
        IPs the host resolved to) when any were seen and truncated when one of
        that row's sets overflowed its cap (a server answering with unbounded
        variety). Rows are ordered by flow count (busiest first), then host.
        host_filter keeps only hosts whose name contains that substring
        (case-insensitive), applied before paging so total is the match count;
        total_flows still counts the whole capture. The list field is hosts, and
        each row's request count is flows. For the individual requests to one
        host use proxy.flows with url_filter.
        """
        return _dump(
            analysis.proxy_hosts(
                session_id, offset=offset, limit=limit, host_filter=host_filter
            )
        )

    @tools.tool(name="proxy.search")
    def proxy_search(
        session_id: str,
        query: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        url_filter: str = "",
        content_type_filter: str = "",
    ) -> dict[str, Any]:
        """Grep the whole capture -- url, headers, decoded bodies -- for a string.

        proxy.flows filters on the summary (url, content-type, failed); the one
        thing it cannot answer is "which flow *contains* this value" -- the token
        that leaked, the api key echoed back in a response, the id a request
        carried in its body -- which otherwise means a proxy.flow.get per flow.
        This searches each retained flow's url, request/response headers and
        decoded request/response bodies for query and returns only the flows that
        matched. Bodies are decoded (gzip/deflate/zstd) the same bounded way
        proxy.flow.get decodes them, so a hit inside a compressed response is
        found. Answers with query, flows, count, total (matching flows after the
        pre-filters), offset, has_more, dropped (ring evictions, same as
        proxy.flows) and scan_capped (true when the decoded-bytes budget was hit
        and later flows went unsearched). Each flows row is {id, seq, method,
        url, host, status, matches} plus body_omitted when the flow's body was
        over the retain cap so only its url was searched. matches is a list of
        {where, count, snippet}: where is one of url, request_headers,
        request_body, response_headers, response_body; count is the occurrences
        in that location; snippet is the first hit with surrounding context,
        ellipsis-marked when clipped from a larger body. The match is
        case-insensitive substring (find a host or token regardless of case).
        url_filter and content_type_filter narrow which flows are searched
        (case-insensitive substring, combined with AND), before the body scan, so
        a targeted search on a busy capture stays cheap; total is then the count
        of flows that both passed the filters and matched the query. The list
        field is flows and the per-location field is matches; to read a matched
        flow in full use proxy.flow.get with its id. A missing or empty query is
        invalid_params, as is one over 1024 characters.
        """
        return _dump(
            analysis.proxy_search(
                session_id,
                query,
                offset=offset,
                limit=limit,
                url_filter=url_filter,
                content_type_filter=content_type_filter,
            )
        )

    @tools.tool(name="proxy.secrets")
    def proxy_secrets(
        session_id: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        url_filter: str = "",
        content_type_filter: str = "",
        name_filter: str = "",
        include_generic: bool = False,
    ) -> dict[str, Any]:
        """Find credentials that crossed the wire: keys/tokens in the live capture.

        The dynamic-traffic counterpart to js.secrets and apk.secrets. Those scan
        a file at rest; this scans what the target actually sent and received --
        an Authorization or Cookie header, an OAuth token riding a redirect url,
        an api key echoed back in a JSON response -- credentials that are minted
        at runtime and never appear in the static bundle. It runs the same shared
        detector table (AWS/Google/GitHub/Slack/Stripe keys, JWTs, private-key
        headers, basic-auth urls, ...) over each retained flow's url,
        request/response headers and decoded request/response bodies
        (gzip/deflate/zstd, bounded exactly like proxy.search). Deduplicated by
        (detector, value). Answers with secrets, count, total (distinct findings
        after name_filter), offset, has_more, detectors (the distinct detector
        names present), dropped (ring evictions, same as proxy.flows) and
        scan_capped (the distinct-findings ceiling or the shared decoded-byte scan
        budget was hit). Each secrets row is {detector, value (the matched
        credential, clipped with value_truncated when long), count (occurrences
        across the capture), where (sorted distinct locations: url,
        request_headers, response_headers, request_body, response_body -- a hit in
        request_headers reads as the client sending it, one in response_body as
        the server leaking it), first_flow ({id, seq, url, where}, the flow to hand
        proxy.flow.get)}. url_filter and content_type_filter pre-narrow which flows
        are scanned (case-insensitive substring, AND-combined), bounding decode
        work like proxy.search. name_filter then keeps only findings whose detector
        or value contains that substring (case-insensitive), applied before paging
        so total is the match count. include_generic adds a high-entropy
        base64/hex catch-all for a value no specific detector claimed (off by
        default; it trades recall for precision). Rows are ordered by detector,
        then occurrence count (descending), then value. The list field is secrets;
        to read a matched flow in full use proxy.flow.get with a finding's
        first_flow.id.
        """
        return _dump(
            analysis.proxy_secrets(
                session_id,
                offset=offset,
                limit=limit,
                url_filter=url_filter,
                content_type_filter=content_type_filter,
                name_filter=name_filter,
                include_generic=include_generic,
            )
        )

    @tools.tool(name="proxy.flow.get")
    def proxy_flow_get(session_id: str, flow_id: str) -> dict[str, Any]:
        """Fetch one flow's headers and body (large bodies spill to an artifact).

        Answers with id, request (method, url, headers) and response (status,
        headers, size). headers is a list of {name, value} pairs in wire order,
        preserving repeats, so every Set-Cookie survives rather than being folded
        into one comma-joined value. A body at most 200000 bytes is response.body; anything
        larger is response.body_path and there is no body key. There are no
        top-level headers or body fields. The request POST/PUT payload, when
        present, is on request.body / request.body_path the same way (a GET with
        no body has neither). A content-encoded body adds body_encoding,
        body_decoded (false means the bytes are still that encoding, e.g.
        brotli), and encoded_size (the on-wire length) to its own section; size
        is the decoded length. body_truncated marks a decoded body cut at the
        decode ceiling. remote_ip/remote_port name the upstream server the flow
        actually reached -- the C2/CDN host behind the domain -- present once a
        connection was established. A flow that failed before any response adds
        top-level failed and error_text, and its response section is empty.
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
        """Export captured flows to a HAR artifact.

        The file is a spec-valid HAR 1.2 log standard viewers (Chrome DevTools,
        HAR analyzers) can open; each entry carries the required request,
        response, timings and startedDateTime members, its queryString recovered
        from the request URL, the request/response headers and the request body
        (as request.postData) from the retained flow (empty for a flow the ring
        already evicted or whose body was omitted), request/response cookies
        parsed from the Cookie/Set-Cookie headers, redirectURL recovered
        from the response Location header, request/response bodySize
        recovered from Content-Length, and serverIPAddress set to the upstream
        host the flow actually connected to, with fields the capture did
        not retain left empty/`-1` rather
        than omitted. Answers with path and entry_count. There is no har, output
        or artifact field. path is the file; looking for har after a successful
        export reads as a missing capture.
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
