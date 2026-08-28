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

    @tools.tool(name="proxy.clear")
    def proxy_clear(session_id: str) -> dict[str, Any]:
        """Drop every captured flow, keeping the proxy running.

        Resets the capture ring so the next action records into a clean window --
        the way to isolate one operation's traffic without the stop/start churn
        that would drop the client's proxy settings. Answers with cleared (how
        many flow summaries were held) and running (always true; use proxy.stop
        to actually stop). The sequence counter resets too, so proxy.flows
        dropped accounting starts fresh. A session with no proxy is refused
        invalid_state.
        """
        return _dump(analysis.proxy_clear(session_id))

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
    ) -> dict[str, Any]:
        """List captured HTTP flows (method, url, status, content type).

        Answers with flows (id, seq, method, url, host, status, content_type,
        response_size), count, total, offset, has_more, and dropped.
        response_size is the decoded response body length in bytes (0 when the
        response had no body). body_omitted is set on a row whose
        request/response body was over the retain cap. A flow mitmproxy could
        not complete (TLS refused, upstream unreachable, connection reset) is
        captured too, carrying error=true and error_msg with a null status;
        such flows were previously dropped entirely. A completed flow always
        carries a numeric status and no error field. The list field is flows,
        not items or requests, and the type column is content_type. dropped is
        how many the capture ring already evicted; a page that filled the limit
        is not the whole log. metadata_truncated marks bounded oversized summary
        fields.
        """
        return _dump(analysis.proxy_flows(session_id, offset=offset, limit=limit))

    @tools.tool(name="proxy.stats")
    def proxy_stats(
        session_id: str,
        top: Annotated[int, Field(ge=1, le=50)] = 10,
    ) -> dict[str, Any]:
        """Aggregate the captured flows into a one-look triage summary.

        Folds the same rows proxy.flows pages, so it needs no export. Answers
        with total and dropped (how many the ring already evicted -- a nonzero
        dropped means the tallies cover only the retained window), methods (a
        method->count map, busiest first), status_classes (2xx/3xx/4xx/5xx and
        none for errored or still-pending flows with a null status), top_hosts
        and top_content_types (each a ranked [{host|content_type, count}] list
        capped at top, default 10), host_count and content_type_count (the
        distinct totals behind those lists), errors and body_omitted (flow
        counts, not byte sizes), and total_response_bytes (summed decoded
        response sizes). content_type is the bare media type; the charset tail
        is dropped before counting. There is no flows or items field here --
        use proxy.flows to read individual rows.
        """
        return _dump(analysis.proxy_stats(session_id, top=top))

    @tools.tool(name="proxy.cookies")
    def proxy_cookies(
        session_id: str,
        limit: Annotated[int, Field(ge=1, le=1000)] = 200,
    ) -> dict[str, Any]:
        """Fold captured Set-Cookie/Cookie headers into a distinct cookie inventory.

        The wire view of cookies: what servers set (with their security
        attributes) and what the client sent back, across the whole capture --
        complementary to web.cookies, which reads the live browser jar. Answers
        with cookies, count, total, truncated and body_unavailable (flows whose
        headers were evicted from the retain ring). Cookies are keyed by (name,
        domain), so the same name on two hosts stays distinct. Each cookie
        carries name, domain, value, path, http_only, secure, same_site
        (Strict/Lax/None or null), set_count (times seen in a Set-Cookie),
        sent_count (times seen in a request Cookie) and sources (set-cookie,
        cookie, or both). A session cookie set without http_only and secure is
        the weakness worth flagging.
        """
        return _dump(analysis.proxy_cookies(session_id, limit=limit))

    @tools.tool(name="proxy.endpoints")
    def proxy_endpoints(
        session_id: str,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """Fold the capture into distinct (method, host, path) endpoints.

        Turns a noisy flow log into the API map: the query string is stripped so
        /search?q=a and /search?q=b collapse into one GET /search, and each
        endpoint aggregates how often it was hit, the distinct status codes seen,
        and how many of its flows errored. Answers with endpoints (ranked by
        hits), count, total (distinct endpoints), truncated (the list was
        capped), and total_flows (rows folded). Each endpoint carries method,
        host, path, hits, statuses (a sorted list of distinct status codes) and
        errors. Use proxy.flows to read the individual rows behind an endpoint.
        """
        return _dump(analysis.proxy_endpoints(session_id, limit=limit))

    @tools.tool(name="proxy.search")
    def proxy_search(
        session_id: str,
        query: str,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        case_sensitive: bool = False,
    ) -> dict[str, Any]:
        """Search the whole capture for a substring (url, host, headers, bodies).

        Where proxy.flows only surfaces the summary columns, this scans each
        retained flow's request/response headers and bodies too -- the way you
        hunt a token, a hostname, a JSON key, or an error string across a
        session without exporting a HAR.

        Answers with query, matches, count, scanned (rows examined),
        case_sensitive, truncated (the result cap was hit), and body_unavailable
        (flows whose body was evicted from the retain ring, so only their
        url/host could be searched). Each match carries id, method, url, host,
        status, matched_in (every field that hit: url, host, request_headers,
        response_headers, request_body, response_body) and, for the header/body
        hits, snippets -- a bounded window around each match with an ellipsis
        when it was clipped. The match is case-insensitive unless case_sensitive
        is set. There is no regex; query is a literal substring.
        """
        return _dump(
            analysis.proxy_search(
                session_id, query, limit=limit, case_sensitive=case_sensitive
            )
        )

    @tools.tool(name="proxy.flow.get")
    def proxy_flow_get(session_id: str, flow_id: str) -> dict[str, Any]:
        """Fetch one flow's headers and bodies (large or binary bodies spill).

        Answers with id, request (method, url, headers) and response (status,
        headers). Both request and response carry the body: size, and either
        body (UTF-8 text at most 200000 bytes) or body_path plus spill_reason
        (too_large or binary) when the body was spilled to an artifact rather
        than decoded lossily. A spilled body also carries artifact_id. Headers
        are bounded in count and size; metadata_truncated on request or
        response marks a clipped header map or field. There is no top-level
        headers or body field, and a binary body is never returned as a
        mojibake body string.
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
        """Export captured flows to a spec-valid HAR 1.2 artifact.

        Answers with path, entry_count and truncated, plus artifact_id when
        the HAR was registered. truncated is true when the oldest entries were
        dropped to keep the file under the capture cap. There is no har,
        output or artifact field. path is the file; looking for har after a
        successful export reads as a missing capture.
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
