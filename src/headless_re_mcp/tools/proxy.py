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
        """Export captured flows to a HAR artifact.

        Answers with path and entry_count. There is no har, output or
        artifact field. path is the file; looking for har after a successful
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
