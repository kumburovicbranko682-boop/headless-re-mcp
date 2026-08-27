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
        started_at as an epoch time), count, total, offset, has_more, and
        dropped. body_omitted is set on a
        row whose request/response body was over the retain cap. A flow that
        failed before any response (upstream reset, TLS handshake failure,
        timeout) has status null and carries failed with error_text, so a
        failed connection is not read as one still in flight. The list
        field is flows, not items or requests, and the type column is
        content_type. dropped is how many the capture ring already evicted;
        a page that filled the limit is not the whole log. metadata_truncated
        marks bounded oversized summary fields.
        """
        return _dump(analysis.proxy_flows(session_id, offset=offset, limit=limit))

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
        decode ceiling. A flow that failed before any response adds top-level
        failed and error_text, and its response section is empty.
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
        from the response Location header, and request/response bodySize
        recovered from Content-Length, with fields the capture did
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
