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
        method: str | None = None,
        host_contains: str | None = None,
        url_contains: str | None = None,
        status_min: Annotated[int | None, Field(ge=100, le=599)] = None,
        status_max: Annotated[int | None, Field(ge=100, le=599)] = None,
    ) -> dict[str, Any]:
        """List captured HTTP flows (method, url, status, content type).

        Answers with flows (id, seq, method, url, host, status, content_type),
        count, total, offset, has_more, and dropped. body_omitted is set on a
        row whose request/response body was over the retain cap. The list
        field is flows, not items or requests, and the type column is
        content_type. dropped is how many the capture ring already evicted;
        a page that filled the limit is not the whole log. count may be below
        the requested limit when the result-size budget trimmed the page (each
        url can be 16 KiB), so read count, not limit, and page on has_more.
        metadata_truncated marks bounded oversized summary fields.

        Optional filters narrow a busy capture and are ANDed: method is an exact
        case-insensitive match (e.g. POST); host_contains and url_contains are
        case-insensitive substrings; status_min and status_max are an inclusive
        status-code range (both 100..599), so status_min 400 alone is every
        error and status_min 404 with status_max 404 is exactly 404. A status
        bound excludes any flow with no response captured. When a filter is
        active the reply adds filtered true and captured (the pre-filter ring
        size), and total becomes the number of matching flows, so page on
        has_more against the filtered view. An empty or whitespace-only filter
        string is ignored rather than matching everything or nothing.
        """
        return _dump(
            analysis.proxy_flows(
                session_id,
                offset=offset,
                limit=limit,
                method=method,
                host_contains=host_contains,
                url_contains=url_contains,
                status_min=status_min,
                status_max=status_max,
            )
        )

    @tools.tool(name="proxy.flow.get")
    def proxy_flow_get(session_id: str, flow_id: str) -> dict[str, Any]:
        """Fetch one flow's headers and bodies (large bodies spill to an artifact).

        Answers with id, request (method, url, headers, size) and response
        (status, headers, size). Both request and response carry a body the same
        way: a text body is body with base64_encoded false; a binary body is
        base64 in body with base64_encoded true, so it is recoverable and not
        silently mangled into mojibake. A body too large to inline -- over 200000
        chars, or whose JSON-encoded form would overrun the result budget -- is
        spilled to body_path with no body key (request.body_path for the sent
        payload, response.body_path for the reply). Header maps are coerced to
        strings and bounded by size; headers_truncated is set on the request or
        response when its headers were capped. There are no top-level headers or
        body fields.
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
        """Export captured flows to a HAR 1.2 artifact.

        Answers with path and entry_count. There is no har, output or
        artifact field. path is the file; looking for har after a successful
        export reads as a missing capture. Each entry is a complete HAR record
        -- request/response headers, query string, bodies (a binary body is
        base64 with content.encoding "base64"), status, timings and
        startedDateTime -- so the file is usable by other HAR tools, not just a
        request line. A flow whose body was evicted or exceeded the retention
        cap still exports as a lean entry carrying a comment that its headers
        and body were not retained, so no captured flow is silently dropped.
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
