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
    def proxy_flow_get(session_id: str, flow_id: str) -> dict[str, Any]:
        """Fetch one flow's headers and body (large bodies spill to an artifact).

        Answers with id, request (method, url, headers) and response (status,
        headers, size). A text body at most 200000 bytes is response.body; a
        larger body -- or a binary body of any size (one holding a NUL byte or
        non-UTF-8 bytes, such as a captured .wasm, image or font) -- is
        response.body_path and there is no body key, so the exact bytes survive
        for the static tools rather than being mangled into inline text. There
        are no top-level headers or body fields. A WebSocket flow also carries
        websocket with the captured messages (direction sent or received, type
        text or binary, payload, payload_len, ts), count, total, offset,
        has_more, dropped and closed; a binary message's payload is base64 and
        an oversized one is cut and marked payload_truncated. dropped counts
        frames the per-flow retention cap evicted (a long socket cannot grow
        without bound). Only the first 500 retained messages ride along here --
        page the whole retained conversation with proxy.ws.frames.
        """
        return _dump(analysis.proxy_flow_get(session_id, flow_id))

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
