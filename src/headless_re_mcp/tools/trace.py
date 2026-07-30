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


def build_trace_tools(analysis: AnalysisService) -> tuple[BoundTool, ...]:
    tools = ToolSetBuilder()
    @tools.tool(name="trace.start")
    def trace_start(
        session_id: str,
        path: Annotated[str, Field(min_length=1, max_length=32767)],
        max_events: Annotated[int, Field(ge=1, le=1_000_000)] = 10_000,
        timeout_ms: Annotated[int, Field(ge=1, le=3_600_000)] = 60_000,
        max_file_bytes: Annotated[int, Field(ge=1, le=268_435_456)] = 16_777_216,
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 30.0,
    ) -> dict[str, Any]:
        """Start run-trace recording to an absolute path with quotas."""
        return _dump(
            analysis.trace_start(
                session_id,
                path,
                max_events=max_events,
                timeout_ms=timeout_ms,
                max_file_bytes=max_file_bytes,
                timeout=timeout,
            )
        )

    @tools.tool(name="trace.stop")
    def trace_stop(
        session_id: str,
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 30.0,
    ) -> dict[str, Any]:
        """Stop run-trace recording."""
        return _dump(analysis.trace_stop(session_id, timeout=timeout))

    @tools.tool(name="trace.status")
    def trace_status(
        session_id: str,
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 30.0,
    ) -> dict[str, Any]:
        """Report run-trace recording status and quotas."""
        return _dump(analysis.trace_status(session_id, timeout=timeout))
    return tools.bindings
