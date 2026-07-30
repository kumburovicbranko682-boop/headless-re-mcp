from __future__ import annotations

from typing import Annotated, Any

from pydantic import Field

from headless_re_mcp.core.models import ModuleSelector, Result
from headless_re_mcp.core.service import AnalysisService, JsonObject
from headless_re_mcp.tools.binding import BoundTool, ToolSetBuilder


def _dump(result: Result[JsonObject]) -> dict[str, Any]:
    value = result.model_dump(mode="json")
    if not isinstance(value, dict):
        raise TypeError("result envelope did not serialize to an object")
    return value


def build_meta_tools(analysis: AnalysisService) -> tuple[BoundTool, ...]:
    tools = ToolSetBuilder()
    @tools.tool(name="sync.static_to_runtime")
    def sync_static_to_runtime(session_id: str, address: int) -> dict[str, Any]:
        """Map an IDA address to the matching loaded main-module runtime address."""
        return _dump(analysis.sync_static_to_runtime(session_id, address))

    @tools.tool(name="sync.runtime_to_static")
    def sync_runtime_to_static(session_id: str, address: int) -> dict[str, Any]:
        """Map a loaded main-module runtime address back to its IDA address."""
        return _dump(analysis.sync_runtime_to_static(session_id, address))

    @tools.tool(name="sync.module_preferred_to_runtime")
    def sync_module_preferred_to_runtime(
        session_id: str,
        selector: ModuleSelector,
        address: int,
    ) -> dict[str, Any]:
        """Map an explicitly selected PE preferred VA to its current runtime VA."""
        return _dump(analysis.sync_module_preferred_to_runtime(session_id, selector, address))

    @tools.tool(name="sync.module_runtime_to_preferred")
    def sync_module_runtime_to_preferred(
        session_id: str,
        selector: ModuleSelector,
        address: int,
    ) -> dict[str, Any]:
        """Map an explicitly selected runtime VA back to its PE preferred VA."""
        return _dump(analysis.sync_module_runtime_to_preferred(session_id, selector, address))

    @tools.tool(name="capabilities.search")
    def capabilities_search(
        backend: str | None = None,
        status: str | None = None,
    ) -> dict[str, Any]:
        """Search discovered backend capabilities and readiness."""
        return _dump(analysis.capabilities_search(backend=backend, status=status))

    @tools.tool(name="capabilities.describe")
    def capabilities_describe(capability_id: str) -> dict[str, Any]:
        """Describe one capability id from the catalog."""
        return _dump(analysis.capabilities_describe(capability_id))

    @tools.tool(name="artifacts.list")
    def artifacts_list(
        session_id: str | None = None,
        offset: int = 0,
        limit: Annotated[int, Field(ge=1, le=256)] = 50,
    ) -> dict[str, Any]:
        return _dump(analysis.artifacts_list(session_id, offset=offset, limit=limit))

    @tools.tool(name="artifacts.describe")
    def artifacts_describe(artifact_id: str) -> dict[str, Any]:
        return _dump(analysis.artifacts_describe(artifact_id))

    @tools.tool(name="artifacts.read")
    def artifacts_read(
        artifact_id: str, offset: int = 0, limit: Annotated[int, Field(ge=1, le=262144)] = 4096
    ) -> dict[str, Any]:
        return _dump(analysis.artifacts_read(artifact_id, offset=offset, limit=limit))

    @tools.tool(name="artifacts.gc")
    def artifacts_gc(max_total_bytes: int = 512 * 1024 * 1024) -> dict[str, Any]:
        return _dump(analysis.artifacts_gc(max_total_bytes=max_total_bytes))

    @tools.tool(name="timeline.list")
    def timeline_list(
        session_id: str, offset: int = 0, limit: Annotated[int, Field(ge=1, le=256)] = 100
    ) -> dict[str, Any]:
        return _dump(analysis.timeline_list(session_id, offset=offset, limit=limit))

    @tools.tool(name="sessions.unclean")
    def sessions_unclean() -> dict[str, Any]:
        return _dump(analysis.sessions_unclean())

    @tools.tool(name="audit.list")
    def audit_list(
        session_id: str | None = None,
        offset: int = 0,
        limit: Annotated[int, Field(ge=1, le=256)] = 50,
    ) -> dict[str, Any]:
        return _dump(analysis.audit_list(session_id, offset=offset, limit=limit))
    return tools.bindings
