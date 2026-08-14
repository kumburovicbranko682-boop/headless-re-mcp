"""Protocol-independent workspace.* tools (startup work direction)."""

from __future__ import annotations

from typing import Any

from headless_re_mcp.core.models import Result
from headless_re_mcp.core.service import AnalysisService, JsonObject
from headless_re_mcp.tools.binding import BoundTool, ToolSetBuilder


def _dump(result: Result[JsonObject]) -> dict[str, Any]:
    value = result.model_dump(mode="json")
    if not isinstance(value, dict):
        raise TypeError("result envelope did not serialize to an object")
    return value


def build_workspace_tools(analysis: AnalysisService) -> tuple[BoundTool, ...]:
    tools = ToolSetBuilder()

    @tools.tool(name="workspace.mode.get")
    def workspace_mode_get() -> dict[str, Any]:
        """Return the active work direction.

        Answers with profile (full/pe/android/web), label, available, and
        hidden_prefixes. There is no mode or options field.
        """
        return _dump(analysis.workspace_mode_get())

    @tools.tool(name="workspace.mode.set")
    def workspace_mode_set(profile: str) -> dict[str, Any]:
        """Set the startup work direction; persists and applies on next connection.

        Same payload as workspace.mode.get: Answers with profile, label,
        available, and hidden_prefixes.
        """
        return _dump(analysis.workspace_mode_set(profile))

    return tools.bindings
