"""Protocol-independent workspace.* tools (startup work direction)."""

from __future__ import annotations

import re
from typing import Annotated, Any

from pydantic import Field

from headless_re_mcp.core.models import Result
from headless_re_mcp.core.service import AnalysisService, JsonObject
from headless_re_mcp.core.workspace import PROFILES
from headless_re_mcp.tools.binding import BoundTool, ToolSetBuilder

# Built from core.workspace.PROFILES so the schema accepts exactly the profiles
# that exist. A hand-written second copy would silently reject a profile added
# to PROFILES but not here (the schema rejects before the service normalizes),
# the same drift the frida.hook.template names had. re.escape guards a future
# profile that is not a bare identifier; today's are, so the pattern is unchanged.
_PROFILE_PATTERN = "^(" + "|".join(re.escape(profile) for profile in PROFILES) + ")$"


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
    def workspace_mode_set(
        profile: Annotated[str, Field(pattern=_PROFILE_PATTERN)],
    ) -> dict[str, Any]:
        """Set the startup work direction; persists and applies on next connection.

        Same payload as workspace.mode.get, plus note and persisted.
        Answers with profile, label, available, hidden_prefixes, note and
        persisted. note says MCP clients see the new tool surface on their
        next connection.
        """
        return _dump(analysis.workspace_mode_set(profile))

    return tools.bindings
