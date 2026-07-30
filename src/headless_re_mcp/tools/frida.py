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


def build_frida_tools(analysis: AnalysisService) -> tuple[BoundTool, ...]:
    tools = ToolSetBuilder()
    @tools.tool(name="frida.attach")
    def frida_attach(session_id: str) -> dict[str, Any]:
        return _dump(analysis.frida_attach(session_id))

    @tools.tool(name="frida.modules")
    def frida_modules(
        session_id: str, limit: Annotated[int, Field(ge=1, le=256)] = 64
    ) -> dict[str, Any]:
        return _dump(analysis.frida_modules(session_id, limit=limit))

    @tools.tool(name="frida.exports")
    def frida_exports(
        session_id: str,
        module_name: str,
        limit: Annotated[int, Field(ge=1, le=512)] = 64,
    ) -> dict[str, Any]:
        return _dump(analysis.frida_exports(session_id, module_name, limit=limit))

    @tools.tool(name="frida.memory.read")
    def frida_memory_read(
        session_id: str, address: int, size: Annotated[int, Field(ge=1, le=262144)] = 16
    ) -> dict[str, Any]:
        return _dump(analysis.frida_memory_read(session_id, address, size))

    @tools.tool(name="frida.hook.template")
    def frida_hook_template(session_id: str, template: str = "noop") -> dict[str, Any]:
        return _dump(analysis.frida_hook_template(session_id, template=template))
    return tools.bindings
