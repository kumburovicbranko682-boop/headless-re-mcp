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


def build_ghidra_tools(analysis: AnalysisService) -> tuple[BoundTool, ...]:
    tools = ToolSetBuilder()
    @tools.tool(name="ghidra.analyze")
    def ghidra_analyze(
        session_id: str, timeout: Annotated[float, Field(gt=0, le=600.0)] = 120.0
    ) -> dict[str, Any]:
        return _dump(analysis.ghidra_analyze(session_id, timeout=timeout))

    @tools.tool(name="ghidra.functions")
    def ghidra_functions(
        session_id: str,
        limit: Annotated[int, Field(ge=1, le=1024)] = 256,
        timeout: Annotated[float, Field(gt=0, le=600.0)] = 180.0,
    ) -> dict[str, Any]:
        return _dump(analysis.ghidra_functions(session_id, limit=limit, timeout=timeout))

    @tools.tool(name="ghidra.symbols")
    def ghidra_symbols(
        session_id: str,
        limit: Annotated[int, Field(ge=1, le=1024)] = 256,
        timeout: Annotated[float, Field(gt=0, le=600.0)] = 180.0,
    ) -> dict[str, Any]:
        return _dump(analysis.ghidra_symbols(session_id, limit=limit, timeout=timeout))

    @tools.tool(name="ghidra.xrefs")
    def ghidra_xrefs(
        session_id: str,
        address: str,
        limit: Annotated[int, Field(ge=1, le=1024)] = 256,
        timeout: Annotated[float, Field(gt=0, le=600.0)] = 180.0,
    ) -> dict[str, Any]:
        return _dump(analysis.ghidra_xrefs(session_id, address, limit=limit, timeout=timeout))

    @tools.tool(name="ghidra.decompile")
    def ghidra_decompile(
        session_id: str,
        address: str,
        timeout: Annotated[float, Field(gt=0, le=600.0)] = 180.0,
    ) -> dict[str, Any]:
        return _dump(analysis.ghidra_decompile(session_id, address, timeout=timeout))
    return tools.bindings
