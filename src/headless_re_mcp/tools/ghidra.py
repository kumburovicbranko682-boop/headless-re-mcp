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
        """Run Ghidra headless import and analysis, then delete the project.

        The other ghidra tools do not read what this produced. Each of
        ghidra.functions, ghidra.symbols, ghidra.xrefs and ghidra.decompile
        imports the binary again under -deleteProject, so calling this first
        does not save them any work. Minutes on a large binary. Requires
        HEADLESS_RE_GHIDRA_HOME.
        """
        return _dump(analysis.ghidra_analyze(session_id, timeout=timeout))

    @tools.tool(name="ghidra.functions")
    def ghidra_functions(
        session_id: str,
        limit: Annotated[int, Field(ge=1, le=1024)] = 256,
        timeout: Annotated[float, Field(gt=0, le=600.0)] = 180.0,
    ) -> dict[str, Any]:
        """Functions Ghidra found.

        Answers with items, each carrying name, entry and body_size, plus count
        and has_more so a page that filled the limit is not read as the whole list.
        """
        return _dump(analysis.ghidra_functions(session_id, limit=limit, timeout=timeout))

    @tools.tool(name="ghidra.symbols")
    def ghidra_symbols(
        session_id: str,
        limit: Annotated[int, Field(ge=1, le=1024)] = 256,
        timeout: Annotated[float, Field(gt=0, le=600.0)] = 180.0,
    ) -> dict[str, Any]:
        """Symbols Ghidra recovered.

        Answers with items, each carrying name, address and type, plus count
        and has_more. The listing does not include a containing scope.
        """
        return _dump(analysis.ghidra_symbols(session_id, limit=limit, timeout=timeout))

    @tools.tool(name="ghidra.xrefs")
    def ghidra_xrefs(
        session_id: str,
        address: str,
        limit: Annotated[int, Field(ge=1, le=1024)] = 256,
        timeout: Annotated[float, Field(gt=0, le=600.0)] = 180.0,
    ) -> dict[str, Any]:
        """References to address, as Ghidra resolved them.

        Only incoming refs (getReferencesTo). Answers with items carrying from,
        to and type, plus count and has_more. Outgoing refs are not listed.
        """
        return _dump(analysis.ghidra_xrefs(session_id, address, limit=limit, timeout=timeout))

    @tools.tool(name="ghidra.decompile")
    def ghidra_decompile(
        session_id: str,
        address: str,
        timeout: Annotated[float, Field(gt=0, le=600.0)] = 180.0,
    ) -> dict[str, Any]:
        """Ghidra's decompilation of the function at address.

        Answers with decompiled, and truncated when the C was cut at the
        buffer. A second reading of code IDA decompiled differently, or of
        code it could not.
        """
        return _dump(analysis.ghidra_decompile(session_id, address, timeout=timeout))
    return tools.bindings
