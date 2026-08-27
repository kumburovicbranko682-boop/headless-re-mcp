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

        Answers with project_dir, stdout_excerpt and note.
        There is no functions field and no analysis field. The other ghidra tools
        do not read what this produced. Each of ghidra.functions, ghidra.symbols,
        ghidra.xrefs and ghidra.decompile imports the binary again under
        -deleteProject, so calling this first does not save them any work. Minutes
        on a large binary. Requires HEADLESS_RE_GHIDRA_HOME.
        """
        return _dump(analysis.ghidra_analyze(session_id, timeout=timeout))

    @tools.tool(name="ghidra.functions")
    def ghidra_functions(
        session_id: str,
        limit: Annotated[int, Field(ge=1, le=1024)] = 256,
        timeout: Annotated[float, Field(gt=0, le=600.0)] = 180.0,
    ) -> dict[str, Any]:
        """Functions Ghidra found.

        Answers with items, each carrying name, entry, body_size and
        entry_address -- a {module, rva, va, architecture} object, the same
        coordinate shape the r2 tools attach, so the two engines join on
        rva/module. Plus count and has_more so a page that filled the limit is
        not read as the whole list. The payload also names module, image_base
        and architecture once at the top level.
        """
        return _dump(analysis.ghidra_functions(session_id, limit=limit, timeout=timeout))

    @tools.tool(name="ghidra.symbols")
    def ghidra_symbols(
        session_id: str,
        limit: Annotated[int, Field(ge=1, le=1024)] = 256,
        timeout: Annotated[float, Field(gt=0, le=600.0)] = 180.0,
    ) -> dict[str, Any]:
        """Symbols Ghidra recovered.

        Answers with items, each carrying name, address, type and
        address_detail -- the structured {module, rva, va, architecture}
        companion of the address string (the r2 coordinate shape); an address
        outside the load image, like an EXTERNAL thunk, is va-only there. Plus
        count and has_more. The listing does not include a containing scope.
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
        to, type, from_address and to_address -- each a {module, rva, va,
        architecture} object in the same shape r2 emits for its edges. Plus
        count and has_more. Outgoing refs are not listed.
        """
        return _dump(analysis.ghidra_xrefs(session_id, address, limit=limit, timeout=timeout))

    @tools.tool(name="ghidra.decompile")
    def ghidra_decompile(
        session_id: str,
        address: str,
        timeout: Annotated[float, Field(gt=0, le=600.0)] = 180.0,
    ) -> dict[str, Any]:
        """Ghidra's decompilation of the function at address.

        Answers with decompiled, truncated when the C was cut at the buffer,
        and -- when a function contains address -- function, entry and
        entry_address ({module, rva, va, architecture}, the same coordinate
        object the listings carry). An empty decompiled with no function key
        means no function there, not an empty body. A second reading of code
        IDA decompiled differently, or of code it could not.
        """
        return _dump(analysis.ghidra_decompile(session_id, address, timeout=timeout))
    return tools.bindings
