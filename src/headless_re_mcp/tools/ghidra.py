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

        Answers with items, each carrying name, entry and body_size, plus count
        and has_more so a page that filled the limit is not read as the whole list.
        A failed export is an error, not a binary with no functions.
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
        and has_more. The listing does not include a containing scope. A failed
        export is an error, not an empty listing.
        """
        return _dump(analysis.ghidra_symbols(session_id, limit=limit, timeout=timeout))

    @tools.tool(name="ghidra.data")
    def ghidra_data(
        session_id: str,
        limit: Annotated[int, Field(ge=1, le=1024)] = 256,
        timeout: Annotated[float, Field(gt=0, le=600.0)] = 180.0,
    ) -> dict[str, Any]:
        """Defined data Ghidra typed -- globals, tables, constants, typed bytes.

        Reads the listing's defined-data items, the ones ghidra.functions
        (code) and ghidra.symbols (labels only) leave out and that
        ghidra.strings would show only for the string-typed subset. Answers
        with items, each carrying address, label (the primary symbol at that
        address, empty when the item is unlabeled), type (the Ghidra data type
        name, e.g. char[16], dword, pointer), length (bytes) and value (the
        item's default representation, capped at 256 chars with value_truncated
        set when the representation was longer -- a large array does not blow
        the payload). count and has_more so a page that filled the limit is not
        read as every defined datum. A failed export is an error, not a binary
        with no data. The list field is items, not data.
        """
        return _dump(analysis.ghidra_data(session_id, limit=limit, timeout=timeout))

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
        A failed export is an error, not an address with no references.
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
        and found: found is false when no function contains address, so an
        empty decompiled then means "no function here", not an empty body. A
        second reading of code IDA decompiled differently, or of code it could
        not. A failed export is an error, not empty code.
        """
        return _dump(analysis.ghidra_decompile(session_id, address, timeout=timeout))
    return tools.bindings
