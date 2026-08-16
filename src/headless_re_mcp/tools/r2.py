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


def build_r2_tools(analysis: AnalysisService) -> tuple[BoundTool, ...]:
    tools = ToolSetBuilder()
    @tools.tool(name="r2.info")
    def r2_info(
        session_id: str, timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0
    ) -> dict[str, Any]:
        """Binary identity as radare2 sees it: format, arch, bits, endianness, entry.

        A second opinion on a file IDA may have loaded differently. Requires
        radare2 on PATH or HEADLESS_RE_R2.
        """
        return _dump(analysis.r2_info(session_id, timeout=timeout))

    @tools.tool(name="r2.open")
    def r2_open(
        session_id: str, timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0
    ) -> dict[str, Any]:
        """Open the session binary in radare2 and run its own analysis pass.

        Independent of the IDA database; the other r2 tools read what this
        produced. Analysis cost scales with the binary, so give a packed or
        large sample a longer timeout. The identity excerpt is capped: read
        truncated rather than treating info as the whole `i` listing.
        """
        return _dump(analysis.r2_open(session_id, timeout=timeout))

    @tools.tool(name="r2.functions")
    def r2_functions(
        session_id: str, timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0
    ) -> dict[str, Any]:
        """Functions radare2 found, with address, size and name.

        Useful where IDA and radare2 disagree about where code begins, which is
        common in packed or obfuscated samples. The item list is capped: read
        items_truncated rather than treating count as every function.
        """
        return _dump(analysis.r2_functions(session_id, timeout=timeout))

    @tools.tool(name="r2.strings")
    def r2_strings(
        session_id: str, timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0
    ) -> dict[str, Any]:
        """Strings radare2 recovered, with address, encoding and section.

        The item list is capped. Read items_truncated rather than treating
        count as every string.
        """
        return _dump(analysis.r2_strings(session_id, timeout=timeout))

    @tools.tool(name="r2.imports")
    def r2_imports(
        session_id: str, timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0
    ) -> dict[str, Any]:
        """Imported symbols with the library each resolves to.

        The item list is capped. Read items_truncated rather than treating
        count as every import.
        """
        return _dump(analysis.r2_imports(session_id, timeout=timeout))

    @tools.tool(name="r2.exports")
    def r2_exports(
        session_id: str, timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0
    ) -> dict[str, Any]:
        """Exported symbols with their addresses.

        The item list is capped. Read items_truncated rather than treating
        count as every export.
        """
        return _dump(analysis.r2_exports(session_id, timeout=timeout))

    @tools.tool(name="r2.disasm")
    def r2_disasm(
        session_id: str,
        address: int,
        count: Annotated[int, Field(ge=1, le=512)] = 32,
        timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0,
    ) -> dict[str, Any]:
        """Disassemble count instructions at address, as radare2 decodes them.

        Oversized r2 output is cut and marked truncated. Read that flag
        rather than treating the listing as the whole decode.
        """
        return _dump(analysis.r2_disasm(session_id, address, count=count, timeout=timeout))

    @tools.tool(name="r2.xrefs")
    def r2_xrefs(
        session_id: str,
        address: int,
        timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0,
    ) -> dict[str, Any]:
        """References to and from address, as radare2 resolved them.

        The item list is capped. Read items_truncated rather than treating
        count as every reference.
        """
        return _dump(analysis.r2_xrefs(session_id, address, timeout=timeout))
    return tools.bindings
