"""Protocol-independent dex.* tool definitions (standalone Dalvik executables)."""

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


def build_dex_tools(analysis: AnalysisService) -> tuple[BoundTool, ...]:
    tools = ToolSetBuilder()

    @tools.tool(name="dex.summary")
    def dex_summary(
        path: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=5000)] = 200,
    ) -> dict[str, Any]:
        """Summarise a standalone Dalvik executable (.dex) with the stdlib.

        The apk.* tools open an APK container via androguard; this reads a lone
        .dex by path -- one dropped by malware, loaded at runtime, or pulled out
        of an APK -- with no androguard and no CLI. It validates the header and
        returns the section shape plus a paginated slice of the string table.

        Answers with version, checksum, signature (SHA-1), file_size (declared)
        and actual_size, header_size, endian, map_off, data_size, counts
        (strings, types, protos, fields, methods, classes), and a page of
        strings (the class/method names and literals) with strings_count,
        strings_total, offset, limit and has_more so a filled page is not read
        as the whole table, plus warnings for any string offset that left the
        file. Strings are best-effort UTF-8 and bounded. A file that is not a
        DEX is invalid_params, one over 64 MiB too_large.
        """
        return _dump(analysis.dex_summary(path, offset=offset, limit=limit))

    return tools.bindings
