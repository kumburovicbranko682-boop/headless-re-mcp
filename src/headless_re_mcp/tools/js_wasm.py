"""Protocol-independent js.* and wasm.* tool definitions (Web static analysis)."""

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


def build_js_wasm_tools(analysis: AnalysisService) -> tuple[BoundTool, ...]:
    tools = ToolSetBuilder()

    @tools.tool(name="js.deobfuscate")
    def js_deobfuscate(
        path: str, timeout: Annotated[float, Field(gt=0, le=600.0)] = 120.0
    ) -> dict[str, Any]:
        """Deobfuscate and unminify a JavaScript file via webcrack (returns code).

        webcrack can exit non-zero after writing usable code. Read partial and
        exit_code rather than treating the output as a clean deobfuscation.
        Oversized code is cut and marked truncated.
        """
        return _dump(analysis.js_deobfuscate(path, timeout=timeout))

    @tools.tool(name="js.beautify")
    def js_beautify(
        path: str, timeout: Annotated[float, Field(gt=0, le=600.0)] = 120.0
    ) -> dict[str, Any]:
        """Return a readable, unminified form of a JavaScript file via webcrack.

        webcrack can exit non-zero after writing usable code. Read partial and
        exit_code rather than treating the output as clean.
        """
        return _dump(analysis.js_beautify(path, timeout=timeout))

    @tools.tool(name="js.unpack_bundle")
    def js_unpack_bundle(
        path: str, timeout: Annotated[float, Field(gt=0, le=1200.0)] = 300.0
    ) -> dict[str, Any]:
        """Unpack a webpack/browserify bundle into module files via webcrack.

        The file list is capped. Read has_more and file_count rather than
        treating files as every module. webcrack can exit non-zero after
        writing a usable tree: read partial and exit_code rather than treating
        the unpack as clean.
        """
        return _dump(analysis.js_unpack_bundle(path, timeout=timeout))

    @tools.tool(name="wasm.wat")
    def wasm_wat(
        path: str, timeout: Annotated[float, Field(gt=0, le=600.0)] = 120.0
    ) -> dict[str, Any]:
        """Convert a .wasm module to WebAssembly text (WAT) via wasm2wat.

        wasm2wat can exit non-zero after writing usable text. Read partial and
        exit_code rather than treating the WAT as complete. Oversized text is
        cut and marked truncated.
        """
        return _dump(analysis.wasm_wat(path, timeout=timeout))

    @tools.tool(name="wasm.info")
    def wasm_info(
        path: str, timeout: Annotated[float, Field(gt=0, le=600.0)] = 120.0
    ) -> dict[str, Any]:
        """Dump sections and details of a .wasm module via wasm-objdump.

        wasm-objdump can exit non-zero after writing usable text. Read partial
        and exit_code rather than treating the dump as complete. Oversized
        text is cut and marked truncated.
        """
        return _dump(analysis.wasm_info(path, timeout=timeout))

    return tools.bindings
