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
        """Deobfuscate and unminify a JavaScript file via webcrack.

        Answers with code and bytes, plus truncated when the inline text was cut
        at the buffer. When truncated, artifact_path points at a file holding the
        full deobfuscated output (artifact_bytes long) so the whole bundle is
        still readable -- the inline code is only a preview. An input over 16 MiB
        is refused as too_large rather than handed to webcrack.
        """
        return _dump(analysis.js_deobfuscate(path, timeout=timeout))

    @tools.tool(name="js.beautify")
    def js_beautify(
        path: str, timeout: Annotated[float, Field(gt=0, le=600.0)] = 120.0
    ) -> dict[str, Any]:
        """Return a readable, unminified form of a JavaScript file via webcrack.

        Same payload as js.deobfuscate. Answers with code and bytes, plus
        truncated when the inline text was cut at the buffer and, in that case,
        artifact_path / artifact_bytes for the full output on disk. An input over
        16 MiB is refused as too_large rather than handed to webcrack.
        """
        return _dump(analysis.js_beautify(path, timeout=timeout))

    @tools.tool(name="js.unpack_bundle")
    def js_unpack_bundle(
        path: str,
        timeout: Annotated[float, Field(gt=0, le=1200.0)] = 300.0,
        offset: int = 0,
        limit: Annotated[int, Field(ge=1, le=2000)] = 100,
    ) -> dict[str, Any]:
        """Unpack a webpack/browserify bundle into module files via webcrack.

        Answers with output_dir, file_count, files, count, total, offset and
        has_more. The file list is paged: read total and has_more rather than
        assuming files is complete. An input over 16 MiB is refused as
        too_large rather than handed to webcrack.
        """
        return _dump(
            analysis.js_unpack_bundle(path, timeout=timeout, offset=offset, limit=limit)
        )

    @tools.tool(name="wasm.wat")
    def wasm_wat(
        path: str, timeout: Annotated[float, Field(gt=0, le=600.0)] = 120.0
    ) -> dict[str, Any]:
        """Convert a .wasm module to WebAssembly text (WAT) via wasm2wat.

        Answers with wat and bytes, plus truncated when the inline text was cut
        at the buffer. When truncated, artifact_path / artifact_bytes give the
        full WAT dump on disk. An input over 16 MiB is refused as too_large
        rather than handed to wasm2wat.
        """
        return _dump(analysis.wasm_wat(path, timeout=timeout))

    @tools.tool(name="wasm.decompile")
    def wasm_decompile(
        path: str, timeout: Annotated[float, Field(gt=0, le=600.0)] = 120.0
    ) -> dict[str, Any]:
        """Decompile a .wasm module to readable pseudo-C via wasm-decompile.

        Where wasm.wat gives the raw stack-machine text, this gives a C-like form
        with named functions, structured control flow and the module's data
        segments (so an embedded URL or key reads as a string, not a byte run) --
        the WASM analogue of ghidra.decompile for a native binary. Answers with
        code and bytes, plus truncated when the inline text was cut at the buffer;
        when truncated, artifact_path / artifact_bytes give the full decompilation
        on disk so the preview is never the whole story. An input over 16 MiB is
        refused as too_large rather than handed to wasm-decompile.
        """
        return _dump(analysis.wasm_decompile(path, timeout=timeout))

    @tools.tool(name="wasm.info")
    def wasm_info(
        path: str, timeout: Annotated[float, Field(gt=0, le=600.0)] = 120.0
    ) -> dict[str, Any]:
        """Dump sections and details of a .wasm module via wasm-objdump.

        Answers with objdump holding that text, not a sections list, plus
        truncated when the inline text was cut at the buffer. When truncated,
        artifact_path / artifact_bytes give the full dump on disk. An input over
        16 MiB is refused as too_large rather than handed to wasm-objdump.
        """
        return _dump(analysis.wasm_info(path, timeout=timeout))

    return tools.bindings
