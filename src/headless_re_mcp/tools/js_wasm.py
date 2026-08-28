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

        Answers with code and bytes, plus truncated when the text was cut at
        the buffer. If webcrack exits non-zero but still emitted code, that
        code is returned with exit_code, tool_failed and stderr set so a
        partial run is not read as complete. An input over 16 MiB is refused
        as too_large rather than handed to webcrack.
        """
        return _dump(analysis.js_deobfuscate(path, timeout=timeout))

    @tools.tool(name="js.beautify")
    def js_beautify(
        path: str, timeout: Annotated[float, Field(gt=0, le=600.0)] = 120.0
    ) -> dict[str, Any]:
        """Return a readable, unminified form of a JavaScript file via webcrack.

        Same payload as js.deobfuscate: Answers with code and bytes, plus
        truncated when the text was cut at the buffer, and exit_code /
        tool_failed / stderr when webcrack exits non-zero but still emitted
        code. An input over 16 MiB is refused as too_large rather than handed
        to webcrack.
        """
        return _dump(analysis.js_beautify(path, timeout=timeout))

    @tools.tool(name="js.unpack_bundle")
    def js_unpack_bundle(
        path: str,
        timeout: Annotated[float, Field(gt=0, le=1200.0)] = 300.0,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=2000)] = 100,
    ) -> dict[str, Any]:
        """Unpack a webpack/browserify bundle into module files via webcrack.

        Answers with output_dir, file_count, files, count, total, offset and
        has_more. The file list is paged: read total and has_more rather than
        assuming files is complete. If webcrack exits non-zero but still wrote
        files, they are returned with exit_code, tool_failed and stderr set so
        a partial unpack is not read as complete. An input over 16 MiB is
        refused as too_large rather than handed to webcrack.
        """
        return _dump(
            analysis.js_unpack_bundle(path, timeout=timeout, offset=offset, limit=limit)
        )

    @tools.tool(name="wasm.wat")
    def wasm_wat(
        path: str, timeout: Annotated[float, Field(gt=0, le=600.0)] = 120.0
    ) -> dict[str, Any]:
        """Convert a .wasm module to WebAssembly text (WAT) via wasm2wat.

        Answers with wat and bytes, plus truncated when the text was cut at
        the buffer, and exit_code / tool_failed / stderr when wasm2wat exits
        non-zero but still emitted text. An input over 16 MiB is refused as
        too_large, and a file that is not a WebAssembly module as
        invalid_params, rather than handed to wasm2wat.
        """
        return _dump(analysis.wasm_wat(path, timeout=timeout))

    @tools.tool(name="wasm.info")
    def wasm_info(
        path: str, timeout: Annotated[float, Field(gt=0, le=600.0)] = 120.0
    ) -> dict[str, Any]:
        """Dump sections and details of a .wasm module via wasm-objdump.

        Answers with objdump holding that text, not a sections list, plus
        truncated when the text was cut at the buffer, and exit_code /
        tool_failed / stderr when wasm-objdump exits non-zero but still
        emitted text. An input over 16 MiB is refused as too_large, and a file
        that is not a WebAssembly module as invalid_params, rather than handed
        to wasm-objdump.
        """
        return _dump(analysis.wasm_info(path, timeout=timeout))

    @tools.tool(name="wasm.summary")
    def wasm_summary(path: str) -> dict[str, Any]:
        """Summarize a .wasm module's structure in pure Python (no wabt needed).

        Where wasm.wat / wasm.info shell out to wabt (and go
        capability_unavailable when it is absent), this reads the binary
        section table itself, so it answers on any host. It does not
        disassemble code.

        Answers with version, a sections table (each id, name, size, offset and
        an entry count), and per-section tallies: type_count, import_count,
        function_count (defined), table_count, memory_count, global_count,
        export_count, element_count, data_segment_count, and start_function.

        The high-value fields are imports and exports: imports lists each
        {module, name, kind, ...} so you can see the host surface the module
        reaches for (wasi_snapshot_preview1.*, env.emscripten_*), and exports
        lists each {name, kind, index}. Both carry an import_kinds /
        export_kinds breakdown and an *_truncated flag; they are capped at 500
        entries. memories reports {initial_pages, max_pages, shared} per linear
        memory, and custom_sections plus module_name / has_name_section surface
        debug metadata.

        A file that is not a WebAssembly module is refused as invalid_params
        and one over 16 MiB as too_large. Malformed input never raises: a bad
        section is listed in malformed_sections and skipped, and a binary that
        ends early sets truncated.
        """
        return _dump(analysis.wasm_summary(path))

    return tools.bindings
