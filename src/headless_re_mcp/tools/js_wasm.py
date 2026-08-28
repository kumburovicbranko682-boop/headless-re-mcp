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

    @tools.tool(name="wasm.strings")
    def wasm_strings(
        path: str,
        min_length: Annotated[int, Field(ge=1, le=64)] = 4,
    ) -> dict[str, Any]:
        """Extract printable string constants from a .wasm module (no wabt needed).

        Compiled WebAssembly keeps its string literals -- URLs, error text,
        format strings, sometimes embedded keys -- in the data section, so this
        is the quickest triage of a stripped module. Pure Python: it reads the
        data segments directly and needs no external tool.

        Answers with items, each carrying text, segment (the data-segment
        index), offset (byte offset within that segment) and length, plus
        count. Read items_total, items_limit and items_truncated when the list
        filled the cap (4096); there is no strings, truncated or has_more field.
        min_length (default 4, 1..64) sets the shortest run kept. has_data_section
        is false when the module carries no data section, and malformed is true
        if the data section could not be split.

        A file that is not a WebAssembly module is refused as invalid_params and
        one over 16 MiB as too_large.
        """
        return _dump(analysis.wasm_strings(path, min_length=min_length))

    @tools.tool(name="wasm.functions")
    def wasm_functions(
        path: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=2000)] = 100,
    ) -> dict[str, Any]:
        """List a .wasm module's functions with resolved signatures (no wabt).

        Where wasm.summary only counts them, this walks the whole function index
        space in order: each imported function first, then each defined one.
        Pure Python; needs no external tool.

        Answers with functions (paged), count, total, offset, has_more, plus
        imported_count and defined_count. Each row carries index (its position
        in the function index space), kind (imported or defined), type_index,
        and -- when the type section resolved -- params and results (lists of
        value types like i32/i64/f32/f64/funcref). An imported row also carries
        module and name (the import descriptor); a defined row carries name when
        the name section named it, and an imported row a debug_name likewise.
        types_resolved is false when the type section could not be parsed (so
        params/results are absent), and scan_capped marks a module whose
        function count hit the collect cap. Read has_more so a page that filled
        the limit is not read as every function.

        A file that is not a WebAssembly module is refused as invalid_params and
        one over 16 MiB as too_large.
        """
        return _dump(analysis.wasm_functions(path, offset=offset, limit=limit))

    @tools.tool(name="wasm.globals")
    def wasm_globals(
        path: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=2000)] = 100,
    ) -> dict[str, Any]:
        """List a .wasm module's defined globals (section 6). Pure Python, no wabt.

        summary only counts globals; this names each one. Answers with globals
        (paged), count, total, offset, has_more, plus imported_count (imported
        globals precede defined ones in the index space, so it is added as an
        offset) and resolved (false when the section could not be parsed).

        Each row carries index (its position in the global index space),
        value_type (i32/i64/f32/f64/v128/funcref/externref), mutable (a mutable
        global is where a packer often keeps a stack pointer or a decode key),
        and init -- the decoded leading instruction of the initializer: {op}
        plus value for i32.const/i64.const or index for global.get/ref.func;
        op is "complex" for a multi-instruction initializer. scan_capped marks a
        module whose global count hit the collect cap.

        A file that is not a WebAssembly module is refused as invalid_params and
        one over 16 MiB as too_large.
        """
        return _dump(analysis.wasm_globals(path, offset=offset, limit=limit))

    @tools.tool(name="wasm.exports")
    def wasm_exports(
        path: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=2000)] = 100,
    ) -> dict[str, Any]:
        """List a .wasm module's exports, resolving function signatures. No wabt.

        summary lists exports by name/kind/index; this is the exported API
        surface with types. Answers with exports (paged), count, total, offset,
        has_more, plus imported_func_count and types_resolved (false when the
        type section could not be parsed).

        Each row carries name (the exported name), kind (func/table/memory/
        global) and index. A func export also carries origin (imported when it
        re-exports an imported function, else defined), type_index, params and
        results (value-type lists, absent when types did not resolve), and
        internal_name when the name section named the target. scan_capped marks
        a module whose export count hit the collect cap. Read has_more so a page
        that filled the limit is not read as every export.

        A file that is not a WebAssembly module is refused as invalid_params and
        one over 16 MiB as too_large.
        """
        return _dump(analysis.wasm_exports(path, offset=offset, limit=limit))

    @tools.tool(name="wasm.imports")
    def wasm_imports(
        path: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=2000)] = 100,
    ) -> dict[str, Any]:
        """List a .wasm module's imports with descriptors and resolved signatures.

        summary caps the import list and does not resolve function types; this
        pages the whole import section and, for each function import, resolves
        params/results. It names the host surface a stripped module reaches for
        (wasi_snapshot_preview1.*, env.emscripten_*), the single most useful
        thing for triage. Pure Python, no wabt.

        Answers with imports (paged), count, total, offset, has_more, plus
        imported_func_count and types_resolved (false when the type section
        could not be parsed). Each row carries module, name and kind (func/table/
        memory/global). A func row also carries type_index, func_index (its slot
        in the function index space, which imports occupy first) and, when types
        resolved, params and results. A table row carries element_type and
        limits; a memory row carries limits; a global row carries value_type and
        mutable. scan_capped marks a module whose import count hit the collect
        cap.

        A file that is not a WebAssembly module is refused as invalid_params and
        one over 16 MiB as too_large.
        """
        return _dump(analysis.wasm_imports(path, offset=offset, limit=limit))

    return tools.bindings
