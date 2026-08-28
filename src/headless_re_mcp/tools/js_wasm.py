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
        the buffer. When truncated, the whole output is written to a file and
        its path returned as code_path so the tail past the inline cap is still
        readable; capture_truncated instead means even that file is a prefix
        because webcrack outran the capture cap. An input over 16 MiB is refused
        as too_large rather than handed to webcrack.
        """
        return _dump(analysis.js_deobfuscate(path, timeout=timeout))

    @tools.tool(name="js.beautify")
    def js_beautify(
        path: str, timeout: Annotated[float, Field(gt=0, le=600.0)] = 120.0
    ) -> dict[str, Any]:
        """Return a readable, unminified form of a JavaScript file via webcrack.

        Same payload as js.deobfuscate: Answers with code and bytes, plus
        truncated when the text was cut at the buffer, code_path holding the
        whole output when it was, and capture_truncated when even that file is
        a prefix. An input over 16 MiB is refused as too_large rather than
        handed to webcrack.
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
        assuming files is complete. An input over 16 MiB is refused as
        too_large rather than handed to webcrack.
        """
        return _dump(
            analysis.js_unpack_bundle(path, timeout=timeout, offset=offset, limit=limit)
        )

    @tools.tool(name="wasm.summary")
    def wasm_summary(
        path: str,
        max_imports: Annotated[int, Field(ge=1, le=5000)] = 1000,
        max_exports: Annotated[int, Field(ge=1, le=5000)] = 1000,
    ) -> dict[str, Any]:
        """Structured imports/exports/sections of a .wasm module, without wabt.

        wasm.wat and wasm.info shell out to wabt and hand back a wall of text to
        grep; this reads the module's binary sections in-process (no wabt, so it
        works when wabt is not installed) and returns the triage facts as data.
        Answers with version, sections (one {id, name, size} per section in file
        order, custom_name on a custom section), imports and exports, and
        start_function when the module declares one. Each imports row is {module,
        name, kind}, plus type_index for a function import -- the host interface
        the module needs (env.* JS glue, wasi_snapshot_preview1.* syscalls) that
        names what it can call out to. Each exports row is {name, kind, index} --
        its entry points. kind is func, table, memory or global. The lists are
        capped by max_imports/max_exports; imports_total/exports_total carry the
        declared section length and imports_truncated/exports_truncated say a page
        did not cover it, so a capped list is not read as the whole section
        (imports_count/exports_count are the returned lengths). For the full
        instruction text use wasm.wat; for wabt's section dump use wasm.info. A
        file that is not a readable wasm module is invalid_params, and one over
        16 MiB is too_large.
        """
        return _dump(
            analysis.wasm_summary(path, max_imports=max_imports, max_exports=max_exports)
        )

    @tools.tool(name="wasm.names")
    def wasm_names(
        path: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=2000)] = 200,
        name_filter: str = "",
    ) -> dict[str, Any]:
        """Resolve a .wasm module's function indices to names, without wabt.

        wasm.summary reports bare indices (export index 3, start_function 3);
        this decodes the module's ``name`` custom section so those indices get
        human names -- the difference between "func 42" and "_ZN4core...", the
        first thing a wasm reversing pass wants. Parsed in-process (no wabt).
        Answers with module_name (the module's own name subsection, often ""),
        names (each {index, name} from the function-name subsection), count,
        total, offset, has_more, and scan_capped when the namemap exceeded the
        collect ceiling, plus has_name_section. When has_name_section is false
        the module was stripped of its names (the usual release build) and names
        is empty -- that is the answer, not an error, and there is nothing to
        resolve. name_filter keeps only entries whose name contains that
        substring (case-sensitive, since wasm names are symbols), applied before
        paging so total is the match count -- the way to find one function in a
        module that named thousands. The list field is names, not functions or
        symbols. A file that is not a readable wasm module is invalid_params; one
        over 16 MiB is too_large.
        """
        return _dump(
            analysis.wasm_names(path, offset=offset, limit=limit, name_filter=name_filter)
        )

    @tools.tool(name="wasm.strings")
    def wasm_strings(
        path: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=2000)] = 200,
        min_length: Annotated[int, Field(ge=1, le=256)] = 4,
        name_filter: str = "",
    ) -> dict[str, Any]:
        """Pull printable strings from a .wasm module's data section, no wabt.

        The content companion to wasm.summary (structure) and wasm.names
        (symbols): a module's rodata -- the URLs, endpoints, error messages,
        format strings and embedded keys a triage pass greps for -- lives in the
        data section, and this is ``strings`` of that section, parsed in-process
        (no wabt). Answers with strings (each {offset (module-absolute byte
        offset), text, size}, plus text_truncated when one run exceeded the text
        clip), count, total, offset, has_more, scan_capped when the section held
        more runs than the collect ceiling, and has_data_section. When
        has_data_section is false the module ships no initialised memory and
        strings is empty -- that is the answer, not an error. min_length is the
        shortest run kept (default 4, so binary noise is dropped the way strings
        does); raising it cuts the noise on a large module. name_filter keeps
        only runs whose text contains that substring (case-insensitive, since
        these are prose and URLs not symbols), applied before paging so total is
        the match count -- the way to find "https" or an api host among
        thousands. The list field is strings; use wasm.names for symbol names.
        A file that is not a readable wasm module is invalid_params; one over
        16 MiB is too_large.
        """
        return _dump(
            analysis.wasm_strings(
                path,
                offset=offset,
                limit=limit,
                min_length=min_length,
                name_filter=name_filter,
            )
        )

    @tools.tool(name="wasm.wat")
    def wasm_wat(
        path: str, timeout: Annotated[float, Field(gt=0, le=600.0)] = 120.0
    ) -> dict[str, Any]:
        """Convert a .wasm module to WebAssembly text (WAT) via wasm2wat.

        Answers with wat and bytes, plus truncated when the text was cut at
        the buffer. WAT expands well past a module's byte size, so on a real
        module the buffer is usually hit: the whole listing is then written to
        a file and its path returned as wat_path, and capture_truncated marks
        the rarer case where even that file is a prefix. An input over 16 MiB
        is refused as too_large rather than handed to wasm2wat.
        """
        return _dump(analysis.wasm_wat(path, timeout=timeout))

    @tools.tool(name="wasm.info")
    def wasm_info(
        path: str, timeout: Annotated[float, Field(gt=0, le=600.0)] = 120.0
    ) -> dict[str, Any]:
        """Dump sections and details of a .wasm module via wasm-objdump.

        Answers with objdump holding that text, not a sections list, plus
        truncated when the text was cut at the buffer. When truncated, the
        whole dump is written to a file and its path returned as objdump_path,
        and capture_truncated marks the rarer case where even that file is a
        prefix. An input over 16 MiB is refused as too_large rather than handed
        to wasm-objdump.
        """
        return _dump(analysis.wasm_info(path, timeout=timeout))

    return tools.bindings
