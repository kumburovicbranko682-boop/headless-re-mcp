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
        the buffer. When truncated, the full output is written to a file and
        its path returned as code_path -- read that for the complete source
        rather than treating the inline code as whole. An input over 16 MiB is
        refused as too_large rather than handed to webcrack.
        """
        return _dump(analysis.js_deobfuscate(path, timeout=timeout))

    @tools.tool(name="js.beautify")
    def js_beautify(
        path: str, timeout: Annotated[float, Field(gt=0, le=600.0)] = 120.0
    ) -> dict[str, Any]:
        """Return a readable, unminified form of a JavaScript file via webcrack.

        Same payload as js.deobfuscate: Answers with code and bytes, plus
        truncated when the text was cut at the buffer, and code_path to the
        full output when it was. An input over 16 MiB is refused as too_large
        rather than handed to webcrack.
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

        Answers with wat and bytes, plus truncated when the text was cut at
        the buffer. When truncated, the full WAT is written to a file and its
        path returned as wat_path -- a real module's disassembly runs to many
        megabytes, so read that rather than reading the inline wat as whole.
        An input over 16 MiB is refused as too_large rather than handed to
        wasm2wat.
        """
        return _dump(analysis.wasm_wat(path, timeout=timeout))

    @tools.tool(name="wasm.info")
    def wasm_info(
        path: str, timeout: Annotated[float, Field(gt=0, le=600.0)] = 120.0
    ) -> dict[str, Any]:
        """Dump sections and details of a .wasm module via wasm-objdump.

        Answers with objdump holding that text, not a sections list, plus
        truncated when the text was cut at the buffer, and objdump_path to the
        full dump when it was. An input over 16 MiB is refused as too_large
        rather than handed to wasm-objdump.
        """
        return _dump(analysis.wasm_info(path, timeout=timeout))

    @tools.tool(name="wasm.summary")
    def wasm_summary(path: str) -> dict[str, Any]:
        """Structured import/export/memory summary of a .wasm module.

        Parses the module's section table directly in pure Python -- no wabt
        needed, so this answers even when wasm2wat/wasm-objdump are absent.
        Answers with imports (each module/name/kind, kind one of
        func/table/memory/global), import_count, exports (each name/kind/index),
        export_count, memory (initial/maximum pages, or null when the module
        declares none), has_start, custom_sections (their names, e.g. "name"),
        and counts (types, functions defined in this module, imported_functions,
        tables, globals, memories, data_segments, elements). The import list is
        the host/JS/WASI interop boundary; exports are the callable surface.
        Both lists cap at 4096 -- read imports_truncated/imports_total/
        imports_limit and the exports_* counterparts when a list filled the cap.
        An input over 16 MiB is refused as too_large; a non-module is rejected
        as invalid_params rather than guessed at.
        """
        return _dump(analysis.wasm_summary(path))

    @tools.tool(name="wasm.strings")
    def wasm_strings(
        path: str,
        min_length: Annotated[int, Field(ge=1, le=256)] = 4,
        contains: str | None = None,
    ) -> dict[str, Any]:
        """Printable strings a .wasm module embeds in its data segments.

        Compiled WebAssembly keeps its string literals -- URLs, host names,
        api_key/token markers, error and format strings -- in the data section
        that initializes linear memory. This parses that section directly in
        pure Python (no wabt needed, so it answers even when wasm2wat/
        wasm-objdump are absent) and scans each segment for printable ASCII
        runs. Answers with strings, each carrying string, segment (the data
        segment index) and addr (its linear-memory address, present only when
        the segment's offset is a literal constant); plus count, total,
        data_segments (how many segments the module has), min_length, and
        scan_capped (true when more strings exist beyond the 4096 cap).

        min_length is the shortest run to keep (default 4) -- raise it to cut
        noise, lower it to catch short markers. Pass contains to keep only
        strings containing a case-insensitive substring (a host, a key marker);
        the filter runs during the scan so the 4096 cap bounds matches, and the
        reply then also carries filtered true and query. Only the data section
        is read; an input over 16 MiB is refused as too_large and a non-module
        as invalid_params. This is wasm.summary's companion: summary is the
        import/export surface, this is the embedded string surface.
        """
        return _dump(analysis.wasm_strings(path, min_length=min_length, contains=contains))

    @tools.tool(name="wasm.names")
    def wasm_names(path: str, contains: str | None = None) -> dict[str, Any]:
        """Module and function names from a .wasm module's name custom section.

        The name section is WebAssembly's debug symbol table: a non-stripped
        build (or a dev build) records the readable name of each function index,
        so an internal function that never made the export table -- invisible to
        wasm.summary, which only lists exports -- still has a name here. This is
        the WASM parallel of a native symbol table, parsed directly in pure
        Python (no wabt needed, so it answers even when wasm2wat/wasm-objdump are
        absent). Answers with has_name_section (false for a stripped module,
        which is a different answer from a present-but-empty table), module_name
        (the module's own name, or null), functions (each carrying index and
        name), count, total, and scan_capped (true when more names exist beyond
        the 4096 cap). Pass contains to keep only names containing a
        case-insensitive substring (a getter, a crypto routine); the filter runs
        during the scan so the 4096 cap bounds matches, and the reply then also
        carries filtered true and query. An input over 16 MiB is refused as
        too_large and a non-module as invalid_params. This completes the
        wasm.summary/wasm.strings/wasm.names trio: the export surface, the string
        surface, and the internal-name surface.
        """
        return _dump(analysis.wasm_names(path, contains=contains))

    @tools.tool(name="wasm.sections")
    def wasm_sections(path: str) -> dict[str, Any]:
        """The section table of a .wasm module: id, name, size and file offset.

        wasm.summary counts what is inside the sections; this is the map of the
        sections themselves -- the WASM parallel of a native section table
        (r2.sections). Parsed directly in pure Python (no wabt needed, so it
        answers even when wasm2wat/wasm-objdump are absent). Answers with
        version and sections, each carrying id (the numeric section id), name
        (custom/type/import/function/table/memory/global/export/start/element/
        code/data/data_count/tag, or "section <n>" for an id from a newer
        proposal), size (the body length in bytes) and offset (the body's byte
        offset in the file, so a caller can carve or seek). A custom section
        also carries custom_name and payload_size (the bytes after the name),
        so a fat custom section hiding a payload is not mistaken for a fat
        standard section. Also count and total; sections_truncated with
        sections_total/sections_limit mark a module with more than 4096 sections
        (a hostile fan-out of tiny custom sections). An input over 16 MiB is
        refused as too_large and a non-module as invalid_params. This is where
        you find the code/data section offsets and spot an oversized custom
        section, completing the wasm.summary/strings/names/sections static set.
        """
        return _dump(analysis.wasm_sections(path))

    @tools.tool(name="wasm.functions")
    def wasm_functions(path: str, contains: str | None = None) -> dict[str, Any]:
        """The module's function table with resolved signatures (pure Python).

        wasm.summary only counts functions and wasm.names only maps an index to
        a name; neither gives a function's signature or says which functions are
        imported from the host versus defined in the module. This joins the
        type, import and function sections into one addressed table (and attaches
        each name from the name section when present) -- the WASM parallel of a
        native function/symbol table with signatures. Parsed directly in pure
        Python, so it answers even when wasm2wat/wasm-objdump are absent.

        Answers with functions, each carrying index (the global function index,
        imported functions first), kind (imported/defined), type_index, params
        and results (value-type names such as i32/i64/f32/f64/v128/funcref/
        externref), plus name when the name section has one and, for an imported
        function, module and import_name. signature_unknown is set when the type
        index cannot be resolved (a truncated type section, or a GC type this
        parser stops at). Also count, total, imported_count and defined_count
        (the module's structural totals), and scan_capped (true when more than
        4096 functions matched). Pass contains to keep only functions whose
        name/module/import_name holds a case-insensitive substring; the filter
        runs during assembly so the 4096 cap bounds matches, and the reply then
        also carries filtered true and query. An input over 16 MiB is refused as
        too_large and a non-module as invalid_params.
        """
        return _dump(analysis.wasm_functions(path, contains=contains))

    @tools.tool(name="wasm.exports")
    def wasm_exports(path: str, contains: str | None = None) -> dict[str, Any]:
        """The module's export table -- its callable surface -- with signatures.

        The export section is the module's public API: the names JS reaches via
        instance.exports. wasm.summary lists them coarsely (name/kind/index) and
        wasm.functions lists every function but not which are exported; neither
        resolves an exported function's signature. This joins the export section
        to the type/import/function sections, so a function export comes back
        with the exact ABI a caller invokes. Parsed in pure Python, so it answers
        even when wasm2wat/wasm-objdump are absent.

        Answers with exports, each carrying name (the exported name), kind
        (func/table/memory/global) and index (into that kind's space). A func
        export also carries origin (imported/defined -- a re-exported host import
        versus a module function), type_index, params and results (value-type
        names such as i32/i64/f32/f64/v128/funcref/externref), internal_name when
        the name section has one, and signature_unknown when the type cannot be
        resolved. Also count, total and scan_capped (more exports exist than the
        4096 listed). Pass contains to keep only exports whose name/kind holds a
        case-insensitive substring; the reply then also carries filtered true and
        query. An input over 16 MiB is refused as too_large and a non-module as
        invalid_params.
        """
        return _dump(analysis.wasm_exports(path, contains=contains))

    @tools.tool(name="wasm.imports")
    def wasm_imports(path: str, contains: str | None = None) -> dict[str, Any]:
        """The module's import table -- what it requires from the host -- decoded.

        The import section is the module's host boundary: every function,
        memory, table and global it cannot run without. wasm.summary names
        imports coarsely (module/name/kind) and wasm.functions resolves only the
        imported functions; neither decodes the non-func descriptors. This
        decodes all four kinds and is the mirror of wasm.exports: exports say
        what the module provides, imports say what it demands. Parsed in
        pure Python, so it answers even when wasm2wat/wasm-objdump are absent.

        Answers with imports, each carrying module (the host-side namespace,
        e.g. env or wasi_snapshot_preview1), name, kind and index (the slot in
        that kind's index space -- imports fill the low indices, so a func
        import's index is its global function index). A func entry adds
        type_index, params and results (value-type names), with
        signature_unknown when unresolvable; a table entry reftype plus
        initial/maximum; a memory entry initial/maximum in 64 KiB pages plus
        shared when the threads flag is set; a global entry valtype and mutable.
        Also count, total, scan_capped (more imports exist than the 4096
        listed), exact per-kind func_count/table_count/memory_count/
        global_count, and the distinct source modules as modules/module_count.
        Pass contains to keep only imports whose module/name/kind holds a
        case-insensitive substring; the reply then also carries filtered true
        and query. An input over 16 MiB is refused as too_large and a non-module
        as invalid_params.
        """
        return _dump(analysis.wasm_imports(path, contains=contains))

    return tools.bindings
