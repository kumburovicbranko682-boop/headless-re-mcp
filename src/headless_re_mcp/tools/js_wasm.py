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

    @tools.tool(name="wasm.data")
    def wasm_data(
        path: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """Map a WebAssembly module's data segments to linear memory, wabt-free.

        The data section's load map: it lists each segment's mode and where it
        lands, in pure Python, so unlike wasm.info / wasm.wat it needs no wabt
        installed, and it is the structural companion to wasm.strings (which
        pulls the text out of the same bytes). Each row is index, mode (active --
        copied into memory at instantiation -- or passive -- copied on demand by
        memory.init) and size, the payload's byte length. An active segment also
        carries memory_index (which linear memory it targets, almost always 0)
        and memory_offset, the destination address when that offset is a plain
        i32.const; a computed offset (e.g. global.get) leaves memory_offset null
        rather than guessing. Segment bytes themselves are not returned -- use
        wasm.strings for their text. Answers with has_data_section (false when
        the module has none -- then segments is empty and total 0, not an error),
        segments, count, total, offset and has_more so a filled page is not read
        as every segment; total is capped at 50000 with scan_capped when more may
        exist, and truncated is true when a segment length or offset expression
        is malformed (segments read so far are still returned). A file that is
        not a WebAssembly module is refused as invalid_params, one over 16 MiB as
        too_large.
        """
        return _dump(analysis.wasm_data(path, offset=offset, limit=limit))

    @tools.tool(name="wasm.exports")
    def wasm_exports(
        path: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """List a WebAssembly module's exports (its public surface), wabt-free.

        The mirror of wasm.imports: it reads the .wasm binary directly in pure
        Python, so unlike wasm.info / wasm.wat it needs no wabt installed.
        Exports are what the module hands back to its host -- the functions the
        JS glue can call and the memories, tables and globals it can reach -- so
        they are the module's public API and the first thing to read when
        deciding what a blob offers (an exported _malloc/_free and a table says
        an Emscripten runtime; a single exported hash function says a shim).
        Each row is name, kind (func, table, memory or global) and index, the
        position in that kind's index space; the index counts imported entries
        of the same kind first, per the WASM spec, so it is not a row number.
        Answers with exports, count, total, offset and has_more so a filled page
        is not read as every export; total is capped at 5000 with scan_capped
        when more may exist, and truncated is true when a malformed or short
        module cut the parse (entries read so far are still returned). A file
        that is not a WebAssembly module is refused as invalid_params, one over
        16 MiB as too_large.
        """
        return _dump(analysis.wasm_exports(path, offset=offset, limit=limit))

    @tools.tool(name="wasm.functions")
    def wasm_functions(
        path: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """List a WebAssembly module's functions with signatures, wabt-free.

        The capstone of the wabt-free WASM readers: it joins the type, import
        and function sections into one function-index table, so the indices
        match those wasm.names, wasm.exports and wasm.imports report. Each row is
        index (its position in the function index space), kind (import or local),
        type_index (into the type section) and params / results, the value-type
        names of its signature (i32, i64, f32, f64, v128, funcref, externref; an
        exotic or GC type renders as hex). Imported functions come first, per the
        WASM spec, and carry module and name (the import's module and field);
        local functions carry name only when the "name" custom section supplies
        one (imports are named by their import pair, not the name section).
        imported_count marks the import/local boundary. A missing type section
        leaves params and results empty (type_index is still reported) rather
        than erroring, and a stripped module simply yields no local names.
        Answers with functions, count, total, offset and has_more so a filled
        page is not read as every function; total is capped at 50000 with
        scan_capped when more may exist, and truncated is true when a section is
        malformed or a value type is not understood (functions resolved so far
        are still returned). A file that is not a WebAssembly module is refused
        as invalid_params, one over 16 MiB as too_large.
        """
        return _dump(analysis.wasm_functions(path, offset=offset, limit=limit))

    @tools.tool(name="wasm.globals")
    def wasm_globals(
        path: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """List a WebAssembly module's globals (its module-level state), wabt-free.

        Globals are a module's mutable state cells -- the stack pointer, heap
        base, memory/table bases and config flags a runtime threads through the
        code. This lists them in pure Python, so unlike wasm.info / wasm.wat it
        needs no wabt installed, joining the import and global sections into one
        table whose indices match the global index space. Each row is index (its
        position there), kind (import or local), type (the value type: i32, i64,
        f32, f64, v128, funcref, externref, or hex for an exotic one) and mutable
        (true for a var global, false for a const one). Imported globals come
        first, per the WASM spec, and carry module and name (the import's module
        and field); imported_count marks the import/local boundary. Module-
        defined globals each carry an initialiser expression, which is stepped
        over, not evaluated, so no value is reported. Answers with globals,
        count, total, offset and has_more so a filled page is not read as every
        global; total is capped at 50000 with scan_capped when more may exist,
        and truncated is true when a section is malformed or an initialiser uses
        an opcode outside the constant-expression set (globals resolved so far
        are still returned). A file that is not a WebAssembly module is refused
        as invalid_params, one over 16 MiB as too_large.
        """
        return _dump(analysis.wasm_globals(path, offset=offset, limit=limit))

    @tools.tool(name="wasm.imports")
    def wasm_imports(
        path: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """List a WebAssembly module's imports (the JS<->WASM boundary), wabt-free.

        Reads the .wasm binary directly in pure Python, so unlike wasm.info /
        wasm.wat it needs no wabt installed. Imports are what a module pulls from
        its host -- the JS functions, memories, tables and globals it cannot run
        without -- and reading them is the fastest way to see what a module does
        (a memory import plus env.emscripten_* says one thing; a lone crypto
        shim says another). Each row is module, name and kind (func, table,
        memory or global) in binary order, which is the order that assigns each
        import its index. Answers with imports, count, total, offset and
        has_more so a filled page is not read as every import; total is capped at
        5000 with scan_capped when more may exist, and truncated is true when a
        malformed or short module cut the parse (entries read so far are still
        returned). A file that is not a WebAssembly module is refused as
        invalid_params, one over 16 MiB as too_large.
        """
        return _dump(analysis.wasm_imports(path, offset=offset, limit=limit))

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

    @tools.tool(name="wasm.names")
    def wasm_names(
        path: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """Recover a WebAssembly module's debug names (its symbol table), wabt-free.

        The optional "name" custom section is a module's symbol table: it maps
        function indices to source names, the difference between reading _malloc
        and reading func[214]. This parses it in pure Python, so unlike wasm.info
        / wasm.wat it needs no wabt installed, and it complements wasm.sections
        (which only reports that a "name" section exists) and wasm.exports (which
        shows only the handful of names the module chose to expose). Answers with
        has_name_section (false for a stripped module -- then functions is empty
        and total 0, not an error), module (the module's own name, or null), and
        functions, a page of {index, name} where index is the position in the
        function index space (imported functions counted first, per the WASM
        spec). Only the module (subsection 0) and function (subsection 1) name
        maps are surfaced; local and label names are skipped. Answers with count,
        total, offset and has_more so a filled page is not read as every name;
        total is capped at 50000 with scan_capped when more may exist, and
        truncated is true when a subsection's declared size runs past the section
        or a length is malformed (names read so far are still returned). A file
        that is not a WebAssembly module is refused as invalid_params, one over
        16 MiB as too_large.
        """
        return _dump(analysis.wasm_names(path, offset=offset, limit=limit))

    @tools.tool(name="wasm.sections")
    def wasm_sections(
        path: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """List a WebAssembly module's sections (its table of contents), wabt-free.

        The structural overview to read first: it walks the section table in
        pure Python, so unlike wasm.info / wasm.wat it needs no wabt installed,
        and it frames what wasm.imports and wasm.exports drill into. Each row is
        id, name (custom, type, import, function, table, memory, global, export,
        start, element, code, data or data_count -- unknown for an id the spec
        does not define), offset (the byte position of the section's id byte)
        and size (the declared body length). Sections whose body starts with a
        vector -- everything but start and custom -- also carry entries, that
        vector's length (the item count, or for data_count the declared data-
        segment count); a custom section instead carries custom_name, its own
        name (e.g. "name", "producers", ".debug_info"), which is how debug and
        tooling metadata is spotted without a decompiler. Answers with sections,
        count, total, offset and has_more so a filled page is not read as the
        whole table; total is capped at 5000 with scan_capped when more may
        exist, and truncated is true when a section's declared size runs past
        the module or a length is malformed (sections read so far, including the
        short one, are still returned). A file that is not a WebAssembly module
        is refused as invalid_params, one over 16 MiB as too_large.
        """
        return _dump(analysis.wasm_sections(path, offset=offset, limit=limit))

    @tools.tool(name="wasm.strings")
    def wasm_strings(
        path: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        min_length: Annotated[int, Field(ge=1, le=256)] = 4,
    ) -> dict[str, Any]:
        """Extract printable strings from a .wasm module's data section, wabt-free.

        `strings` for WASM: the data section holds a module's initialized memory
        -- its string literals, URLs, file paths, format strings and error
        messages -- and this surfaces them in pure Python, so unlike wasm.info /
        wasm.wat it needs no wabt installed. It scans the raw data-section bytes
        for runs of printable ASCII (0x20..0x7e) rather than parsing each
        segment's offset expression, whose LEB immediates can contain the 0x0B
        end byte and defeat a naive skip; the cost is that a few structural bytes
        between payloads may cling to a string's edge. Runs shorter than
        min_length (default 4) are dropped and longer than 1024 characters
        clipped; results are de-duplicated and kept in first-appearance order,
        which groups strings that sit near each other in memory. Answers with
        has_data_section (false when the module has none -- then strings is empty
        and total 0, not an error), data_bytes (the scanned size), min_length,
        and strings with count, total, offset and has_more so a filled page is
        not read as every string; total is capped at 50000 with scan_capped when
        more may exist, and truncated is true when the section walk hit a
        malformed length. A file that is not a WebAssembly module is refused as
        invalid_params, one over 16 MiB as too_large.
        """
        return _dump(
            analysis.wasm_strings(
                path, offset=offset, limit=limit, min_length=min_length
            )
        )

    return tools.bindings
