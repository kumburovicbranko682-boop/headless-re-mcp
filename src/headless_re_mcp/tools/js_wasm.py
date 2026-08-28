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
        return _dump(analysis.js_unpack_bundle(path, timeout=timeout, offset=offset, limit=limit))

    @tools.tool(name="js.strings")
    def js_strings(
        path: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        min_length: Annotated[int, Field(ge=1, le=256)] = 4,
    ) -> dict[str, Any]:
        """Extract string literals from a JavaScript file, node-free.

        `strings` for JavaScript: it surfaces the quoted literals -- URLs, API
        endpoints, file paths, error messages and embedded secrets -- so unlike
        js.deobfuscate / js.beautify it needs no webcrack or Node installed. It
        reads the source as text and makes one comment-aware pass over ' / " /
        backtick literals, decoding backslash escapes so an obfuscated
        \\x68\\x74\\x74\\x70 or \\u002f reads back as http / a slash. It does
        not fully lex JS: regex literals are not tracked, so a divide/regex
        ambiguity can occasionally misread one -- the accepted cost of a robust
        best-effort scan. Literals shorter than min_length (default 4) are
        dropped and longer than 2048 characters clipped; results are
        de-duplicated and kept in first-appearance order. Answers with
        input_bytes, min_length, and strings with count, total, offset and
        has_more so a filled page is not read as every literal; total is capped
        at 50000 with scan_capped when more may exist, and truncated is true
        when the text ended inside an open literal or block comment. A missing
        file is not_found, one over 16 MiB too_large.
        """
        return _dump(analysis.js_strings(path, offset=offset, limit=limit, min_length=min_length))

    @tools.tool(name="js.endpoints")
    def js_endpoints(
        path: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """Extract the URLs a JavaScript file talks to, node-free.

        The "what does this bundle contact" pivot: it surfaces the
        scheme://host URLs -- http, https, ws, wss, ftp and the like --
        hard-coded in a script's string literals, the C2/API/CDN hosts that are
        the first IOCs of web triage. It reuses js.strings' comment-aware,
        escape-decoding literal scan, so a URL obfuscated as \\x68\\x74\\x74\\x70
        is caught once decoded, and needs no webcrack or Node. To stay
        high-signal it matches only URLs carrying a scheme (schemeless relative
        paths like /api/x are left to js.strings) and reports each url with its
        host (the authority after ://, userinfo stripped). Results are
        de-duplicated by url in first-appearance order. Answers with
        input_bytes and endpoints with count, total, offset and has_more so a
        filled page is not read as every URL; total is capped at 10000 with
        scan_capped when more may exist, and truncated is true when the text
        ended inside an open literal or block comment. A missing file is
        not_found, one over 16 MiB too_large.
        """
        return _dump(analysis.js_endpoints(path, offset=offset, limit=limit))

    @tools.tool(name="js.imports")
    def js_imports(
        path: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """Extract a JavaScript file's module dependencies, node-free.

        The "what does this bundle pull in" pivot: it surfaces the module
        specifiers a script imports -- ESM import / export ... from, dynamic
        import() and CommonJS require() -- the dependency surface you map before
        trusting a bundle. It tokenizes the source comment- and string-aware, so
        an import word inside a comment or string is never miscounted, and needs
        no webcrack or Node. Each specifier is reported with its kind (bare
        package like react / @scope/pkg, relative ./x, absolute /x or a url) and
        the syntax that referenced it (import, export, dynamic, require); a
        computed specifier (a template literal with ${...}) is skipped since it
        is not statically knowable. It does not fully parse JS: regex literals
        are not tracked, so a divide/regex ambiguity can occasionally misread
        one. Results are de-duplicated by specifier in first-appearance order.
        Answers with input_bytes and imports (each row spec, kind and syntax)
        with count, total, offset and has_more so a filled page is not read as
        every dependency; total is capped at 10000 with scan_capped when more
        may exist (also set when the source is so large the token ceiling is
        hit), and truncated is true when the text ended inside an open literal
        or block comment. A missing file is not_found, one over 16 MiB
        too_large.
        """
        return _dump(analysis.js_imports(path, offset=offset, limit=limit))

    @tools.tool(name="js.comments")
    def js_comments(
        path: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
        min_length: Annotated[int, Field(ge=1, le=256)] = 1,
    ) -> dict[str, Any]:
        """Extract the comments from a JavaScript file, node-free.

        The comment counterpart to js.strings: it surfaces the // and /* */ text
        the other scanners skip -- the //# sourceMappingURL= pointer to an
        unminified original, the license/banner headers that fingerprint which
        libraries a bundle vendored, and the TODO/FIXME notes, dead code and
        URLs developers leave behind. It reads the source as text and makes one
        pass that consumes string literals whole, so a // inside a string is
        never mistaken for a comment, and needs no webcrack or Node. It does not
        fully lex JS: regex literals are not tracked, so a divide/regex ambiguity
        can occasionally misread one. Each comment is reported with its text
        (stripped, clipped to 4096 chars), kind (line or block) and 1-based start
        line; bodies shorter than min_length (default 1, so empty comments drop)
        are skipped and results are de-duplicated by body -- a banner repeated
        per module in a bundle collapses to one row -- in first-appearance order.
        Answers with input_bytes, min_length, and comments with count, total,
        offset and has_more so a filled page is not read as every comment; total
        is capped at 50000 with scan_capped when more may exist, and truncated is
        true when the text ended inside an open string or block comment. A
        missing file is not_found, one over 16 MiB too_large.
        """
        return _dump(analysis.js_comments(path, offset=offset, limit=limit, min_length=min_length))

    @tools.tool(name="wasm.callers")
    def wasm_callers(
        path: str,
        function: Annotated[int, Field(ge=0)],
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """Find every function that directly calls a function (xrefs), wabt-free.

        The reverse of wasm.calls: name a target function index and this walks
        every code-section body in pure Python -- no wabt needed -- and reports
        the functions whose bodies contain a direct call / return_call to it,
        the "xrefs to this function" a disassembler shows. It answers the first
        question of a triage -- who reaches this suspicious import or routine
        (resolve the target and the callers against wasm.functions for names) --
        server-side, so a large module's whole call graph need not be paged
        through to filter it client-side. Each row is index (the caller's
        module-wide function index) and call_sites (how many call instructions
        in it target the function, so a helper invoked three times reads as 3)
        with decoded (false when that caller's body used an opcode outside the
        walker's table, meaning its count may be low). Indirect calls are
        invisible here by nature -- a call_indirect names no callee -- so
        wasm.elements enumerates a table's possible targets instead. Returns
        target (echoed back), has_code_section (false when the module has no
        code section -- then callers is empty and total 0, not an error),
        imported_count, undecoded_bodies (functions the walker could not fully
        decode, whose calls to the target may be missed) and callers with count,
        total, offset and has_more so a filled page is not read as every caller;
        total is capped at 50000 with scan_capped when more may exist, and
        truncated is true when the code section itself is malformed (callers
        found so far are still returned). A file that is not a WebAssembly module
        is refused as invalid_params, one over 16 MiB as too_large.
        """
        return _dump(analysis.wasm_callers(path, function=function, offset=offset, limit=limit))

    @tools.tool(name="wasm.calls")
    def wasm_calls(
        path: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """Extract each function's direct call targets (the call graph), wabt-free.

        Who calls whom, statically: the code section's instruction streams are
        walked in pure Python -- no wabt needed -- and every call / return_call
        target is collected per function, so an export can be traced down to the
        routine that does the work (join indices against wasm.functions for
        names; call_indirect dispatch is counted here and its possible targets
        enumerated by wasm.elements). Each row is index (the function's index in
        the module-wide space, where imports occupy [0, imported_count) and have
        no bodies), callees (the function's distinct direct targets, sorted;
        capped at 100 per function with callees_clipped), call_sites and
        call_indirect_sites (instruction counts, so N calls to one helper still
        read as N), and decoded -- false when the body used an opcode outside
        the walker's table (e.g. a GC proposal instruction); the calls found up
        to that point are kept, and because bodies are size-delimited the walk
        resumes cleanly at the next function. Answers with has_code_section
        (false for a module with no code section -- then functions is empty and
        total 0, not an error), imported_count, and functions with count, total,
        offset and has_more so a filled page is not read as the whole graph;
        total is capped at 50000 with scan_capped when more may exist, and
        truncated is true when the section itself is malformed (rows read so far
        are still returned). A file that is not a WebAssembly module is refused
        as invalid_params, one over 16 MiB as too_large.
        """
        return _dump(analysis.wasm_calls(path, offset=offset, limit=limit))

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

    @tools.tool(name="wasm.elements")
    def wasm_elements(
        path: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """Map table slots to functions (the call_indirect targets), wabt-free.

        The element section is where a module fills its tables, so this answers
        the question wasm.tables raises: which functions actually sit in the
        table, i.e. the complete set of indirect-call targets an obfuscator or
        vtable-style dispatcher can reach (join func_index against
        wasm.functions for names). Read in pure Python -- no wabt needed.
        Segments are flattened to one row per table entry: segment (which
        element segment it came from), mode (active is copied into a table at
        instantiation, passive waits for table.init, declared only
        forward-declares functions for ref.func), table_index (the target table
        for active segments, null otherwise), slot (the concrete table index the
        entry lands in when the segment's offset is a simple i32.const; null for
        a computed offset such as global.get, and for passive/declared
        segments) and func_index (null for a ref.null or non-function entry).
        Answers with has_element_section (false when the module has none -- then
        entries is empty and total 0, not an error), segment_count, and entries
        with count, total, offset and has_more so a filled page is not read as
        every entry; total is capped at 50000 with scan_capped when more may
        exist, and truncated is true when a segment is malformed (entries read
        so far are still returned). A file that is not a WebAssembly module is
        refused as invalid_params, one over 16 MiB as too_large.
        """
        return _dump(analysis.wasm_elements(path, offset=offset, limit=limit))

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

    @tools.tool(name="wasm.features")
    def wasm_features(
        path: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """List the WebAssembly features a module was built to use, wabt-free.

        The "target_features" custom section is the capability requirement a
        toolchain (LLVM / wasm-ld) records: which proposals beyond the MVP the
        module uses -- simd128, atomics (threads and shared memory),
        exception-handling, bulk-memory, reference-types, tail-call, sign-ext,
        multivalue and the like. Read in pure Python -- no wabt needed -- it
        tells a triage what runtime the module needs and how much of the modern
        instruction set to expect, which wasm.sections cannot (it only reports
        the custom section exists). It is the capability companion to
        wasm.producers' provenance. Each row is name (the feature) and prefix,
        the one-byte marker: "+" the feature is used, "-" it must not be
        enabled, "=" it is required exactly (an unknown marker byte renders as
        hex); wasm-ld emits "+" for everything a module actually uses, so in
        practice the rows are the used-feature set. Returns
        has_target_features_section (false when the module has none -- then
        features is empty and total 0, not an error) and features with count,
        total, offset and has_more so a filled page is not read as the whole
        set; total is capped at 10000 with scan_capped when more may exist, and
        truncated is true when the section is malformed (rows read so far are
        still returned). The section is self-reported and strippable, so its
        absence is not proof the features are unused. A file that is not a
        WebAssembly module is refused as invalid_params, one over 16 MiB as
        too_large.
        """
        return _dump(analysis.wasm_features(path, offset=offset, limit=limit))

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

    @tools.tool(name="wasm.memory")
    def wasm_memory(
        path: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """List a WebAssembly module's linear memories (its footprint), wabt-free.

        The memory declaration a module cannot run without, read in pure Python,
        so unlike wasm.info / wasm.wat it needs no wabt installed and it says
        more than wasm.sections (which only reports that a memory section
        exists). It joins the import and memory sections into one table over the
        memory index space. Each row is index, kind (import or local), min and
        max, the size bounds in 64 KiB pages (max is null when the module sets
        none, i.e. the memory may grow unbounded), shared (true for a
        threads/atomics memory) and index_type (i64 for a memory64 memory, else
        i32). Imported memories come first, per the WASM spec, and carry module
        and name (the import's module and field); imported_count marks the
        import/local boundary. Most modules declare exactly one memory, but the
        multi-memory proposal allows several. Answers with memories, count,
        total, offset and has_more so a filled page is not read as every memory;
        total is capped at 50000 with scan_capped when more may exist, and
        truncated is true when a limits record is malformed (memories read so far
        are still returned). A file that is not a WebAssembly module is refused
        as invalid_params, one over 16 MiB as too_large.
        """
        return _dump(analysis.wasm_memory(path, offset=offset, limit=limit))

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

    @tools.tool(name="wasm.producers")
    def wasm_producers(
        path: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """Decode a WebAssembly module's build-toolchain fingerprint, wabt-free.

        The "producers" custom section records what built the module -- the
        source language, the compilers and tools it passed through, and the SDK
        -- so this is the provenance a triage opens with: knowing it came from
        Rust 1.75 via LLVM, or Emscripten, or wasm-bindgen, points straight at
        the right deobfuscation and naming strategy. Read in pure Python -- no
        wabt needed -- and it says what wasm.sections cannot (that tool only
        reports the custom section exists). The section's fields (conventionally
        language, processed-by and sdk) are flattened to one row per tool: field
        (which of the three it came from), name (the language or tool, e.g.
        Rust, clang, wasm-bindgen) and version (a free-form string, empty when
        the producer left it blank). Returns has_producers_section (false when
        the module has none -- then producers is empty and total 0, not an
        error), and producers with count, total, offset and has_more so a filled
        page is not read as the whole list; total is capped at 10000 with
        scan_capped when more may exist, and truncated is true when the section
        is malformed (rows read so far are still returned). Note the section is
        self-reported and strippable, so its absence is not proof of anything. A
        file that is not a WebAssembly module is refused as invalid_params, one
        over 16 MiB as too_large.
        """
        return _dump(analysis.wasm_producers(path, offset=offset, limit=limit))

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

    @tools.tool(name="wasm.start")
    def wasm_start(path: str) -> dict[str, Any]:
        """Report a WebAssembly module's start function -- what runs on load, wabt-free.

        The start section names the one function a runtime calls automatically
        when the module is instantiated, before any export is invoked, which
        makes it a prime spot for initialisation, self-unpacking or
        anti-analysis code -- the first thing to read when a module "does
        something" merely by loading. Read in pure Python -- no wabt needed.
        Unlike the listing tools this returns a scalar, because a module has at
        most one start function: has_start_section (false when the module
        declares none -- the common case, not an error), start_function (its
        module-wide function index, or null), and kind -- "import" when that
        index falls in the imported range, which is unusual and worth noting,
        "local" for a module-defined function, or null when there is no start
        (resolve the index against wasm.functions for a name, and wasm.calls for
        what it goes on to invoke). imported_count is given as the context
        needed to read the index. truncated is true when the section is
        malformed. A file that is not a WebAssembly module is refused as
        invalid_params, one over 16 MiB as too_large.
        """
        return _dump(analysis.wasm_start(path))

    @tools.tool(name="wasm.opcodes")
    def wasm_opcodes(path: str) -> dict[str, Any]:
        """Tally a WebAssembly module's instruction mix by family, wabt-free.

        A "what does this module do" fingerprint: every function body in the
        code section is walked in pure Python -- no wabt needed -- and each
        opcode is bucketed into a family, so a glance says whether a module is
        memory-heavy, SIMD-accelerated, call-dense or plain arithmetic without
        disassembling it (pair with wasm.calls for the call graph and
        wasm.features for the proposals declared). The families are control,
        call, call_indirect, parametric, variable, table, memory, reference,
        numeric, simd and atomic; categories carries only the families present,
        each with a count, sorted by count then name. Unlike the listing tools
        this is an aggregate and does not page. It also reports total_functions
        (bodies in the code section), decoded_functions (those walked to the end
        -- a body that hits an opcode outside the walker's table, e.g. a GC
        proposal instruction, is abandoned but its opcodes up to that point are
        still counted, so decoded_functions < total_functions signals a partial
        tally) and instruction_count (opcodes tallied in total). Answers with
        has_code_section (false for a module with no code section -- then
        categories is empty and the counts are 0, not an error); scan_capped is
        true when the module has more functions than the walk ceiling, and
        truncated when the section itself is malformed. A file that is not a
        WebAssembly module is refused as invalid_params, one over 16 MiB as
        too_large.
        """
        return _dump(analysis.wasm_opcodes(path))

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
        return _dump(analysis.wasm_strings(path, offset=offset, limit=limit, min_length=min_length))

    @tools.tool(name="wasm.tables")
    def wasm_tables(
        path: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """List a WebAssembly module's tables (indirect-call surface), wabt-free.

        Tables are where call_indirect targets live: a funcref table holds the
        function pointers an optimizer or obfuscator dispatches through, so its
        size bounds how much indirect dispatch a module can do (wasm.sections
        only says a table section exists). Read in pure Python -- no wabt
        needed. Joins the import and table sections into one view over the table
        index space. Each row is index, kind (import or local), element_type
        (funcref for function pointers, externref for host references; an
        unknown reference-type byte renders as hex), and min and max, the size
        bounds in entries (max is null when the module sets none). Imported
        tables come first, per the WASM spec, and carry module and name --
        Emscripten modules typically import env.__indirect_function_table, a
        strong linkage signal; imported_count marks the import/local boundary.
        Answers with tables, count, total, offset and has_more so a filled page
        is not read as every table; total is capped at 50000 with scan_capped
        when more may exist, and truncated is true when a tabletype is malformed
        (tables read so far are still returned). A file that is not a
        WebAssembly module is refused as invalid_params, one over 16 MiB as
        too_large.
        """
        return _dump(analysis.wasm_tables(path, offset=offset, limit=limit))

    return tools.bindings
