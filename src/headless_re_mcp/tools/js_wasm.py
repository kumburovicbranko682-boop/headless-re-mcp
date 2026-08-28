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

    @tools.tool(name="js.strings")
    def js_strings(
        path: str,
        min_length: Annotated[int, Field(ge=1, le=64)] = 4,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=2000)] = 200,
    ) -> dict[str, Any]:
        """Extract string literals from a JavaScript file (pure Python, no webcrack).

        Where js.deobfuscate/js.beautify need Node/webcrack, this reads the
        source itself, so it answers on any host -- the JS analogue of
        apk.strings / wasm.strings. A small state machine walks the source and
        pulls out single-quoted, double-quoted and template literals, decoding
        escape sequences (\\xHH, \\uHHHH, \\u{...} and the named ones). It skips
        line and block comments, and detects regular-expression literals so a
        quote inside /["']/ is not misread as a string. This is the fastest
        triage for URLs, keys, selectors and dynamic-eval payloads hiding in a
        minified script; pair it with js.deobfuscate first when the source is
        packed.

        Answers with items (paged), count, total, offset, has_more, min_length
        and scan_capped. Each row carries value (the decoded literal), quote
        (single/double/template), line (1-based start line) and length (of the
        decoded value); truncated marks a value cut at the 8192-char cap, and
        unterminated marks a single/double literal that ran to a newline or EOF
        without its closing quote. min_length (default 4, 1..64) sets the
        shortest decoded value kept. Read has_more so a filled page is not read
        as every literal. Template values keep their raw ${...} interpolations;
        a quote inside an obscure regex may still be misparsed.

        A file over 16 MiB is refused as too_large and a missing one as
        not_found; there is no strings, items_truncated or capability_unavailable
        field here.
        """
        return _dump(
            analysis.js_strings(path, min_length=min_length, offset=offset, limit=limit)
        )

    @tools.tool(name="js.urls")
    def js_urls(
        path: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=2000)] = 200,
    ) -> dict[str, Any]:
        """Extract network indicators (URLs, hosts, IPs) from a JavaScript file.

        js.strings lists every literal; this distils the network-relevant ones
        -- the C2 endpoints, API bases, tracking beacons and hard-coded IPs a
        triage wants first -- into a deduped, host-rolled-up inventory, the JS
        counterpart to apk.urls. Pure Python, no webcrack. It scans the raw
        source (not only string literals), so a URL sitting in a comment is
        caught too. Deobfuscate a packed script first when the endpoints are
        assembled from fragments.

        Answers with urls (paged, sorted; each {url, scheme, host}), count,
        total, offset, has_more, then a hosts roll-up (each {host, count},
        most-common first) with host_count and hosts_truncated, an ips list with
        ip_count, and scan_capped when a collection cap was hit. Absolute
        http/https/ws/wss/ftp URLs only; trailing prose punctuation is stripped.
        Read has_more so a filled page is not read as every URL.

        A file over 16 MiB is refused as too_large and a missing one as
        not_found.
        """
        return _dump(analysis.js_urls(path, offset=offset, limit=limit))

    @tools.tool(name="js.imports")
    def js_imports(
        path: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=2000)] = 200,
    ) -> dict[str, Any]:
        """Extract the module dependency graph from a JavaScript file (pure Python).

        js.strings and js.urls read literals and IOCs; this reads the wiring --
        every ESM ``import``/``export ... from``, CommonJS ``require()``, dynamic
        ``import()`` and worker ``importScripts()`` -- so a triage can see what a
        bundle pulls in (CDNs, npm packages, sibling chunks) and where. No
        webcrack/Node needed. Matches are validated against a comment/string/
        regex map, so a require() written inside a string or comment is not
        counted, and a specifier inside a regex is ignored.

        Answers with imports (paged, sorted by specifier), count, total, offset,
        has_more, a kinds tally (occurrences per esm_import / esm_export /
        dynamic_import / require / import_scripts), a packages roll-up (each
        {package, count}, bare specifiers only, most-common first) with
        package_count and packages_truncated, and scan_capped. Each import row
        carries specifier (the raw module string), kind, category (relative for
        ./ or / paths, url for scheme:// or //, else bare), package (the npm
        package for a bare specifier -- @scope/name or the first path segment --
        else null), count (occurrences) and lines (up to 5 sample 1-based line
        numbers). Read has_more so a filled page is not read as every import.

        A file over 16 MiB is refused as too_large and a missing one as
        not_found.
        """
        return _dump(analysis.js_imports(path, offset=offset, limit=limit))

    @tools.tool(name="js.api_usage")
    def js_api_usage(path: str) -> dict[str, Any]:
        """Scan a JavaScript file for sensitive-API sinks, grouped by threat category.

        Where js.imports reads what a script pulls in and js.urls where it talks,
        this reads what it can *do*: it scans a code skeleton with comments,
        string literals and regex literals blanked (so a name inside a string or
        comment never counts) for a curated table of dangerous sinks, the JS
        counterpart to apk.api_usage. Categories are the words a reviewer greps
        for: code_execution (eval, new Function, setTimeout/setInterval,
        execScript), dom_injection (innerHTML/outerHTML, document.write,
        insertAdjacentHTML), network (fetch, XMLHttpRequest, WebSocket,
        sendBeacon, EventSource), storage (localStorage, sessionStorage,
        indexedDB, document.cookie), encoding (atob/btoa, unescape,
        decodeURIComponent, fromCharCode, charCodeAt), crypto (crypto.subtle,
        CryptoJS), messaging (postMessage) and node_exec (child_process, exec,
        spawn). Pure Python, no webcrack. Deobfuscate a packed script first so
        the sinks are visible.

        Answers with categories (sorted by hit count, then name), category_count,
        total_hits and scan_capped. Each category carries category, hits (its
        total matches), apis (each {api, count, lines} -- up to 5 sample 1-based
        line numbers, ranked by count), api_count and apis_truncated. A category
        with no hit is absent rather than reported empty. This is a lexical scan,
        not a data-flow proof: a match names a call site, not a reachable one.

        A file over 16 MiB is refused as too_large and a missing one as
        not_found.
        """
        return _dump(analysis.js_api_usage(path))

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

    @tools.tool(name="wasm.elements")
    def wasm_elements(
        path: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=2000)] = 100,
    ) -> dict[str, Any]:
        """List a .wasm module's element segments: the indirect-call dispatch table.

        summary only counts element segments; this decodes each one's table-slot
        map, so you can resolve a call_indirect target in a stripped module:
        table slot = the segment's offset base plus the position in func_indices,
        and func_indices[k] is the function installed there. Handles all eight
        encodings (active/passive/declarative, funcidx-vector and element-
        expression forms). Pure Python, no wabt.

        Answers with elements (paged), count, total, offset, has_more and
        scan_capped. Each segment carries index, mode (active/passive/
        declarative), table_index (the table it fills, or null for passive/
        declarative), offset (the base slot as a decoded const-init dict like
        {op:i32.const,value:0}, or null when not active), element_type
        (funcref/externref), func_indices (the installed function indices; a null
        entry is a ref.null slot), count (declared entry count) and
        entries_truncated (the per-segment entry cap was hit).

        A file that is not a WebAssembly module is refused as invalid_params and
        one over 16 MiB as too_large.
        """
        return _dump(analysis.wasm_elements(path, offset=offset, limit=limit))

    @tools.tool(name="wasm.data")
    def wasm_data(
        path: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """List a .wasm module's data segments with memory offsets and previews.

        summary only counts data segments and wasm.strings pulls printable runs
        out of them; this lays out the segment table itself, so a runtime memory
        read can be tied back to the constant that seeded it: for an active
        segment, memory address = the offset base plus the position within the
        blob. Pure Python, no wabt.

        Answers with segments (paged), count, total, offset, has_more and
        scan_capped. Each segment carries index, mode (active/passive),
        memory_index (the linear memory it targets, or null for passive), offset
        (the base address as a decoded const-init dict like {op:i32.const,
        value:1024}, or null for passive), size (bytes), hex and text (a bounded
        64-byte preview; non-printable bytes render as '.') and preview_truncated
        (the blob is larger than the preview).

        A file that is not a WebAssembly module is refused as invalid_params and
        one over 16 MiB as too_large.
        """
        return _dump(analysis.wasm_data(path, offset=offset, limit=limit))

    @tools.tool(name="wasm.names")
    def wasm_names(
        path: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """Recover a .wasm module's symbol table from its name custom section.

        The single most valuable read on a module that kept its names, and pure
        Python -- no wabt. Where wasm.functions borrows only function names, this
        dumps the whole name section: the module name, the function name map, and
        (the part nothing else surfaces) the per-function local and argument
        names that make a decompilation readable.

        Answers with has_name_section (false on a stripped module), module (the
        module name or null), functions (paged index->name entries sorted by
        index), function_count, function_total, offset, has_more, then locals,
        local_function_count and locals_truncated. Each locals row carries
        function (the function index), names (a list of {index, name} for its
        locals/arguments), name_count and names_truncated. The offset/limit page
        the function-name list; the locals list is bounded to 200 functions and
        100 names each.

        A file that is not a WebAssembly module is refused as invalid_params and
        one over 16 MiB as too_large.
        """
        return _dump(analysis.wasm_names(path, offset=offset, limit=limit))

    @tools.tool(name="wasm.tables")
    def wasm_tables(
        path: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=2000)] = 100,
    ) -> dict[str, Any]:
        """List a .wasm module's tables (section 4) with reftype and limits.

        The one section type without its own lister: summary reports memory and
        the start function, and functions/globals/exports/imports/elements/data
        each have a tool, but the table definitions -- the indirect-call dispatch
        tables that wasm.elements fills in -- were only visible as import rows.
        This walks the whole table index space, imported tables first then
        defined. Pure Python, no wabt.

        Answers with tables (paged), count, total, offset, has_more,
        imported_count, defined_count, resolved (false when the table section
        will not parse, though imported tables still list) and scan_capped. Each
        table carries index (its position in the table index space), origin
        (imported/defined), element_type (funcref/externref), limits ({initial,
        maximum, shared}) and, for imported tables, module and name (null on
        defined tables).

        A file that is not a WebAssembly module is refused as invalid_params and
        one over 16 MiB as too_large.
        """
        return _dump(analysis.wasm_tables(path, offset=offset, limit=limit))

    @tools.tool(name="wasm.code")
    def wasm_code(
        path: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=2000)] = 100,
    ) -> dict[str, Any]:
        """List a .wasm module's per-function code bodies (section 10).

        The one big section no other tool exposes: functions lists signatures,
        this lists what each defined function actually weighs. Rows are keyed to
        the function index (imported functions have no body, so indices start
        after them), carry the body_size in bytes and the local declaration
        groups, and pick up the debug name from the name section when present.
        body_size is the fastest obfuscation tell in a module -- one function
        dwarfing the rest is the classic interpreter / packed-blob shape. Pure
        Python, no wabt.

        Answers with functions (paged), count, total, offset, has_more,
        imported_count, resolved (false when the code section will not parse)
        and scan_capped. Each function carries index, body_size, local_count,
        local_groups (each {count, type}), local_groups_truncated and, when the
        name section names it, name.

        A file that is not a WebAssembly module is refused as invalid_params and
        one over 16 MiB as too_large.
        """
        return _dump(analysis.wasm_code(path, offset=offset, limit=limit))

    @tools.tool(name="wasm.disassemble")
    def wasm_disassemble(
        path: str,
        function: Annotated[int, Field(ge=0)],
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=5000)] = 200,
    ) -> dict[str, Any]:
        """Decode one defined function's instruction stream (section 10).

        wasm.code weighs each function; this reads what one function does. The
        only way to see a wasm function's actual instructions when no source or
        wat is on hand -- the wasm analogue of ghidra.disassemble. function is
        the absolute function index (same numbering as wasm.functions / wasm.code
        / wasm.callgraph), so an index below imported_count names an import,
        which has no body. The decoder models the MVP plus bulk-memory,
        reference-type and sign-extension opcodes; on a SIMD/atomic or unknown
        opcode it stops cleanly rather than desync, so what it emits is
        trustworthy. Pure Python, no wabt.

        Answers with function, found (false when the index has no defined body),
        imported (true when the index names an import), name (from the name
        section when present), body_size, local_count, instructions (paged),
        count, total, offset, has_more, complete (the whole body decoded),
        stopped_reason (e.g. unsupported_opcode:0xfd when the decode stopped),
        resolved (false when the code section will not parse) and scan_capped.
        Each instruction carries offset (byte offset in the body), op (the
        mnemonic, or op_0xNN for an unnamed numeric op), opcode (hex) and
        operands (a list of rendered immediates: an index, a const value, a
        block type, memarg align/offset...).

        A file that is not a WebAssembly module is refused as invalid_params and
        one over 16 MiB as too_large.
        """
        return _dump(
            analysis.wasm_disassemble(path, function, offset=offset, limit=limit)
        )

    @tools.tool(name="wasm.callgraph")
    def wasm_callgraph(
        path: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """Build a .wasm module's static call graph (section 10).

        wasm.disassemble reads one function; this reads how they wire together --
        the whole-module structure needed to find the entry reach, the functions
        that fan out into the imported host surface, and dead code. Each defined
        function's `call` targets are collected (deduplicated, with imported
        targets flagged so a call into wasi_snapshot_preview1.* or env.* stands
        out) plus a count of `call_indirect` sites, which name no static target.
        Reuses the disassembler, so a body that hits a SIMD/atomic or unknown
        opcode is marked complete false with the edges found so far still real.
        Pure Python, no wabt.

        Answers with functions (paged over the defined functions), count, total,
        offset, has_more, imported_count, edge_count (distinct direct call edges
        over every scanned function), resolved (false when the code section will
        not parse) and scan_capped. Each function carries index (absolute,
        matching wasm.functions / wasm.disassemble), name, calls (each {index,
        name, imported}), call_count (distinct direct callees, which can exceed
        the listed calls when capped), callees_truncated, indirect_call_count and
        complete.

        A file that is not a WebAssembly module is refused as invalid_params and
        one over 16 MiB as too_large.
        """
        return _dump(analysis.wasm_callgraph(path, offset=offset, limit=limit))

    return tools.bindings
