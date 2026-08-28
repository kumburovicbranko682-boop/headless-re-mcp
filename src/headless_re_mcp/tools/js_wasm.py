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

    @tools.tool(name="js.strings")
    def js_strings(
        path: str,
        min_length: Annotated[int, Field(ge=1, le=1024)] = 2,
        category: str = "",
        contains: str = "",
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=5000)] = 200,
    ) -> dict[str, Any]:
        """Extract and classify string literals from a JS file (no webcrack needed).

        js.deobfuscate needs Node/webcrack and returns the whole body; this reads
        the source directly and answers the first triage question -- what
        endpoints, URLs, keys and messages a bundle carries. The JS analogue of
        apk.strings / wasm.strings: a single pass pulls the content of every
        string and template literal (comments and regex literals are skipped so
        their contents are not mistaken for strings), dedups by value with an
        occurrence count, and buckets each into a category -- url (http, https,
        ws, wss, ftp or protocol-relative //host), path (a leading-slash
        endpoint) or text. Narrow with category (one bucket), contains (a
        case-insensitive substring) and min_length (drop short noise).

        Answers with strings (each value, count, category, plus truncated when a
        value was cut at 8192 chars), count, total, offset and has_more over the
        filtered set, distinct (all unique literals before filtering),
        category_counts (the url/path/text breakdown, informative even under a
        category filter), min_length and scan_capped (set once the
        200000-literal ceiling stopped the scan). The list field is strings, not
        results. Works on any .js file on disk, including one spilled by
        web.script.source.
        """
        return _dump(
            analysis.js_strings(
                path,
                min_length=min_length,
                category=category,
                contains=contains,
                offset=offset,
                limit=limit,
            )
        )

    @tools.tool(name="js.imports")
    def js_imports(
        path: str,
        kind: str = "",
        contains: str = "",
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=2000)] = 200,
    ) -> dict[str, Any]:
        """Extract a JS/ES module's dependency edges (no webcrack needed).

        The JS analogue of r2.imports / wasm.summary imports: reads the source
        directly and answers the module-graph question -- which modules,
        packages and URLs a file pulls in. A single pass (skipping comments,
        regex and string/template literals so a keyword inside one is never read
        as code) finds every static import (side-effect, default, * as ns and
        named), export ... from re-export, dynamic import("mod") and CommonJS
        require("mod"). Only literal specifiers are recorded; a computed
        import(expr) / require(expr) is skipped. Imports inside template
        interpolations are not extracted.

        Each edge carries specifier, kind (import, export_from, dynamic_import
        or require), line, and -- for static imports and named re-exports --
        default, namespace and names when present. Narrow with kind (one
        mechanism) and contains (a case-insensitive substring over the
        specifier).

        Answers with imports (the edge list, paged), count, total, offset and
        has_more over the filtered set, specifiers (the sorted unique module
        list for the whole file, capped at 2000), distinct (its true size),
        kind_counts (the breakdown for the whole file) and scan_capped (set once
        the 100000-edge ceiling stopped the scan). The list field is imports,
        not results. Works on any .js/.mjs file on disk, including one spilled
        by web.script.source.
        """
        return _dump(
            analysis.js_imports(
                path,
                kind=kind,
                contains=contains,
                offset=offset,
                limit=limit,
            )
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

    @tools.tool(name="wasm.summary")
    def wasm_summary(
        path: str, timeout: Annotated[float, Field(gt=0, le=600.0)] = 30.0
    ) -> dict[str, Any]:
        """Structured import/export/section surface of a .wasm module.

        Where wasm.info returns wasm-objdump's text and wasm.wat/decompile return
        code text, this parses the module binary itself into machine-readable
        lists: imports (module, name, kind, and for functions type_index plus a
        resolved signature) -- what the module needs from its JS host (env.<name>)
        -- and exports (name, kind, index; for functions also type_index and
        signature) -- the functions and memory a page calls. It is the WebAssembly
        analogue of a PE/ELF import and export table, the seam from "there is a
        wasm module" to "here is its API". kind is func, table, memory or global; a
        function signature reads like "(i32, i32) -> i32". Also answers with
        version, types (the module's whole signature table), per-kind counts
        (import_count, export_count, function_count, memory_count, global_count,
        table_count, type_count) and sections (every section's declared entry
        count). Reads the bytes directly, so it works with no wabt installed; a
        malformed module is a clean backend_error. imports_truncated /
        exports_truncated / types_truncated mark a module whose lists were longer
        than the 4096 cap (the counts stay the real totals). An input over 16 MiB
        is refused as too_large.
        """
        return _dump(analysis.wasm_summary(path, timeout=timeout))

    @tools.tool(name="wasm.functions")
    def wasm_functions(
        path: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=2000)] = 200,
        timeout: Annotated[float, Field(gt=0, le=600.0)] = 30.0,
    ) -> dict[str, Any]:
        """The module's whole function table (r2.functions / apk.methods for wasm).

        Where wasm.summary lists only what a module imports and exports, this is
        the full inventory -- every function, imported and internal alike --
        keyed by its index in the function index space, so an internal routine
        reached only through a call op or a table (invisible to wasm.summary)
        still shows up. It is the navigation entry point for the wasm line: find
        function #142 here, then point wasm.wat / wasm.decompile at it, or read
        its data with wasm.data.

        Answers with functions (a page, sorted by index), each an {index, name
        (from the name section, else the import field or an export name, else
        null), kind ("import" or "local"), type_index, signature (e.g.
        "(i32, i32) -> i32"), params, results, exported, export_names when
        exported}. An import also carries import_module / import_field; a defined
        function also carries size (its code body byte length) and locals (its
        declared local count). Also answers with count, total, offset and
        has_more for paging, import_function_count, defined_function_count,
        has_name_section (whether readable names were recovered) and scan_capped
        (set only if the module had more functions than the 50000 collection
        cap). The list field is functions and each entry's readable label is
        functions[i].name. Reads the bytes directly, so it needs no wabt; a
        malformed module is a clean backend_error and a missing file is
        not_found. An input over 16 MiB is refused as too_large.
        """
        return _dump(
            analysis.wasm_functions(path, offset=offset, limit=limit, timeout=timeout)
        )

    @tools.tool(name="wasm.disasm_function")
    def wasm_disasm_function(
        path: str,
        index: Annotated[int, Field(ge=0)],
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=5000)] = 200,
        timeout: Annotated[float, Field(gt=0, le=600.0)] = 30.0,
    ) -> dict[str, Any]:
        """Disassemble one wasm function's body (the wasm twin of r2.disasm_function).

        Where wasm.wat / wasm.decompile render the whole module -- spilling to an
        artifact for anything sizeable -- this decodes a single function picked
        by its index (from wasm.functions) into a linear op listing, the wasm
        parallel to r2.disasm_function / apk.method_bytecode. It reads the bytes
        directly (no wabt) and cannot drift with a wabt release.

        The listing is trustworthy by construction: the decoder knows the
        immediate shape of every opcode it emits and STOPS at the first opcode
        whose shape it does not (SIMD 0xFD / threads 0xFE / reserved), rather
        than guessing and desynchronising. It covers the MVP instruction set,
        sign-extension, the 0xFC prefix (saturating truncation, bulk memory and
        table ops) and reference types.

        Answers with index, kind ("import" or "local"), name (from the name
        section, else null), type_index, signature, params, results, has_code,
        and for a defined function local_count, local_types, body_size and ops
        (a page). Each op is {offset (its absolute byte offset in the module),
        opcode (the hex byte, or "0xfc N" for a prefixed op), name (the
        mnemonic), text (the rendered instruction, e.g. "local.get 0",
        "i32.const 42", "call 3"), depth (its block-nesting level), bytes (the
        instruction's raw hex) and immediates (structured operands) when it has
        any}. Also answers with count, total, offset and has_more for paging, and
        decoded_all -- false when the walk stopped early, with stopped_at_offset
        and stopped_opcode naming where and on what (usually a SIMD/threads op).
        scan_capped marks a body with more than 100000 ops. An imported function
        has no body: has_code false and an empty ops list, not an error. An index
        past the module's function count is invalid_params; a malformed module is
        a clean backend_error and a missing file is not_found. An input over 16
        MiB is refused as too_large.
        """
        return _dump(
            analysis.wasm_disasm_function(
                path, index, offset=offset, limit=limit, timeout=timeout
            )
        )

    @tools.tool(name="wasm.names")
    def wasm_names(
        path: str, timeout: Annotated[float, Field(gt=0, le=600.0)] = 30.0
    ) -> dict[str, Any]:
        """Recover internal symbol names from a .wasm module's name section.

        wasm.summary names only what a module exposes to its host (imports and
        exports); this reads the ``name`` custom section for the original
        *internal* names a compiler emitted -- functions, locals, globals, types,
        data segments -- turning anonymous indices like func[142] into readable
        identifiers. On a debug-info-bearing module (Emscripten, Rust/wasm-bindgen,
        AssemblyScript) it is usually the single most useful artifact.

        Answers with module_name (the name section's module name, or ""),
        functions (a list of {index, name} sorted by index) and function_count,
        locals (a flattened list of {function, index, name}), other_spaces (a map
        keyed by space -- type, table, memory, global, elem, data, tag -- each a
        {index, name} list), subsections (every name subsection seen, as {id,
        kind, size} with a declared count for the mapped ones) and
        has_name_section. A stripped module answers has_name_section false with
        empty lists -- that is "no names present", not an error. The list fields
        are functions / locals / other_spaces (there is no symbols field); a
        function's readable name is functions[i].name. Reads the bytes directly,
        so it needs no wabt; a malformed module is a clean backend_error.
        functions_truncated (with functions_total the real count), locals_truncated
        and spaces_truncated mark lists longer than the 50000 cap. An input over
        16 MiB is refused as too_large.
        """
        return _dump(analysis.wasm_names(path, timeout=timeout))

    @tools.tool(name="wasm.strings")
    def wasm_strings(
        path: str,
        min_length: Annotated[int, Field(ge=1, le=1024)] = 4,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=5000)] = 200,
        timeout: Annotated[float, Field(gt=0, le=600.0)] = 30.0,
    ) -> dict[str, Any]:
        """Extract printable strings from a .wasm module's Data section.

        The wasm analogue of r2.strings / apk.strings: a module keeps its string
        literals, URLs, format strings, error messages and constants in its data
        segments (its .rodata), which no other reader surfaced. This walks the
        Data section and reports each printable ASCII run at least min_length long
        (default 4), so it is the first-pass triage of "what does this module
        talk about".

        Answers with strings, each a {string, segment (its data-segment index),
        segment_offset (byte offset within that segment), offset (the absolute
        linear-memory address for an active segment, or null for a passive one)};
        a run longer than 4096 bytes is cut and marked value_truncated. Also
        answers with count, total, offset and has_more for paging, data_segments
        (how many segments were seen), scanned_bytes, min_length and scan_capped
        (set once the 50000-string collection cap was hit). The list field is
        strings and each entry's text is strings[i].string (there is no values or
        data field). Reads the bytes directly, so it needs no wabt; a malformed
        module is a clean backend_error. An input over 16 MiB is refused as
        too_large.
        """
        return _dump(
            analysis.wasm_strings(
                path, min_length=min_length, offset=offset, limit=limit, timeout=timeout
            )
        )

    @tools.tool(name="wasm.data")
    def wasm_data(
        path: str,
        segment: Annotated[int, Field(ge=0)] = 0,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=65536)] = 4096,
        timeout: Annotated[float, Field(gt=0, le=600.0)] = 30.0,
    ) -> dict[str, Any]:
        """Read the raw bytes of a .wasm Data-section segment (wasm twin of r2.read).

        wasm.strings surfaces only the printable runs in a module's data
        segments; this is the raw reader for those same segments, so the bytes a
        strings pass cannot show -- an embedded key, certificate, protobuf
        descriptor or compressed payload -- are still recoverable. It reads the
        bytes directly, so it needs no wabt installed.

        Every call answers with segments, the lightweight map of the module's
        data segments (each {index, mode, memory_offset, size} and no bytes, so
        the map stays small) and data_segments (their count). mode is "active"
        (placed in linear memory) or "passive"; memory_offset is the absolute
        linear-memory address an active segment's i32.const placement resolves to
        (null for a passive segment, or when the base is an imported global.get).
        Pick one with segment (default 0) and its raw bytes come back in data as
        a lowercase hex string, windowed by offset (byte offset into the segment)
        and limit (bytes, capped at 65536), alongside encoding ("hex"), size (the
        segment's full length), byte_offset, count (bytes returned) and has_more
        (more bytes past this window). Page a large segment by advancing offset
        until has_more is false. A module with no Data section is a clean empty
        map (data_segments 0, no data field), not an error; a segment index past
        the end is invalid_params; a missing file is not_found and a malformed
        module a backend_error. segments_truncated marks a module with more than
        4096 segments (segments_total keeps the real count). An input over 16 MiB
        is refused as too_large. Decode data from hex; there is no inline byte
        array. This is the static twin of frida.memory.read for a wasm module.
        """
        return _dump(
            analysis.wasm_data(
                path, segment=segment, offset=offset, limit=limit, timeout=timeout
            )
        )

    return tools.bindings
