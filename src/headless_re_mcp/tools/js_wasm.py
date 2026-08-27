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
        the buffer. An input over 16 MiB is refused as too_large rather than
        handed to webcrack.
        """
        return _dump(analysis.js_deobfuscate(path, timeout=timeout))

    @tools.tool(name="js.beautify")
    def js_beautify(
        path: str, timeout: Annotated[float, Field(gt=0, le=600.0)] = 120.0
    ) -> dict[str, Any]:
        """Return a readable, unminified form of a JavaScript file via webcrack.

        Same payload as js.deobfuscate: Answers with code and bytes, plus
        truncated when the text was cut at the buffer. An input over 16 MiB
        is refused as too_large rather than handed to webcrack.
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
        the buffer. An input over 16 MiB is refused as too_large rather than
        handed to wasm2wat.
        """
        return _dump(analysis.wasm_wat(path, timeout=timeout))

    @tools.tool(name="wasm.info")
    def wasm_info(
        path: str, timeout: Annotated[float, Field(gt=0, le=600.0)] = 120.0
    ) -> dict[str, Any]:
        """Dump sections and details of a .wasm module via wasm-objdump.

        Answers with objdump holding that text, not a sections list, plus
        truncated when the text was cut at the buffer. An input over 16 MiB
        is refused as too_large rather than handed to wasm-objdump. For a
        structured host boundary use wasm.imports / wasm.exports instead of
        parsing this text.
        """
        return _dump(analysis.wasm_info(path, timeout=timeout))

    @tools.tool(name="wasm.sections")
    def wasm_sections(
        path: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=2000)] = 200,
    ) -> dict[str, Any]:
        """Map a .wasm module's section layout (its binary structure at a glance).

        Reads the module's top-level sections directly, so it needs no wabt and
        cannot drift with a wabt version; an input over 16 MiB is refused as
        too_large. This is the structured, dependency-free form of the section
        table wasm.info only prints as wasm-objdump text. Answers with sections,
        count, total, offset, has_more and incomplete. Each row has id, name (the
        well-known section name -- "type", "import", "function", "table",
        "memory", "global", "export", "start", "element", "code", "data",
        "data_count", "custom" -- or the byte in hex for an unknown id), size
        (declared body length in bytes) and offset (where the body starts in the
        file). A custom row adds custom_name (which custom section it is, e.g.
        "name" or "producers"), since all custom sections share id 0. A vector-
        prefixed section and data_count add count, the number of entries the
        section header declares -- note this per-row count is the section's entry
        count, distinct from the top-level count, which is rows on this page.
        incomplete is true when a section overran the buffer or the section cap
        was hit, so a partial map is not read as the whole layout. count may be
        below limit when the result-size budget trimmed the page, so read count,
        not limit, and page on has_more. The list field is sections, not items.
        """
        return _dump(analysis.wasm_sections(path, offset=offset, limit=limit))

    @tools.tool(name="wasm.functions")
    def wasm_functions(
        path: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=2000)] = 200,
    ) -> dict[str, Any]:
        """List a .wasm module's defined functions (the internal function table).

        Reads the Function section directly and resolves each entry against the
        Type, Import and custom name sections, so it needs no wabt and cannot
        drift with a wabt version; an input over 16 MiB is refused as too_large.
        This is the function table a reverse engineer navigates -- without it
        internal functions are only indices with no signature or name. Answers
        with functions, count, total, offset, declared, has_more and incomplete.
        Each row has index (the absolute function index, imported functions
        counted first, so it matches the name section and call instructions),
        type_index and, when the Type section resolves it, params and results
        (valtype names); a row also carries name when the custom name section
        names that index. Only defined functions appear here -- imported
        functions are wasm.imports, not this list. total is the number parsed
        and pageable; declared is the count the section header claimed;
        incomplete is true when they diverge because the module was truncated or
        the entry cap was hit. count may be below limit when the result-size
        budget trimmed the page, so read count, not limit, and page on has_more.
        The list field is functions, not items.
        """
        return _dump(analysis.wasm_functions(path, offset=offset, limit=limit))

    @tools.tool(name="wasm.globals")
    def wasm_globals(
        path: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=2000)] = 200,
    ) -> dict[str, Any]:
        """List a .wasm module's defined globals (its global-variable table).

        Reads the Global section directly, so it needs no wabt and cannot drift
        with a wabt version; an input over 16 MiB is refused as too_large. A
        module's globals hold its mutable state and layout constants -- the stack
        pointer, heap base, and feature flags an Emscripten/Rust module ships --
        so their initial values are worth reading straight off the binary.
        Answers with globals, count, total, offset, declared, has_more and
        incomplete. Each row has index (the absolute global index, imported
        globals counted first, so it matches global.get instructions),
        value_type (i32/i64/f32/f64/v128/funcref/externref, or a hex byte for an
        unknown type) and mutable (true for a var global, false for a const one).
        A row also carries init -- the initializer as {op, value} when it is a
        simple constant (op i32.const/i64.const/f32.const/f64.const with the
        literal in value) or a reference (op global.get/ref.func with the index
        in value, or ref.null with no value); a non-finite float const keeps op
        but drops value, and an init that cannot be decoded is omitted. Only
        defined globals appear here -- imported globals are wasm.imports, not
        this list. total is the number parsed and pageable; declared is the count
        the section header claimed; incomplete is true when they diverge because
        the module was truncated, the entry cap was hit, or an init expression
        could not be decoded. count may be below limit when the result-size
        budget trimmed the page, so read count, not limit, and page on has_more.
        The list field is globals, not items.
        """
        return _dump(analysis.wasm_globals(path, offset=offset, limit=limit))

    @tools.tool(name="wasm.imports")
    def wasm_imports(
        path: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=2000)] = 200,
    ) -> dict[str, Any]:
        """List a .wasm module's imports (its host-dependency surface).

        Reads the module's binary Import section directly, so it needs no wabt
        and cannot drift with a wabt version; an input over 16 MiB is refused as
        too_large. Answers with imports, count, total, offset, declared,
        has_more and incomplete. Each row has module, name and kind ("func",
        "table", "memory", "global"); a func row adds type_index and, when the
        Type section resolves it, params and results (valtype names); a memory or
        table row adds limits (min, and max when bounded); a global row adds
        value_type and mutable. total is the number of imports parsed and page-
        able; declared is the count the section header claimed; incomplete is
        true when they diverge because the module was truncated or the entry cap
        was hit, so a short list is not read as the whole surface. count may be
        below limit when the result-size budget trimmed the page, so read count,
        not limit, and page on has_more. The list field is imports, not items.
        """
        return _dump(analysis.wasm_imports(path, offset=offset, limit=limit))

    @tools.tool(name="wasm.exports")
    def wasm_exports(
        path: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=2000)] = 200,
    ) -> dict[str, Any]:
        """List a .wasm module's exports (the entry points it exposes to the host).

        Reads the module's binary Export section directly, so it needs no wabt
        and cannot drift with a wabt version; an input over 16 MiB is refused as
        too_large. Answers with exports, count, total, offset, declared,
        has_more and incomplete. Each row has name, kind ("func", "table",
        "memory", "global") and index (into that kind's index space). total is
        the number of exports parsed and pageable; declared is the count the
        section header claimed; incomplete is true when they diverge because the
        module was truncated or the entry cap was hit. count may be below limit
        when the result-size budget trimmed the page, so read count, not limit,
        and page on has_more. The list field is exports, not items.
        """
        return _dump(analysis.wasm_exports(path, offset=offset, limit=limit))

    @tools.tool(name="wasm.names")
    def wasm_names(
        path: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=2000)] = 200,
    ) -> dict[str, Any]:
        """Read a .wasm module's debug names (function-index to name symbol map).

        Reads the custom "name" section of the module's binary directly, so it
        needs no wabt and cannot drift with a wabt version; an input over 16 MiB
        is refused as too_large. This is what symbolises a stripped-but-named
        module -- without it internal functions are only indices. Answers with
        present, module_name, function_names, count, total, offset, has_more and
        incomplete. present is whether the module carries a name section at all
        (false for a stripped module), which is distinct from a section that is
        present but names no functions (present true, function_names empty).
        module_name is the module's own name or null. function_names lists rows
        of index and name sorted by index; count may be below limit when the
        result-size budget trimmed the page, so read count, not limit, and page
        on has_more.         incomplete is true when the name section was truncated or
        hit the entry cap. The list field is function_names, not names or items.
        """
        return _dump(analysis.wasm_names(path, offset=offset, limit=limit))

    @tools.tool(name="wasm.strings")
    def wasm_strings(
        path: str,
        min_length: Annotated[int, Field(ge=1, le=256)] = 4,
        contains: Annotated[str | None, Field(max_length=200)] = None,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=2000)] = 200,
    ) -> dict[str, Any]:
        """Extract printable strings from a .wasm module's Data section (no wabt).

        Reads the Data-section segments of the module's binary directly, so it
        needs no wabt and cannot drift with a wabt version; an input over 16 MiB
        is refused as too_large. This is the WASM analogue of pe.strings: the
        literal pool a module ships -- URLs, API paths, format strings, error
        text -- that neither wasm.info nor the import/export surface shows.
        Answers with strings, count, total, offset, min_length, data_segments,
        has_more and incomplete. strings are distinct printable-ASCII runs of at
        least min_length characters, sorted; a run longer than 256 characters is
        clipped. contains keeps only strings holding that case-insensitive
        substring and adds filtered true (a blank filter is ignored); total is
        the number of strings after any filter and is pageable. data_segments is
        how many Data segments were scanned. incomplete is true when the Data
        section was truncated mid-walk, an unknown segment layout was hit, or the
        collection cap was reached, so a short list is not read as the whole
        literal pool. count may be below limit when the result-size budget
        trimmed the page, so read count, not limit, and page on has_more. The
        list field is strings, not items.
        """
        return _dump(
            analysis.wasm_strings(
                path,
                min_length=min_length,
                contains=contains,
                offset=offset,
                limit=limit,
            )
        )

    return tools.bindings
