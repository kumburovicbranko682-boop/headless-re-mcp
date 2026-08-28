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

    @tools.tool(name="js.strings")
    def js_strings(
        path: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=2000)] = 200,
        min_length: Annotated[int, Field(ge=1, le=1024)] = 3,
        name_filter: str = "",
    ) -> dict[str, Any]:
        """Extract string literals from a JavaScript file, without webcrack.

        js.deobfuscate/beautify/unpack_bundle all need webcrack (Node); this
        reads and lexes the source in-process, so it stays available when
        webcrack is not configured -- the js-line analogue of the
        wasm.summary/names/strings trio being wabt-free. It is the ``strings`` of
        a bundle: the URLs, api endpoints, error messages and embedded keys a
        triage pass greps for live in string literals, and this pulls them out
        without reading megabytes of minified code. A real lexer, not a regex
        sweep, so quotes inside comments and regex literals are not mistaken for
        strings; and \\x/\\u escape sequences are decoded, which unmasks a URL an
        obfuscator hid as "\\x68\\x74\\x74\\x70". Answers with strings (each
        {offset (char index of the literal), text (decoded), size (decoded
        length), kind (single|double|template)}, plus text_truncated when one
        literal exceeded the text clip), count, total, offset, has_more, and
        scan_capped when the file held more literals than the collect ceiling.
        min_length is the shortest literal kept (default 3, dropping the empty
        and single/two-char literals minified code is full of); raise it to cut
        the noise on a large bundle. name_filter keeps only literals whose text
        contains that substring (case-insensitive, since these are prose and
        URLs), applied before paging so total is the match count -- the way to
        find "http" or an api host among thousands. A template `...` literal's
        static chunks are extracted per chunk (a ${...} hole splits them); the
        expressions inside ${...} are not separately extracted. The list field is
        strings. For a readable form of the whole file use js.beautify; to unpack
        a bundle into modules use js.unpack_bundle. A missing file is not_found;
        one over 16 MiB is too_large.
        """
        return _dump(
            analysis.js_strings(
                path,
                offset=offset,
                limit=limit,
                min_length=min_length,
                name_filter=name_filter,
            )
        )

    @tools.tool(name="js.endpoints")
    def js_endpoints(
        path: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=2000)] = 200,
        name_filter: str = "",
        include_paths: bool = True,
    ) -> dict[str, Any]:
        """Extract the network surface (URLs, hosts, request paths) of a JS file.

        The "what does this bundle talk to" answer, without webcrack. js.strings
        returns every literal; this is the higher-signal cut on top of the same
        lexer -- it pulls the scheme'd URLs (http/https/ws/wss/ftp) and, unless
        include_paths is false, the whole-literal request paths (/api/...,
        /v1/users, any two-segment path) out of the string literals,
        deduplicates them, and aggregates by occurrence. Because it reuses the
        lexer, \\x/\\u-escaped URLs are decoded (an obfuscated endpoint surfaces)
        and quotes inside comments or regex literals are not mistaken for
        endpoints. Answers with endpoints (each {value, kind (url|path), scheme,
        host, count (occurrences across the file), first_offset (char index of
        the first literal it came from)}, sorted by count then value), count,
        total, offset, has_more, hosts (the distinct host set of the URL
        endpoints, the domains at a glance) with hosts_truncated when that set
        overflowed its cap, and scan_capped when the file held more distinct
        endpoints than the collect ceiling. A path endpoint has empty scheme/host.
        name_filter keeps only endpoints whose value or host contains that
        substring (case-insensitive), applied before the host summary and paging
        so total is the match count -- the way to isolate one api host among
        many. include_paths false drops the relative paths to leave only external
        URLs. The list field is endpoints; for every raw literal (not just the
        network ones) use js.strings. A missing file is not_found; one over
        16 MiB is too_large.
        """
        return _dump(
            analysis.js_endpoints(
                path,
                offset=offset,
                limit=limit,
                name_filter=name_filter,
                include_paths=include_paths,
            )
        )

    @tools.tool(name="js.secrets")
    def js_secrets(
        path: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=2000)] = 200,
        name_filter: str = "",
        include_generic: bool = False,
    ) -> dict[str, Any]:
        """Detect embedded credentials (API keys, tokens, private keys) in a JS file.

        The credential cut of the js-line triage triad, without webcrack:
        js.strings returns every literal and js.endpoints the network surface;
        this runs a set of high-precision secret detectors over the same
        escape-decoded, comment/regex-safe string literals, so a leaked key ships
        the shortest path from a bundle to "what did the frontend hardcode".
        Detectors cover AWS access-key ids, Google API keys and OAuth tokens,
        GitHub tokens (classic and fine-grained), Slack tokens and webhooks,
        Stripe secret keys, Twilio SIDs/keys, SendGrid and Mailgun keys, npm
        tokens, JWTs, PEM PRIVATE KEY headers, and user:pass@ URLs. Because it
        reuses the lexer, a key an obfuscator hid as a \\x/\\u-escaped string is
        decoded before matching. Answers with secrets (each {detector, value (the
        matched credential, clipped with value_truncated when long), count
        (occurrences across the file), first_offset (char index of the first
        literal it came from)}, sorted by detector then count then value), count,
        total, offset, has_more, detectors (the distinct detector set present, the
        at-a-glance "what kinds leaked"), and scan_capped when the file held more
        distinct findings than the collect ceiling. The detectors are anchored to
        keep false positives low, so an ordinary long random-looking string is
        not reported unless include_generic is set -- which adds a
        generic_high_entropy detector for a whole-literal base64/hex token with
        high Shannon entropy (only for a literal no specific detector already
        claimed). name_filter keeps only findings whose detector or value contains
        that substring (case-insensitive), applied before paging so total is the
        match count -- the way to pull just the aws or jwt hits. The list field is
        secrets; only string literals are scanned (as with js.strings/endpoints),
        so a secret sitting in a comment is not reported. A missing file is
        not_found; one over 16 MiB is too_large.
        """
        return _dump(
            analysis.js_secrets(
                path,
                offset=offset,
                limit=limit,
                name_filter=name_filter,
                include_generic=include_generic,
            )
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

    @tools.tool(name="wasm.endpoints")
    def wasm_endpoints(
        path: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=2000)] = 200,
        name_filter: str = "",
        include_paths: bool = True,
    ) -> dict[str, Any]:
        """Extract the network surface (URLs, hosts, api paths) from a .wasm data section, no wabt.

        The endpoint companion to wasm.strings: instead of the raw rodata runs it
        runs the same URL/path recogniser js.endpoints and apk.endpoints use over
        those runs, so a module compiled from Rust/Go/C++ gives up the backends it
        reaches -- the fetch hosts, the api paths -- in one call, parsed in-process
        (no wabt). Answers with endpoints, count, total, offset, has_more, hosts
        (the distinct URL host set -- the "what does this module talk to" answer),
        hosts_truncated when that set overflowed its cap, has_data_section, and
        scan_capped when the module held more distinct endpoints than the collect
        ceiling. When has_data_section is false the module ships no initialised
        memory and endpoints is empty -- that is the answer, not an error. Each
        endpoints row is {value (the URL or path), kind (url|path), scheme, host,
        count (occurrences), first_offset (module-absolute byte offset of the
        earliest run it was seen in)}; path rows have empty scheme/host. Rows are
        ordered by count (descending) then value. include_paths=false drops the
        relative request paths and keeps only scheme'd URLs. name_filter keeps only
        endpoints whose value or host contains that substring (case-insensitive),
        applied before the host summary and paging so total is the match count --
        the way to pull one host out of a busy module. The list field is
        endpoints; for the raw strings use wasm.strings. A file that is not a
        readable wasm module is invalid_params; one over 16 MiB is too_large.
        """
        return _dump(
            analysis.wasm_endpoints(
                path,
                offset=offset,
                limit=limit,
                name_filter=name_filter,
                include_paths=include_paths,
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
