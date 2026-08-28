"""webcrack (JS) and wabt (WASM) wrapped as bounded one-shot subprocesses.

Both CLIs are optional and user-provided, exactly like UPX/DIE: a missing tool
degrades to ``capability_unavailable`` rather than blocking readiness. webcrack
needs Node.js 22 or 24; wabt provides ``wasm2wat`` and ``wasm-objdump``.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.common.bounded_run import (
    InvalidTimeout,
    TimedOut,
    clamp_cli_timeout,
    run_bounded,
)

JsonObject = dict[str, Any]
_MAX_INLINE = 400_000
# Per the tool schema: js.deobfuscate / js.beautify / wasm.* declare le=600,
# js.unpack_bundle le=1200. Each caller passes its own ceiling into _run.
_MAX_TIMEOUT_S = 600.0
_MAX_UNPACK_TIMEOUT_S = 1200.0
_MAX_STDERR = 8000
_MAX_LISTED_FILES = 2000
_MAX_COUNTED_FILES = 50_000
# Output is already sliced. The child still has to load the file, and an
# unattended pass that pointed js.deobfuscate at a captured bundle started
# node on whatever sat on disk -- measured 2,097,152 bytes still reached
# run_bounded. Sixteen mebibytes is enough for a real module and not enough
# to keep a core busy for the rest of the timeout.
_MAX_INPUT_BYTES = 16 * 1024 * 1024
# js.strings scans JavaScript source for string literals in pure Python, so --
# unlike js.deobfuscate / js.beautify -- it needs no webcrack or Node. Bounded
# like every other scan: a collect cap on distinct literals, a per-page cap and
# a per-string clip. JS literals (data: URIs, tokens, base64 blobs) run longer
# than the WASM data strings, so the per-string clip is a touch more generous.
_JS_DEFAULT_MIN_STRING = 4
_JS_MAX_MIN_STRING = 256
_MAX_JS_STRINGS_COLLECT = 50000
_MAX_JS_STRINGS_PAGE = 1000
_MAX_JS_STRING_LEN = 2048
# js.endpoints runs a URL match over the same decoded literals js.strings finds,
# so a scheme://host URL obfuscated as \x68\x74\x74\x70... is caught once
# decoded. Its own dedup and caps sit on top of the literal scan's.
_MAX_JS_ENDPOINTS_COLLECT = 10000
_MAX_JS_ENDPOINTS_PAGE = 1000
# Every WebAssembly binary opens with these four bytes. Checking them before
# launching wasm2wat / wasm-objdump turns a cryptic tool failure and a wasted
# subprocess into a precise invalid_params -- the same reason the size cap
# refuses input up front rather than handing it to the child.
_WASM_MAGIC = b"\x00asm"
# wasm.imports parses the module's import section in pure Python, so it works
# with no wabt installed. Bounded like every other scan: a collect cap on
# distinct entries, a page cap matching the tool schema and a per-name clamp.
_MAX_WASM_IMPORTS_COLLECT = 5000
_MAX_WASM_IMPORTS_PAGE = 1000
_MAX_WASM_NAME_LEN = 512
# external-kind byte -> name (WASM core spec). Imports and exports share this
# same one-byte tag, so wasm.imports and wasm.exports both read from it.
_WASM_IMPORT_KINDS = {0: "func", 1: "table", 2: "memory", 3: "global"}
_WASM_IMPORT_SECTION_ID = 2
# wasm.exports parses the export section the same wabt-free way, bounded by its
# own collect/page caps (the per-name clamp above is shared).
_MAX_WASM_EXPORTS_COLLECT = 5000
_MAX_WASM_EXPORTS_PAGE = 1000
_WASM_EXPORT_SECTION_ID = 7
# wasm.sections walks the whole section table (the module's table of contents).
# Section id -> canonical name (WASM core spec, binary section order).
_WASM_SECTION_NAMES = {
    0: "custom",
    1: "type",
    2: "import",
    3: "function",
    4: "table",
    5: "memory",
    6: "global",
    7: "export",
    8: "start",
    9: "element",
    10: "code",
    11: "data",
    12: "data_count",
}
# Sections whose body begins with a vec(...) length (or, for data_count, is that
# length): reading that leading u32 gives the entry count cheaply. start (8) is
# a single funcidx and custom (0) is a name+bytes, so neither is listed here.
_WASM_VEC_SECTION_IDS = frozenset({1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 12})
_MAX_WASM_SECTIONS_COLLECT = 5000
_MAX_WASM_SECTIONS_PAGE = 1000
# wasm.names reads the "name" custom section, the module's debug symbol table.
# Its subsections id 0 (module name) and 1 (function namemap) are the useful
# ones; the collect cap is larger because a symbolized module names thousands
# of functions.
_WASM_NAME_SUBSEC_MODULE = 0
_WASM_NAME_SUBSEC_FUNCTION = 1
_MAX_WASM_NAMES_COLLECT = 50000
_MAX_WASM_NAMES_PAGE = 1000
# wasm.functions cross-references the type (1), import (2) and function (3)
# sections into one function-index -> signature table, so the indices line up
# with wasm.names and wasm.exports. It reads no init expressions, so it needs
# none of the const-expression handling the data/global sections would.
_WASM_TYPE_SECTION_ID = 1
_WASM_FUNCTION_SECTION_ID = 3
_WASM_FUNCTYPE_FORM = 0x60
# value-type byte -> name (numeric types, v128, and the two MVP reference
# types). An unknown byte (e.g. a GC ref-type prefix) renders as hex and the
# surrounding parse degrades to truncated rather than inventing a signature.
_WASM_VALTYPES = {
    0x7F: "i32",
    0x7E: "i64",
    0x7D: "f32",
    0x7C: "f64",
    0x7B: "v128",
    0x70: "funcref",
    0x6F: "externref",
}
_MAX_WASM_FUNCTIONS_COLLECT = 50000
_MAX_WASM_FUNCTIONS_PAGE = 1000
# wasm.strings runs a `strings`-style scan over the data section -- where string
# literals, URLs, paths and error messages live -- rather than parsing segment
# offset expressions (whose LEB immediates can hide the 0x0B end byte, so a
# naive skip misaligns). A printable run is 0x20..0x7e; runs shorter than the
# caller's min_length are dropped, longer than the char cap are clipped.
_WASM_DATA_SECTION_ID = 11
_WASM_DEFAULT_MIN_STRING = 4
_WASM_MAX_MIN_STRING = 256
_MAX_WASM_STRINGS_COLLECT = 50000
_MAX_WASM_STRINGS_PAGE = 1000
_MAX_WASM_STRING_LEN = 1024
# wasm.globals lists module globals (stack pointer, heap base, config flags).
# Each module-defined global carries an init expression that must be stepped
# over to reach the next entry; _skip_const_expr walks that bounded opcode set
# and degrades to truncated on anything it does not recognise, so a misread
# never spills into the next global.
_WASM_GLOBAL_SECTION_ID = 6
_MAX_WASM_GLOBALS_COLLECT = 50000
_MAX_WASM_GLOBALS_PAGE = 1000
# wasm.data maps each data segment to where it loads in linear memory. For an
# active segment the offset is a constant expression; the common i32.const case
# is evaluated to a concrete address, anything else (e.g. global.get) is skipped
# with memory_offset left null. Reuses _WASM_DATA_SECTION_ID from wasm.strings.
_MAX_WASM_DATA_COLLECT = 50000
_MAX_WASM_DATA_PAGE = 1000
# wasm.memory lists the module's linear memories (footprint, shared/threads,
# memory64). Both the memory section and memory imports encode a "limits"
# record, decoded by _read_limits, which wasm.tables will reuse.
_WASM_MEMORY_SECTION_ID = 5
_MAX_WASM_MEMORIES_COLLECT = 50000
_MAX_WASM_MEMORIES_PAGE = 1000
# wasm.tables lists the module's tables -- the indirect-call dispatch surface.
# A tabletype is a reftype byte (funcref/externref) followed by the same limits
# record memories use, so _read_limits is shared; entries are counts, not pages.
_WASM_TABLE_SECTION_ID = 4
_MAX_WASM_TABLES_COLLECT = 50000
_MAX_WASM_TABLES_PAGE = 1000
# wasm.elements flattens element segments into per-slot rows (which function
# lands in which table slot -- the call_indirect target set). The section has
# eight segment encodings selected by a flags value: bit 0x01 passive/declared,
# bit 0x02 an explicit table index (active) or declared (with 0x01), bit 0x04
# entries as const-exprs instead of bare function indices.
_WASM_ELEMENT_SECTION_ID = 9
_MAX_WASM_ELEMENTS_COLLECT = 50000
_MAX_WASM_ELEMENTS_PAGE = 1000
# wasm.calls walks each function body's instruction stream to collect direct
# call targets -- the static call graph. The walker must know every opcode's
# immediates to stay aligned, but the code section prefixes each body with its
# size, so an unrecognised opcode only abandons that one body (decoded: false)
# and the walk resumes cleanly at the next. Plain one-byte opcodes (parametric,
# numeric, sign-extension, ref.is_null/as_non_null) carry no immediates.
_WASM_CODE_SECTION_ID = 10
_WASM_OPS_NO_IMMEDIATE = frozenset(
    {0x00, 0x01, 0x05, 0x0B, 0x0F, 0x1A, 0x1B, 0xD1, 0xD4}
) | frozenset(range(0x45, 0xC5))
# One LEB immediate: br/br_if, blocktypes (a single sleb33), locals/globals,
# table.get/set, memory.size/grow, i32/i64.const, call_ref/return_call_ref,
# ref.null (heaptype), ref.func, br_on_null/br_on_non_null.
_WASM_OPS_ONE_LEB = frozenset(
    {0x02, 0x03, 0x04, 0x0C, 0x0D, 0x14, 0x15, 0x3F, 0x40, 0x41, 0x42}
    | set(range(0x20, 0x27))
    | {0xD0, 0xD2, 0xD5, 0xD6}
)
_MAX_WASM_CALLS_COLLECT = 50000
_MAX_WASM_CALLS_PAGE = 1000
_MAX_WASM_CALLEES = 100
# wasm.callers is the reverse of wasm.calls: given a target function index it
# walks every body (via _walk_body) and reports the functions that directly
# call it -- the "xrefs to this function" view. A body the walker cannot fully
# decode is counted in undecoded_bodies, since its calls to the target may be
# undercounted.
_MAX_WASM_CALLERS_COLLECT = 50000
_MAX_WASM_CALLERS_PAGE = 1000
# wasm.producers decodes the "producers" custom section -- the build-toolchain
# fingerprint. Its format is vec(field), each field a name ("language",
# "processed-by", "sdk") plus a vec of (name, version) pairs; the whole thing is
# flattened to one (field, name, version) row per pair.
_MAX_WASM_PRODUCERS_COLLECT = 10000
_MAX_WASM_PRODUCERS_PAGE = 1000
# wasm.features decodes the "target_features" custom section -- which WASM
# proposals the module was built to use. Its format is vec(feature), each a
# one-byte prefix (0x2B '+' used, 0x2D '-' disallowed, 0x3D '=' required) then a
# feature name; the prefix byte is surfaced as its character.
_WASM_FEATURE_PREFIXES = {0x2B: "+", 0x2D: "-", 0x3D: "="}
_MAX_WASM_FEATURES_COLLECT = 10000
_MAX_WASM_FEATURES_PAGE = 1000
# wasm.start surfaces the start section (id 8) -- the single function index that
# runs automatically at instantiation. It is the one remaining defined section
# not otherwise decoded, and holds exactly zero or one value, so the result is
# scalar rather than a paginated list.
_WASM_START_SECTION_ID = 8


def _capped_file_listing(root: Path, *, cap: int) -> tuple[list[str], int, bool]:
    names: list[str] = []
    total = 0
    has_more = False
    if not root.is_dir():
        return [], 0, False
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if total >= _MAX_COUNTED_FILES:
            has_more = True
            break
        total += 1
        if len(names) < cap:
            names.append(str(path.relative_to(root)))
        else:
            has_more = True
    names.sort()
    return names, total, has_more


class JsReError(RuntimeError):
    def __init__(self, code: str, message: str, **details: object) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


def _require_existing_file(path: Path, *, missing: str) -> Path:
    """Resolve a regular file, or refuse one that would bind the child unbounded."""
    resolved = path.expanduser()
    if not resolved.is_file():
        raise JsReError("not_found", missing, path=str(resolved))
    try:
        size = int(resolved.stat().st_size)
    except OSError as exc:
        raise JsReError("backend_error", f"input unreadable: {exc}", path=str(resolved)) from exc
    cap = _MAX_INPUT_BYTES
    if size > cap:
        raise JsReError(
            "too_large",
            f"input exceeds the {cap}-byte tool limit",
            path=str(resolved),
            size=size,
            max_file_size=cap,
        )
    return resolved


def _looks_like_wasm(path: Path) -> bool:
    """Whether the file opens with the four-byte WebAssembly magic."""
    try:
        with path.open("rb") as handle:
            return handle.read(4) == _WASM_MAGIC
    except OSError:
        return False


class _WasmParseError(Exception):
    """A read ran past the buffer or hit a byte the grammar does not allow.

    Raised only inside the WASM parser and always caught there: a malformed or
    truncated module yields the entries decoded so far with truncated=true,
    never a stack trace or a misaligned tail read as real imports.
    """


def _read_uleb(data: bytes, pos: int) -> tuple[int, int]:
    """Decode one LEB128 unsigned int (u32 range) at pos; return (value, next)."""
    result = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise _WasmParseError("unexpected end of buffer")
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7
        if shift > 35:
            raise _WasmParseError("leb128 too long for u32")


def _read_wasm_name(data: bytes, pos: int) -> tuple[str, int]:
    """Read a WASM name (u32 length prefix + UTF-8 bytes); clamp its length."""
    length, pos = _read_uleb(data, pos)
    end = pos + length
    if length < 0 or end > len(data):
        raise _WasmParseError("name runs past the buffer")
    text = data[pos:end].decode("utf-8", errors="replace")
    return text[:_MAX_WASM_NAME_LEN], end


def _skip_wasm_limits(data: bytes, pos: int) -> int:
    """Skip a limits record (flag byte, min, optional max) for table/memory."""
    if pos >= len(data):
        raise _WasmParseError("limits truncated")
    flag = data[pos]
    pos += 1
    _, pos = _read_uleb(data, pos)
    if flag & 0x01:
        _, pos = _read_uleb(data, pos)
    return pos


def _skip_import_desc(data: bytes, pos: int, kind: int) -> int:
    """Consume the kind-specific descriptor so the next entry stays aligned."""
    if kind == 0:  # func: typeidx
        _, pos = _read_uleb(data, pos)
        return pos
    if kind == 1:  # table: reftype byte, then limits
        if pos >= len(data):
            raise _WasmParseError("table type truncated")
        return _skip_wasm_limits(data, pos + 1)
    if kind == 2:  # memory: limits
        return _skip_wasm_limits(data, pos)
    if kind == 3:  # global: valtype byte + mutability byte
        if pos + 2 > len(data):
            raise _WasmParseError("global type truncated")
        return pos + 2
    raise _WasmParseError(f"unknown import kind {kind}")


def _parse_import_section(data: bytes) -> tuple[list[JsonObject], bool, bool]:
    """Parse an import section body into rows; return (rows, scan_more, truncated)."""
    rows: list[JsonObject] = []
    scan_more = False
    try:
        count, pos = _read_uleb(data, 0)
        for _ in range(count):
            if len(rows) >= _MAX_WASM_IMPORTS_COLLECT:
                scan_more = True
                break
            module, pos = _read_wasm_name(data, pos)
            name, pos = _read_wasm_name(data, pos)
            if pos >= len(data):
                raise _WasmParseError("import kind truncated")
            kind = data[pos]
            pos += 1
            pos = _skip_import_desc(data, pos, kind)
            rows.append(
                {
                    "module": module,
                    "name": name,
                    "kind": _WASM_IMPORT_KINDS.get(kind, "unknown"),
                }
            )
    except _WasmParseError:
        return rows, scan_more, True
    return rows, scan_more, False


def parse_wasm_imports(path: Path, *, offset: int = 0, limit: int = 100) -> JsonObject:
    """List a WebAssembly module's imports (the JS<->WASM boundary), wabt-free.

    Reads the .wasm binary directly in pure Python, so unlike wasm.info / wasm
    .wat it needs no wabt installed. Imports are what a module pulls from its
    host -- the JS functions, memories, tables and globals it cannot run without
    -- and reading them is the fastest way to see what a module actually does
    (a memory import plus env.emscripten_* says one thing; a lone crypto shim
    says another). Each row is module, name and kind (func, table, memory or
    global) in binary order, which is the order that assigns each import its
    index. Returns imports, count, total, offset and has_more so a filled page
    is not read as every import; total is capped at 5000 with scan_capped when
    more may exist, and truncated is true when a malformed or short module cut
    the parse (the entries read so far are still returned). A file that is not a
    WebAssembly module is refused as invalid_params, and one over 16 MiB as
    too_large.
    """
    resolved = _require_existing_file(path, missing="input file not found")
    try:
        raw = resolved.read_bytes()
    except OSError as exc:
        raise JsReError("backend_error", f"input unreadable: {exc}", path=str(resolved)) from exc
    if raw[:4] != _WASM_MAGIC:
        raise JsReError("invalid_params", "not a WebAssembly module", path=str(resolved))
    rows: list[JsonObject] = []
    scan_more = False
    truncated = False
    section_body: bytes | None = None
    try:
        pos = 8  # 4-byte magic + 4-byte version
        total = len(raw)
        while pos < total:
            sec_id = raw[pos]
            pos += 1
            size, pos = _read_uleb(raw, pos)
            end = pos + size
            if end > total:
                truncated = True
                break
            if sec_id == _WASM_IMPORT_SECTION_ID:
                section_body = raw[pos:end]
                break
            pos = end
    except _WasmParseError:
        truncated = True
    if section_body is not None:
        rows, scan_more, body_truncated = _parse_import_section(section_body)
        truncated = truncated or body_truncated
    start = max(0, int(offset))
    cap = max(1, min(int(limit), _MAX_WASM_IMPORTS_PAGE))
    window = rows[start : start + cap]
    return {
        "imports": window,
        "count": len(window),
        "total": len(rows),
        "offset": start,
        "has_more": start + len(window) < len(rows),
        "scan_capped": scan_more,
        "truncated": truncated,
    }


def _parse_export_section(data: bytes) -> tuple[list[JsonObject], bool, bool]:
    """Parse an export section body into rows; return (rows, scan_more, truncated)."""
    rows: list[JsonObject] = []
    scan_more = False
    try:
        count, pos = _read_uleb(data, 0)
        for _ in range(count):
            if len(rows) >= _MAX_WASM_EXPORTS_COLLECT:
                scan_more = True
                break
            name, pos = _read_wasm_name(data, pos)
            if pos >= len(data):
                raise _WasmParseError("export kind truncated")
            kind = data[pos]
            pos += 1
            index, pos = _read_uleb(data, pos)
            rows.append(
                {
                    "name": name,
                    "kind": _WASM_IMPORT_KINDS.get(kind, "unknown"),
                    "index": index,
                }
            )
    except _WasmParseError:
        return rows, scan_more, True
    return rows, scan_more, False


def parse_wasm_exports(path: Path, *, offset: int = 0, limit: int = 100) -> JsonObject:
    """List a WebAssembly module's exports (its public surface), wabt-free.

    The mirror of wasm.imports: it reads the .wasm binary directly in pure
    Python, so unlike wasm.info / wasm.wat it needs no wabt installed. Exports
    are what the module hands back to its host -- the functions the JS glue can
    call and the memories, tables and globals it can reach -- so they are the
    module's public API and the first thing to read when deciding what a blob
    actually offers (an exported _malloc/_free and a table says an Emscripten
    runtime; a single exported hash function says a shim). Each row is name,
    kind (func, table, memory or global) and index, the position in that kind's
    index space; note the index counts imported entries of the same kind first,
    matching the WASM spec, so it is not a row number. Rows keep binary order.
    Returns exports, count, total, offset and has_more so a filled page is not
    read as every export; total is capped at 5000 with scan_capped when more may
    exist, and truncated is true when a malformed or short module cut the parse
    (the entries read so far are still returned). A file that is not a
    WebAssembly module is refused as invalid_params, and one over 16 MiB as
    too_large.
    """
    resolved = _require_existing_file(path, missing="input file not found")
    try:
        raw = resolved.read_bytes()
    except OSError as exc:
        raise JsReError("backend_error", f"input unreadable: {exc}", path=str(resolved)) from exc
    if raw[:4] != _WASM_MAGIC:
        raise JsReError("invalid_params", "not a WebAssembly module", path=str(resolved))
    rows: list[JsonObject] = []
    scan_more = False
    truncated = False
    section_body: bytes | None = None
    try:
        pos = 8  # 4-byte magic + 4-byte version
        total = len(raw)
        while pos < total:
            sec_id = raw[pos]
            pos += 1
            size, pos = _read_uleb(raw, pos)
            end = pos + size
            if end > total:
                truncated = True
                break
            if sec_id == _WASM_EXPORT_SECTION_ID:
                section_body = raw[pos:end]
                break
            pos = end
    except _WasmParseError:
        truncated = True
    if section_body is not None:
        rows, scan_more, body_truncated = _parse_export_section(section_body)
        truncated = truncated or body_truncated
    start = max(0, int(offset))
    cap = max(1, min(int(limit), _MAX_WASM_EXPORTS_PAGE))
    window = rows[start : start + cap]
    return {
        "exports": window,
        "count": len(window),
        "total": len(rows),
        "offset": start,
        "has_more": start + len(window) < len(rows),
        "scan_capped": scan_more,
        "truncated": truncated,
    }


def _section_entry_count(body: bytes) -> int | None:
    """Read the leading vec length of a section body; None if it cannot be read."""
    try:
        count, _ = _read_uleb(body, 0)
        return count
    except _WasmParseError:
        return None


def _custom_section_name(body: bytes) -> str | None:
    """Read a custom section's leading name; None if it cannot be read."""
    try:
        name, _ = _read_wasm_name(body, 0)
        return name
    except _WasmParseError:
        return None


def parse_wasm_sections(path: Path, *, offset: int = 0, limit: int = 100) -> JsonObject:
    """List a WebAssembly module's sections (its table of contents), wabt-free.

    The structural overview to read first: it walks the section table in pure
    Python, so unlike wasm.info / wasm.wat it needs no wabt installed, and it
    frames what wasm.imports and wasm.exports then drill into. Each row is id,
    name (custom, type, import, function, table, memory, global, export, start,
    element, code, data or data_count -- unknown for an id the spec does not
    define), offset (the byte position of the section's id byte) and size (the
    declared body length in bytes). Sections whose body starts with a vector --
    everything but start and custom -- also carry entries, that vector's length
    (for type/function/... the item count, for data_count the declared data-
    segment count); a custom section instead carries custom_name, the section's
    own name (e.g. "name", "producers", ".debug_info"), which is how debug and
    tooling metadata is spotted without a decompiler. Sections keep binary
    order, which for the known ids is ascending except that custom sections may
    sit between any two. Returns sections, count, total, offset and has_more so
    a filled page is not read as the whole table; total is capped at 5000 with
    scan_capped when more may exist, and truncated is true when a section's
    declared size runs past the module or a length is malformed (the sections
    read so far, including the short one, are still returned). A file that is
    not a WebAssembly module is refused as invalid_params, one over 16 MiB as
    too_large.
    """
    resolved = _require_existing_file(path, missing="input file not found")
    try:
        raw = resolved.read_bytes()
    except OSError as exc:
        raise JsReError("backend_error", f"input unreadable: {exc}", path=str(resolved)) from exc
    if raw[:4] != _WASM_MAGIC:
        raise JsReError("invalid_params", "not a WebAssembly module", path=str(resolved))
    rows: list[JsonObject] = []
    scan_more = False
    truncated = False
    try:
        pos = 8  # 4-byte magic + 4-byte version
        total = len(raw)
        while pos < total:
            if len(rows) >= _MAX_WASM_SECTIONS_COLLECT:
                scan_more = True
                break
            sec_start = pos
            sec_id = raw[pos]
            pos += 1
            size, pos = _read_uleb(raw, pos)
            body_start = pos
            end = body_start + size
            row: JsonObject = {
                "id": sec_id,
                "name": _WASM_SECTION_NAMES.get(sec_id, "unknown"),
                "offset": sec_start,
                "size": size,
            }
            if end > total:
                # The header parsed but the body is short: record what we saw
                # and stop rather than slice past the buffer.
                truncated = True
                rows.append(row)
                break
            body = raw[body_start:end]
            if sec_id == 0:
                cname = _custom_section_name(body)
                if cname is not None:
                    row["custom_name"] = cname
            elif sec_id in _WASM_VEC_SECTION_IDS:
                entries = _section_entry_count(body)
                if entries is not None:
                    row["entries"] = entries
            rows.append(row)
            pos = end
    except _WasmParseError:
        truncated = True
    start = max(0, int(offset))
    cap = max(1, min(int(limit), _MAX_WASM_SECTIONS_PAGE))
    window = rows[start : start + cap]
    return {
        "sections": window,
        "count": len(window),
        "total": len(rows),
        "offset": start,
        "has_more": start + len(window) < len(rows),
        "scan_capped": scan_more,
        "truncated": truncated,
    }


def _find_custom_section(raw: bytes, want: str) -> tuple[bytes | None, bool]:
    """Return (body_after_name, truncated) for the first custom section named want.

    body_after_name is the section content that follows the section's own name
    string, i.e. the bytes a subsection parser should read. None means no such
    custom section was found; truncated is set if the walk hit a section whose
    declared size ran past the module.
    """
    truncated = False
    try:
        pos = 8  # 4-byte magic + 4-byte version
        total = len(raw)
        while pos < total:
            sec_id = raw[pos]
            pos += 1
            size, pos = _read_uleb(raw, pos)
            end = pos + size
            if end > total:
                truncated = True
                break
            if sec_id == 0:
                name, name_end = _read_wasm_name(raw, pos)
                if name == want:
                    return raw[name_end:end], truncated
            pos = end
    except _WasmParseError:
        truncated = True
    return None, truncated


def _parse_namemap(data: bytes, rows: list[JsonObject]) -> bool:
    """Fill rows with {index, name} from a namemap; return True if the cap was hit."""
    count, pos = _read_uleb(data, 0)
    for _ in range(count):
        if len(rows) >= _MAX_WASM_NAMES_COLLECT:
            return True
        idx, pos = _read_uleb(data, pos)
        name, pos = _read_wasm_name(data, pos)
        rows.append({"index": idx, "name": name})
    return False


def _parse_name_section(
    body: bytes,
) -> tuple[str | None, list[JsonObject], bool, bool]:
    """Parse a name section body; return (module, func_rows, scan_more, truncated)."""
    module_name: str | None = None
    func_rows: list[JsonObject] = []
    scan_more = False
    try:
        pos = 0
        total = len(body)
        while pos < total:
            sub_id = body[pos]
            pos += 1
            sub_size, pos = _read_uleb(body, pos)
            sub_end = pos + sub_size
            if sub_end > total:
                return module_name, func_rows, scan_more, True
            if sub_id == _WASM_NAME_SUBSEC_MODULE:
                module_name, _ = _read_wasm_name(body, pos)
            elif sub_id == _WASM_NAME_SUBSEC_FUNCTION:
                scan_more = _parse_namemap(body[pos:sub_end], func_rows)
            pos = sub_end
    except _WasmParseError:
        return module_name, func_rows, scan_more, True
    return module_name, func_rows, scan_more, False


def parse_wasm_names(path: Path, *, offset: int = 0, limit: int = 100) -> JsonObject:
    """Recover a WebAssembly module's debug names (its symbol table), wabt-free.

    The optional "name" custom section is a module's symbol table: it maps
    function indices to source names, and the difference between reading _malloc
    and reading func[214]. This parses it in pure Python, so unlike wasm.info /
    wasm.wat it needs no wabt installed, and it complements wasm.sections (which
    only reports that a "name" section exists) and wasm.exports (which shows
    only the handful of names the module chose to expose). Answers with
    has_name_section (false for a stripped module -- then functions is empty and
    total 0, not an error), module (the module's own name, or null), and
    functions, a page of {index, name} where index is the position in the
    function index space (imported functions counted first, per the WASM spec).
    Only the module (subsection 0) and function (subsection 1) name maps are
    surfaced; local and label names are skipped. Returns count, total, offset
    and has_more so a filled page is not read as every name; total is capped at
    50000 with scan_capped when more may exist, and truncated is true when a
    subsection's declared size runs past the section or a length is malformed
    (names read so far are still returned). A file that is not a WebAssembly
    module is refused as invalid_params, one over 16 MiB as too_large.
    """
    resolved = _require_existing_file(path, missing="input file not found")
    try:
        raw = resolved.read_bytes()
    except OSError as exc:
        raise JsReError("backend_error", f"input unreadable: {exc}", path=str(resolved)) from exc
    if raw[:4] != _WASM_MAGIC:
        raise JsReError("invalid_params", "not a WebAssembly module", path=str(resolved))
    body, truncated = _find_custom_section(raw, "name")
    module_name: str | None = None
    func_rows: list[JsonObject] = []
    scan_more = False
    has_name_section = body is not None
    if body is not None:
        module_name, func_rows, scan_more, body_truncated = _parse_name_section(body)
        truncated = truncated or body_truncated
    start = max(0, int(offset))
    cap = max(1, min(int(limit), _MAX_WASM_NAMES_PAGE))
    window = func_rows[start : start + cap]
    return {
        "module": module_name,
        "has_name_section": has_name_section,
        "functions": window,
        "count": len(window),
        "total": len(func_rows),
        "offset": start,
        "has_more": start + len(window) < len(func_rows),
        "scan_capped": scan_more,
        "truncated": truncated,
    }


def _byte_at(data: bytes, pos: int) -> int:
    """Read one byte, raising the parser error (not IndexError) past the end."""
    if pos >= len(data):
        raise _WasmParseError("unexpected end of buffer")
    return data[pos]


def _valtype_name(byte: int) -> str:
    """Name a value-type byte, falling back to its hex for unknown/GC types."""
    return _WASM_VALTYPES.get(byte, f"0x{byte:02x}")


def _collect_section_bodies(raw: bytes, ids: frozenset[int]) -> tuple[dict[int, bytes], bool]:
    """Capture the first body of each wanted section id; flag walk truncation."""
    bodies: dict[int, bytes] = {}
    truncated = False
    try:
        pos = 8  # 4-byte magic + 4-byte version
        total = len(raw)
        while pos < total:
            sec_id = raw[pos]
            pos += 1
            size, pos = _read_uleb(raw, pos)
            end = pos + size
            if end > total:
                truncated = True
                break
            if sec_id in ids and sec_id not in bodies:
                bodies[sec_id] = raw[pos:end]
            pos = end
    except _WasmParseError:
        truncated = True
    return bodies, truncated


def _parse_type_section(
    body: bytes,
) -> tuple[list[tuple[list[str], list[str]]], bool]:
    """Parse vec(functype) into (params, results) pairs; flag truncation."""
    sigs: list[tuple[list[str], list[str]]] = []
    try:
        count, pos = _read_uleb(body, 0)
        for _ in range(count):
            form = _byte_at(body, pos)
            pos += 1
            if form != _WASM_FUNCTYPE_FORM:
                # A non-func (GC struct/array/rec) type: the rest cannot be
                # lined up by index, so stop and report what parsed.
                raise _WasmParseError("non-function type in type section")
            nparams, pos = _read_uleb(body, pos)
            params = []
            for _ in range(nparams):
                params.append(_valtype_name(_byte_at(body, pos)))
                pos += 1
            nresults, pos = _read_uleb(body, pos)
            results = []
            for _ in range(nresults):
                results.append(_valtype_name(_byte_at(body, pos)))
                pos += 1
            sigs.append((params, results))
    except _WasmParseError:
        return sigs, True
    return sigs, False


def _parse_function_section(body: bytes) -> tuple[list[int], bool]:
    """Parse vec(typeidx) for module-defined functions; flag truncation."""
    typeidxs: list[int] = []
    try:
        count, pos = _read_uleb(body, 0)
        for _ in range(count):
            tidx, pos = _read_uleb(body, pos)
            typeidxs.append(tidx)
    except _WasmParseError:
        return typeidxs, True
    return typeidxs, False


def _parse_func_imports(body: bytes) -> tuple[list[tuple[str, str, int]], bool]:
    """Parse the import section, keeping (module, field, typeidx) for func imports."""
    out: list[tuple[str, str, int]] = []
    try:
        count, pos = _read_uleb(body, 0)
        for _ in range(count):
            module, pos = _read_wasm_name(body, pos)
            field, pos = _read_wasm_name(body, pos)
            kind = _byte_at(body, pos)
            pos += 1
            if kind == 0:  # func import: the descriptor is a typeidx
                tidx, pos = _read_uleb(body, pos)
                out.append((module, field, tidx))
            else:
                pos = _skip_import_desc(body, pos, kind)
    except _WasmParseError:
        return out, True
    return out, False


def parse_wasm_functions(path: Path, *, offset: int = 0, limit: int = 100) -> JsonObject:
    """List a WebAssembly module's functions with signatures, wabt-free.

    The capstone of the wabt-free WASM readers: it joins the type (1), import
    (2) and function (3) sections into one function-index table, so the indices
    match those wasm.names, wasm.exports and wasm.imports report. Each row is
    index (its position in the function index space), kind (import or local),
    type_index (into the type section) and params / results, the value-type
    names of its signature (i32, i64, f32, f64, v128, funcref, externref; an
    exotic or GC type renders as hex). Imported functions come first, per the
    WASM spec, and carry module and name (the import's module and field);
    local functions carry name only when the "name" custom section supplies one
    (imports are named by their import pair, not the name section). imported_
    count marks the import/local boundary. A missing type section leaves params
    and results empty (type_index is still reported) rather than erroring, and a
    stripped module simply yields no local names. Returns functions, count,
    total, offset and has_more so a filled page is not read as every function;
    total is capped at 50000 with scan_capped when more may exist, and truncated
    is true when a section is malformed or a value type is not understood (the
    functions resolved so far are still returned). A file that is not a
    WebAssembly module is refused as invalid_params, one over 16 MiB as
    too_large.
    """
    resolved = _require_existing_file(path, missing="input file not found")
    try:
        raw = resolved.read_bytes()
    except OSError as exc:
        raise JsReError("backend_error", f"input unreadable: {exc}", path=str(resolved)) from exc
    if raw[:4] != _WASM_MAGIC:
        raise JsReError("invalid_params", "not a WebAssembly module", path=str(resolved))
    wanted = frozenset({_WASM_TYPE_SECTION_ID, _WASM_IMPORT_SECTION_ID, _WASM_FUNCTION_SECTION_ID})
    bodies, truncated = _collect_section_bodies(raw, wanted)
    sigs: list[tuple[list[str], list[str]]] = []
    func_imports: list[tuple[str, str, int]] = []
    local_typeidxs: list[int] = []
    if _WASM_TYPE_SECTION_ID in bodies:
        sigs, sig_trunc = _parse_type_section(bodies[_WASM_TYPE_SECTION_ID])
        truncated = truncated or sig_trunc
    if _WASM_IMPORT_SECTION_ID in bodies:
        func_imports, imp_trunc = _parse_func_imports(bodies[_WASM_IMPORT_SECTION_ID])
        truncated = truncated or imp_trunc
    if _WASM_FUNCTION_SECTION_ID in bodies:
        local_typeidxs, fn_trunc = _parse_function_section(bodies[_WASM_FUNCTION_SECTION_ID])
        truncated = truncated or fn_trunc
    name_body, name_walk_trunc = _find_custom_section(raw, "name")
    names: dict[int, str] = {}
    if name_body is not None:
        _, name_rows, _, name_trunc = _parse_name_section(name_body)
        truncated = truncated or name_trunc or name_walk_trunc
        names = {int(row["index"]): str(row["name"]) for row in name_rows}

    def _signature(tidx: int) -> tuple[list[str], list[str]]:
        if 0 <= tidx < len(sigs):
            params, results = sigs[tidx]
            return list(params), list(results)
        return [], []

    rows: list[JsonObject] = []
    scan_more = False
    imported_count = len(func_imports)
    idx = 0
    for module, field, tidx in func_imports:
        if len(rows) >= _MAX_WASM_FUNCTIONS_COLLECT:
            scan_more = True
            break
        params, results = _signature(tidx)
        rows.append(
            {
                "index": idx,
                "kind": "import",
                "module": module,
                "name": field,
                "type_index": tidx,
                "params": params,
                "results": results,
            }
        )
        idx += 1
    if not scan_more:
        for tidx in local_typeidxs:
            if len(rows) >= _MAX_WASM_FUNCTIONS_COLLECT:
                scan_more = True
                break
            params, results = _signature(tidx)
            row: JsonObject = {
                "index": idx,
                "kind": "local",
                "type_index": tidx,
                "params": params,
                "results": results,
            }
            local_name = names.get(idx)
            if local_name is not None:
                row["name"] = local_name
            rows.append(row)
            idx += 1
    start = max(0, int(offset))
    cap = max(1, min(int(limit), _MAX_WASM_FUNCTIONS_PAGE))
    window = rows[start : start + cap]
    return {
        "functions": window,
        "imported_count": imported_count,
        "count": len(window),
        "total": len(rows),
        "offset": start,
        "has_more": start + len(window) < len(rows),
        "scan_capped": scan_more,
        "truncated": truncated,
    }


def _scan_printable_strings(
    data: bytes, *, min_len: int, collect_cap: int, str_cap: int
) -> tuple[list[str], bool]:
    """Extract distinct printable ASCII runs in first-seen order; flag the cap.

    A run is a maximal span of bytes in 0x20..0x7e; runs shorter than min_len
    are ignored and longer than str_cap are clipped. De-duplicates so the list
    is "what text is in here", not every occurrence; scan_more is True once
    collect_cap distinct runs are held and a further new one is seen.
    """
    result: dict[str, None] = {}
    scan_more = False
    pattern = re.compile(rb"[ -~]{%d,}" % max(1, min_len))
    for match in pattern.finditer(data):
        text = match.group()[:str_cap].decode("ascii")
        if text in result:
            continue
        if len(result) >= collect_cap:
            scan_more = True
            break
        result[text] = None
    return list(result.keys()), scan_more


def parse_wasm_strings(
    path: Path,
    *,
    offset: int = 0,
    limit: int = 100,
    min_length: int = _WASM_DEFAULT_MIN_STRING,
) -> JsonObject:
    """Extract printable strings from a WebAssembly module's data section, wabt-free.

    `strings` for WASM: the data section holds a module's initialized memory --
    its string literals, URLs, file paths, format strings and error messages --
    and this surfaces them in pure Python, so unlike wasm.info / wasm.wat it
    needs no wabt installed. It scans the raw data-section bytes for runs of
    printable ASCII (0x20..0x7e) rather than parsing each segment's offset
    expression, whose LEB immediates can contain the 0x0B end byte and defeat a
    naive skip; the cost is that a few structural bytes between payloads may
    cling to a string's edge. Runs shorter than min_length (default 4) are
    dropped and longer than 1024 characters clipped; results are de-duplicated
    and kept in first-appearance order, which groups strings that sit near each
    other in memory. Answers with has_data_section (false when the module has
    none -- then strings is empty and total 0, not an error), data_bytes (the
    scanned size), min_length, and strings with count, total, offset and
    has_more so a filled page is not read as every string; total is capped at
    50000 with scan_capped when more may exist, and truncated is true when the
    section walk hit a malformed length. A file that is not a WebAssembly module
    is refused as invalid_params, one over 16 MiB as too_large.
    """
    resolved = _require_existing_file(path, missing="input file not found")
    try:
        raw = resolved.read_bytes()
    except OSError as exc:
        raise JsReError("backend_error", f"input unreadable: {exc}", path=str(resolved)) from exc
    if raw[:4] != _WASM_MAGIC:
        raise JsReError("invalid_params", "not a WebAssembly module", path=str(resolved))
    bodies, truncated = _collect_section_bodies(raw, frozenset({_WASM_DATA_SECTION_ID}))
    data_body = bodies.get(_WASM_DATA_SECTION_ID, b"")
    has_data_section = _WASM_DATA_SECTION_ID in bodies
    min_len = max(1, min(int(min_length), _WASM_MAX_MIN_STRING))
    found, scan_more = _scan_printable_strings(
        data_body,
        min_len=min_len,
        collect_cap=_MAX_WASM_STRINGS_COLLECT,
        str_cap=_MAX_WASM_STRING_LEN,
    )
    start = max(0, int(offset))
    cap = max(1, min(int(limit), _MAX_WASM_STRINGS_PAGE))
    window = found[start : start + cap]
    return {
        "strings": window,
        "has_data_section": has_data_section,
        "data_bytes": len(data_body),
        "min_length": min_len,
        "count": len(window),
        "total": len(found),
        "offset": start,
        "has_more": start + len(window) < len(found),
        "scan_capped": scan_more,
        "truncated": truncated,
    }


def _skip_leb(data: bytes, pos: int) -> int:
    """Consume one LEB128 (signed or unsigned) without decoding its value."""
    while True:
        byte = _byte_at(data, pos)
        pos += 1
        if not byte & 0x80:
            return pos


def _skip_const_expr(data: bytes, pos: int) -> int:
    """Step over a constant expression, returning the position after its end.

    Constant expressions (data/element offsets and global initialisers) draw
    from a small opcode set. Each is skipped by consuming exactly its immediate
    so the byte after 0x0B is the next entry. An opcode outside this set raises
    _WasmParseError -- the caller then reports truncated rather than letting a
    misread run into the following global.
    """
    while True:
        op = _byte_at(data, pos)
        pos += 1
        if op == 0x0B:  # end
            return pos
        if op in (0x41, 0x42):  # i32.const / i64.const: (S)LEB immediate
            pos = _skip_leb(data, pos)
        elif op == 0x43:  # f32.const: 4 raw bytes
            pos += 4
        elif op == 0x44:  # f64.const: 8 raw bytes
            pos += 8
        elif op in (0x23, 0xD2):  # global.get / ref.func: LEB index
            pos = _skip_leb(data, pos)
        elif op == 0xD0:  # ref.null: one heaptype byte (MVP)
            pos += 1
        elif op in (0x6A, 0x6B, 0x6C, 0x7C, 0x7D, 0x7E):
            # extended-const arithmetic (i32/i64 add/sub/mul): no immediate
            continue
        elif op == 0xFD:  # SIMD prefix: only v128.const (subop 12) is const
            sub, pos = _read_uleb(data, pos)
            if sub != 12:
                raise _WasmParseError(f"non-const SIMD op {sub} in const expr")
            pos += 16
        else:
            raise _WasmParseError(f"unexpected const-expr opcode {op:#x}")
        if pos > len(data):
            raise _WasmParseError("const expr runs past the buffer")


def _parse_global_imports(
    body: bytes,
) -> tuple[list[tuple[str, str, int, int]], bool]:
    """Parse the import section, keeping (module, field, valtype, mut) for globals."""
    out: list[tuple[str, str, int, int]] = []
    try:
        count, pos = _read_uleb(body, 0)
        for _ in range(count):
            module, pos = _read_wasm_name(body, pos)
            field, pos = _read_wasm_name(body, pos)
            kind = _byte_at(body, pos)
            pos += 1
            if kind == 3:  # global import: valtype byte + mutability byte
                valtype = _byte_at(body, pos)
                mut = _byte_at(body, pos + 1)
                pos += 2
                out.append((module, field, valtype, mut))
            else:
                pos = _skip_import_desc(body, pos, kind)
    except _WasmParseError:
        return out, True
    return out, False


def _parse_global_section(body: bytes) -> tuple[list[tuple[int, int]], bool]:
    """Parse vec(global) into (valtype, mut) pairs, skipping init exprs."""
    out: list[tuple[int, int]] = []
    try:
        count, pos = _read_uleb(body, 0)
        for _ in range(count):
            valtype = _byte_at(body, pos)
            mut = _byte_at(body, pos + 1)
            pos += 2
            pos = _skip_const_expr(body, pos)
            out.append((valtype, mut))
    except _WasmParseError:
        return out, True
    return out, False


def parse_wasm_globals(path: Path, *, offset: int = 0, limit: int = 100) -> JsonObject:
    """List a WebAssembly module's globals (its module-level state), wabt-free.

    Globals are a module's mutable state cells -- the stack pointer, heap base,
    memory/table bases and config flags a runtime threads through the code. This
    lists them in pure Python, so unlike wasm.info / wasm.wat it needs no wabt
    installed, joining the import (2) and global (6) sections into one table
    whose indices match the global index space. Each row is index (its position
    there), kind (import or local), type (the value type: i32, i64, f32, f64,
    v128, funcref, externref, or hex for an exotic one) and mutable (true for a
    var global, false for a const one). Imported globals come first, per the
    WASM spec, and carry module and name (the import's module and field);
    imported_count marks the import/local boundary. Module-defined globals each
    carry an initialiser expression, which is stepped over, not evaluated, so no
    value is reported. Returns globals, count, total, offset and has_more so a
    filled page is not read as every global; total is capped at 50000 with
    scan_capped when more may exist, and truncated is true when a section is
    malformed or an initialiser uses an opcode outside the constant-expression
    set (the globals resolved so far are still returned). A file that is not a
    WebAssembly module is refused as invalid_params, one over 16 MiB as
    too_large.
    """
    resolved = _require_existing_file(path, missing="input file not found")
    try:
        raw = resolved.read_bytes()
    except OSError as exc:
        raise JsReError("backend_error", f"input unreadable: {exc}", path=str(resolved)) from exc
    if raw[:4] != _WASM_MAGIC:
        raise JsReError("invalid_params", "not a WebAssembly module", path=str(resolved))
    bodies, truncated = _collect_section_bodies(
        raw, frozenset({_WASM_IMPORT_SECTION_ID, _WASM_GLOBAL_SECTION_ID})
    )
    global_imports: list[tuple[str, str, int, int]] = []
    local_globals: list[tuple[int, int]] = []
    if _WASM_IMPORT_SECTION_ID in bodies:
        global_imports, imp_trunc = _parse_global_imports(bodies[_WASM_IMPORT_SECTION_ID])
        truncated = truncated or imp_trunc
    if _WASM_GLOBAL_SECTION_ID in bodies:
        local_globals, glob_trunc = _parse_global_section(bodies[_WASM_GLOBAL_SECTION_ID])
        truncated = truncated or glob_trunc
    rows: list[JsonObject] = []
    scan_more = False
    imported_count = len(global_imports)
    idx = 0
    for module, field, valtype, mut in global_imports:
        if len(rows) >= _MAX_WASM_GLOBALS_COLLECT:
            scan_more = True
            break
        rows.append(
            {
                "index": idx,
                "kind": "import",
                "module": module,
                "name": field,
                "type": _valtype_name(valtype),
                "mutable": mut == 0x01,
            }
        )
        idx += 1
    if not scan_more:
        for valtype, mut in local_globals:
            if len(rows) >= _MAX_WASM_GLOBALS_COLLECT:
                scan_more = True
                break
            rows.append(
                {
                    "index": idx,
                    "kind": "local",
                    "type": _valtype_name(valtype),
                    "mutable": mut == 0x01,
                }
            )
            idx += 1
    start = max(0, int(offset))
    cap = max(1, min(int(limit), _MAX_WASM_GLOBALS_PAGE))
    window = rows[start : start + cap]
    return {
        "globals": window,
        "imported_count": imported_count,
        "count": len(window),
        "total": len(rows),
        "offset": start,
        "has_more": start + len(window) < len(rows),
        "scan_capped": scan_more,
        "truncated": truncated,
    }


def _read_sleb(data: bytes, pos: int) -> tuple[int, int]:
    """Decode one signed LEB128 at pos; return (value, next). Sign-extends."""
    result = 0
    shift = 0
    while True:
        byte = _byte_at(data, pos)
        pos += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            if byte & 0x40 and shift < 64:
                result |= -(1 << shift)
            return result, pos
        if shift > 70:
            raise _WasmParseError("sleb128 too long")


def _eval_offset_expr(data: bytes, pos: int) -> tuple[int | None, int]:
    """Evaluate a data/element offset expression; return (value_or_None, next).

    The overwhelmingly common form is ``i32.const N; end`` and is resolved to N.
    Anything else -- a global.get, an extended-const computation -- is stepped
    over with the value left None, so a non-constant offset never becomes a made
    up address.
    """
    try:
        if _byte_at(data, pos) == 0x41:  # i32.const
            value, after = _read_sleb(data, pos + 1)
            if _byte_at(data, after) == 0x0B:  # end
                return value, after + 1
    except _WasmParseError:
        pass
    return None, _skip_const_expr(data, pos)


def _parse_data_section(body: bytes) -> tuple[list[JsonObject], bool, bool]:
    """Parse vec(data segment) into rows; return (rows, scan_more, truncated)."""
    rows: list[JsonObject] = []
    scan_more = False
    try:
        count, pos = _read_uleb(body, 0)
        for index in range(count):
            if len(rows) >= _MAX_WASM_DATA_COLLECT:
                scan_more = True
                break
            flag, pos = _read_uleb(body, pos)
            row: JsonObject = {"index": index}
            if flag == 0:  # active, memory 0: offset expr + bytes
                memory_offset, pos = _eval_offset_expr(body, pos)
                row.update({"mode": "active", "memory_index": 0, "memory_offset": memory_offset})
            elif flag == 1:  # passive: bytes only
                row["mode"] = "passive"
            elif flag == 2:  # active, explicit memidx: memidx + offset expr + bytes
                memory_index, pos = _read_uleb(body, pos)
                memory_offset, pos = _eval_offset_expr(body, pos)
                row.update(
                    {
                        "mode": "active",
                        "memory_index": memory_index,
                        "memory_offset": memory_offset,
                    }
                )
            else:
                raise _WasmParseError(f"unknown data segment flag {flag}")
            size, pos = _read_uleb(body, pos)
            end = pos + size
            if end > len(body):
                raise _WasmParseError("segment bytes run past the section")
            pos = end
            row["size"] = size
            rows.append(row)
    except _WasmParseError:
        return rows, scan_more, True
    return rows, scan_more, False


def parse_wasm_data(path: Path, *, offset: int = 0, limit: int = 100) -> JsonObject:
    """Map a WebAssembly module's data segments to linear memory, wabt-free.

    The data section's load map: it lists each segment's mode and where it
    lands, in pure Python, so unlike wasm.info / wasm.wat it needs no wabt
    installed, and it is the structural companion to wasm.strings (which pulls
    the text out of the same bytes). Each row is index, mode (active -- copied
    into memory at instantiation -- or passive -- copied on demand by memory
    .init) and size, the payload's byte length. An active segment also carries
    memory_index (which linear memory it targets, almost always 0) and
    memory_offset, the destination address when that offset is a plain i32
    .const; a computed offset (e.g. global.get) leaves memory_offset null rather
    than guessing. Segment bytes themselves are not returned -- use wasm.strings
    for their text. Answers with has_data_section (false when the module has
    none -- then segments is empty and total 0, not an error), segments, count,
    total, offset and has_more so a filled page is not read as every segment;
    total is capped at 50000 with scan_capped when more may exist, and truncated
    is true when a segment length or offset expression is malformed (the
    segments read so far are still returned). A file that is not a WebAssembly
    module is refused as invalid_params, one over 16 MiB as too_large.
    """
    resolved = _require_existing_file(path, missing="input file not found")
    try:
        raw = resolved.read_bytes()
    except OSError as exc:
        raise JsReError("backend_error", f"input unreadable: {exc}", path=str(resolved)) from exc
    if raw[:4] != _WASM_MAGIC:
        raise JsReError("invalid_params", "not a WebAssembly module", path=str(resolved))
    bodies, truncated = _collect_section_bodies(raw, frozenset({_WASM_DATA_SECTION_ID}))
    has_data_section = _WASM_DATA_SECTION_ID in bodies
    rows: list[JsonObject] = []
    scan_more = False
    if has_data_section:
        rows, scan_more, body_truncated = _parse_data_section(bodies[_WASM_DATA_SECTION_ID])
        truncated = truncated or body_truncated
    start = max(0, int(offset))
    cap = max(1, min(int(limit), _MAX_WASM_DATA_PAGE))
    window = rows[start : start + cap]
    return {
        "segments": window,
        "has_data_section": has_data_section,
        "count": len(window),
        "total": len(rows),
        "offset": start,
        "has_more": start + len(window) < len(rows),
        "scan_capped": scan_more,
        "truncated": truncated,
    }


def _read_limits(data: bytes, pos: int) -> tuple[int, int | None, bool, bool, int]:
    """Decode a limits record; return (min, max_or_None, shared, is64, next).

    The flag byte is a bit set: 0x01 a maximum follows, 0x02 shared (threads),
    0x04 a 64-bit (memory64) index. Used for both memory and table types.
    """
    flag = _byte_at(data, pos)
    pos += 1
    minimum, pos = _read_uleb(data, pos)
    maximum: int | None = None
    if flag & 0x01:
        maximum, pos = _read_uleb(data, pos)
    return minimum, maximum, bool(flag & 0x02), bool(flag & 0x04), pos


def _parse_memory_imports(
    body: bytes,
) -> tuple[list[tuple[str, str, int, int | None, bool, bool]], bool]:
    """Parse the import section, keeping the limits of each memory import."""
    out: list[tuple[str, str, int, int | None, bool, bool]] = []
    try:
        count, pos = _read_uleb(body, 0)
        for _ in range(count):
            module, pos = _read_wasm_name(body, pos)
            field, pos = _read_wasm_name(body, pos)
            kind = _byte_at(body, pos)
            pos += 1
            if kind == 2:  # memory import: a limits record
                minimum, maximum, shared, is64, pos = _read_limits(body, pos)
                out.append((module, field, minimum, maximum, shared, is64))
            else:
                pos = _skip_import_desc(body, pos, kind)
    except _WasmParseError:
        return out, True
    return out, False


def _parse_memory_section(
    body: bytes,
) -> tuple[list[tuple[int, int | None, bool, bool]], bool]:
    """Parse vec(memtype) into (min, max, shared, is64) tuples."""
    out: list[tuple[int, int | None, bool, bool]] = []
    try:
        count, pos = _read_uleb(body, 0)
        for _ in range(count):
            minimum, maximum, shared, is64, pos = _read_limits(body, pos)
            out.append((minimum, maximum, shared, is64))
    except _WasmParseError:
        return out, True
    return out, False


def parse_wasm_memory(path: Path, *, offset: int = 0, limit: int = 100) -> JsonObject:
    """List a WebAssembly module's linear memories (its footprint), wabt-free.

    The memory declaration a module cannot run without, read in pure Python, so
    unlike wasm.info / wasm.wat it needs no wabt installed and it says more than
    wasm.sections (which only reports that a memory section exists). It joins the
    import (2) and memory (5) sections into one table over the memory index
    space. Each row is index, kind (import or local), min and max, the size
    bounds in 64 KiB pages (max is null when the module sets none, i.e. the
    memory may grow unbounded), shared (true for a threads/atomics memory) and
    index_type (i64 for a memory64 memory, else i32). Imported memories come
    first, per the WASM spec, and carry module and name (the import's module and
    field); imported_count marks the import/local boundary. Most modules declare
    exactly one memory, but the multi-memory proposal allows several. Returns
    memories, count, total, offset and has_more so a filled page is not read as
    every memory; total is capped at 50000 with scan_capped when more may exist,
    and truncated is true when a limits record is malformed (the memories read
    so far are still returned). A file that is not a WebAssembly module is
    refused as invalid_params, one over 16 MiB as too_large.
    """
    resolved = _require_existing_file(path, missing="input file not found")
    try:
        raw = resolved.read_bytes()
    except OSError as exc:
        raise JsReError("backend_error", f"input unreadable: {exc}", path=str(resolved)) from exc
    if raw[:4] != _WASM_MAGIC:
        raise JsReError("invalid_params", "not a WebAssembly module", path=str(resolved))
    bodies, truncated = _collect_section_bodies(
        raw, frozenset({_WASM_IMPORT_SECTION_ID, _WASM_MEMORY_SECTION_ID})
    )
    mem_imports: list[tuple[str, str, int, int | None, bool, bool]] = []
    local_mems: list[tuple[int, int | None, bool, bool]] = []
    if _WASM_IMPORT_SECTION_ID in bodies:
        mem_imports, imp_trunc = _parse_memory_imports(bodies[_WASM_IMPORT_SECTION_ID])
        truncated = truncated or imp_trunc
    if _WASM_MEMORY_SECTION_ID in bodies:
        local_mems, mem_trunc = _parse_memory_section(bodies[_WASM_MEMORY_SECTION_ID])
        truncated = truncated or mem_trunc
    rows: list[JsonObject] = []
    scan_more = False
    imported_count = len(mem_imports)
    idx = 0
    for module, field, minimum, maximum, shared, is64 in mem_imports:
        if len(rows) >= _MAX_WASM_MEMORIES_COLLECT:
            scan_more = True
            break
        rows.append(
            {
                "index": idx,
                "kind": "import",
                "module": module,
                "name": field,
                "min": minimum,
                "max": maximum,
                "shared": shared,
                "index_type": "i64" if is64 else "i32",
            }
        )
        idx += 1
    if not scan_more:
        for minimum, maximum, shared, is64 in local_mems:
            if len(rows) >= _MAX_WASM_MEMORIES_COLLECT:
                scan_more = True
                break
            rows.append(
                {
                    "index": idx,
                    "kind": "local",
                    "min": minimum,
                    "max": maximum,
                    "shared": shared,
                    "index_type": "i64" if is64 else "i32",
                }
            )
            idx += 1
    start = max(0, int(offset))
    cap = max(1, min(int(limit), _MAX_WASM_MEMORIES_PAGE))
    window = rows[start : start + cap]
    return {
        "memories": window,
        "imported_count": imported_count,
        "count": len(window),
        "total": len(rows),
        "offset": start,
        "has_more": start + len(window) < len(rows),
        "scan_capped": scan_more,
        "truncated": truncated,
    }


def _parse_table_imports(
    body: bytes,
) -> tuple[list[tuple[str, str, int, int, int | None]], bool]:
    """Parse the import section, keeping the tabletype of each table import."""
    out: list[tuple[str, str, int, int, int | None]] = []
    try:
        count, pos = _read_uleb(body, 0)
        for _ in range(count):
            module, pos = _read_wasm_name(body, pos)
            field, pos = _read_wasm_name(body, pos)
            kind = _byte_at(body, pos)
            pos += 1
            if kind == 1:  # table import: reftype + limits
                reftype = _byte_at(body, pos)
                pos += 1
                minimum, maximum, _shared, _is64, pos = _read_limits(body, pos)
                out.append((module, field, reftype, minimum, maximum))
            else:
                pos = _skip_import_desc(body, pos, kind)
    except _WasmParseError:
        return out, True
    return out, False


def _parse_table_section(
    body: bytes,
) -> tuple[list[tuple[int, int, int | None]], bool]:
    """Parse vec(tabletype) into (reftype, min, max) tuples."""
    out: list[tuple[int, int, int | None]] = []
    try:
        count, pos = _read_uleb(body, 0)
        for _ in range(count):
            reftype = _byte_at(body, pos)
            pos += 1
            minimum, maximum, _shared, _is64, pos = _read_limits(body, pos)
            out.append((reftype, minimum, maximum))
    except _WasmParseError:
        return out, True
    return out, False


def parse_wasm_tables(path: Path, *, offset: int = 0, limit: int = 100) -> JsonObject:
    """List a WebAssembly module's tables (indirect-call surface), wabt-free.

    Tables are where call_indirect targets live: a funcref table holds the
    function pointers an optimizer or obfuscator dispatches through, so its size
    bounds how much indirect dispatch a module can do (wasm.sections only says a
    table section exists). Read in pure Python -- no wabt needed. Joins the
    import (2) and table (4) sections into one view over the table index space.
    Each row is index, kind (import or local), element_type (funcref for
    function pointers, externref for host references; an unknown reference-type
    byte renders as hex), and min and max, the size bounds in entries (max is
    null when the module sets none). Imported tables come first, per the WASM
    spec, and carry module and name -- Emscripten modules typically import
    env.__indirect_function_table, a strong linkage signal; imported_count marks
    the import/local boundary. Returns tables, count, total, offset and has_more
    so a filled page is not read as every table; total is capped at 50000 with
    scan_capped when more may exist, and truncated is true when a tabletype is
    malformed (tables read so far are still returned). A file that is not a
    WebAssembly module is refused as invalid_params, one over 16 MiB as
    too_large.
    """
    resolved = _require_existing_file(path, missing="input file not found")
    try:
        raw = resolved.read_bytes()
    except OSError as exc:
        raise JsReError("backend_error", f"input unreadable: {exc}", path=str(resolved)) from exc
    if raw[:4] != _WASM_MAGIC:
        raise JsReError("invalid_params", "not a WebAssembly module", path=str(resolved))
    bodies, truncated = _collect_section_bodies(
        raw, frozenset({_WASM_IMPORT_SECTION_ID, _WASM_TABLE_SECTION_ID})
    )
    tab_imports: list[tuple[str, str, int, int, int | None]] = []
    local_tabs: list[tuple[int, int, int | None]] = []
    if _WASM_IMPORT_SECTION_ID in bodies:
        tab_imports, imp_trunc = _parse_table_imports(bodies[_WASM_IMPORT_SECTION_ID])
        truncated = truncated or imp_trunc
    if _WASM_TABLE_SECTION_ID in bodies:
        local_tabs, tab_trunc = _parse_table_section(bodies[_WASM_TABLE_SECTION_ID])
        truncated = truncated or tab_trunc
    rows: list[JsonObject] = []
    scan_more = False
    imported_count = len(tab_imports)
    idx = 0
    for module, field, reftype, minimum, maximum in tab_imports:
        if len(rows) >= _MAX_WASM_TABLES_COLLECT:
            scan_more = True
            break
        rows.append(
            {
                "index": idx,
                "kind": "import",
                "module": module,
                "name": field,
                "element_type": _valtype_name(reftype),
                "min": minimum,
                "max": maximum,
            }
        )
        idx += 1
    if not scan_more:
        for reftype, minimum, maximum in local_tabs:
            if len(rows) >= _MAX_WASM_TABLES_COLLECT:
                scan_more = True
                break
            rows.append(
                {
                    "index": idx,
                    "kind": "local",
                    "element_type": _valtype_name(reftype),
                    "min": minimum,
                    "max": maximum,
                }
            )
            idx += 1
    start = max(0, int(offset))
    cap = max(1, min(int(limit), _MAX_WASM_TABLES_PAGE))
    window = rows[start : start + cap]
    return {
        "tables": window,
        "imported_count": imported_count,
        "count": len(window),
        "total": len(rows),
        "offset": start,
        "has_more": start + len(window) < len(rows),
        "scan_capped": scan_more,
        "truncated": truncated,
    }


def _eval_ref_expr(data: bytes, pos: int) -> tuple[int | None, int]:
    """Evaluate an element-entry expression; return (funcidx_or_None, next).

    The common form is ``ref.func N; end`` and resolves to N. Anything else --
    ref.null, a global.get -- is stepped over with the index left None, so a
    non-function entry never becomes a made up function index.
    """
    try:
        if _byte_at(data, pos) == 0xD2:  # ref.func
            idx, after = _read_uleb(data, pos + 1)
            if _byte_at(data, after) == 0x0B:  # end
                return idx, after + 1
    except _WasmParseError:
        pass
    return None, _skip_const_expr(data, pos)


def _parse_elem_section(body: bytes) -> tuple[list[JsonObject], int, bool, bool]:
    """Flatten element segments; return (rows, segments, scan_more, truncated)."""
    rows: list[JsonObject] = []
    segments = 0
    scan_more = False
    try:
        count, pos = _read_uleb(body, 0)
        for segment in range(count):
            if len(rows) >= _MAX_WASM_ELEMENTS_COLLECT:
                scan_more = True
                break
            flag, pos = _read_uleb(body, pos)
            if flag > 7:
                raise _WasmParseError(f"unknown element segment flags {flag}")
            mode = ("active", "passive", "active", "declared")[flag & 0x03]
            table_index: int | None = None
            table_offset: int | None = None
            if mode == "active":
                if flag & 0x02:
                    table_index, pos = _read_uleb(body, pos)
                else:
                    table_index = 0
                table_offset, pos = _eval_offset_expr(body, pos)
            if flag != 0 and flag != 4:
                # elemkind (funcidx encodings) or reftype (expr encodings)
                pos += 1
                if pos > len(body):
                    raise _WasmParseError("element segment runs past the buffer")
            n, pos = _read_uleb(body, pos)
            segments += 1
            for position in range(n):
                if len(rows) >= _MAX_WASM_ELEMENTS_COLLECT:
                    scan_more = True
                    break
                if flag & 0x04:
                    func_index, pos = _eval_ref_expr(body, pos)
                else:
                    func_index, pos = _read_uleb(body, pos)
                slot = table_offset + position if table_offset is not None else None
                rows.append(
                    {
                        "segment": segment,
                        "mode": mode,
                        "table_index": table_index,
                        "slot": slot,
                        "func_index": func_index,
                    }
                )
            if scan_more:
                break
    except _WasmParseError:
        return rows, segments, scan_more, True
    return rows, segments, scan_more, False


def parse_wasm_elements(path: Path, *, offset: int = 0, limit: int = 100) -> JsonObject:
    """Map table slots to functions (the call_indirect targets), wabt-free.

    The element section is where a module fills its tables, so this answers the
    question wasm.tables raises: which functions actually sit in the table, i.e.
    the complete set of indirect-call targets an obfuscator or vtable-style
    dispatcher can reach (join func_index against wasm.functions for names).
    Read in pure Python -- no wabt needed. Segments are flattened to one row per
    table entry: segment (which element segment it came from), mode (active is
    copied into a table at instantiation, passive waits for table.init, declared
    only forward-declares functions for ref.func), table_index (the target
    table for active segments, null otherwise), slot (the concrete table index
    the entry lands in when the segment's offset is a simple i32.const; null for
    a computed offset such as global.get, and for passive/declared segments) and
    func_index (null for a ref.null or non-function entry). Returns
    has_element_section (false when the module has none -- then entries is empty
    and total 0, not an error), segment_count, and entries with count, total,
    offset and has_more so a filled page is not read as every entry; total is
    capped at 50000 with scan_capped when more may exist, and truncated is true
    when a segment is malformed (entries read so far are still returned). A file
    that is not a WebAssembly module is refused as invalid_params, one over
    16 MiB as too_large.
    """
    resolved = _require_existing_file(path, missing="input file not found")
    try:
        raw = resolved.read_bytes()
    except OSError as exc:
        raise JsReError("backend_error", f"input unreadable: {exc}", path=str(resolved)) from exc
    if raw[:4] != _WASM_MAGIC:
        raise JsReError("invalid_params", "not a WebAssembly module", path=str(resolved))
    bodies, truncated = _collect_section_bodies(raw, frozenset({_WASM_ELEMENT_SECTION_ID}))
    has_element_section = _WASM_ELEMENT_SECTION_ID in bodies
    rows: list[JsonObject] = []
    segments = 0
    scan_more = False
    if has_element_section:
        rows, segments, scan_more, elem_trunc = _parse_elem_section(
            bodies[_WASM_ELEMENT_SECTION_ID]
        )
        truncated = truncated or elem_trunc
    start = max(0, int(offset))
    cap = max(1, min(int(limit), _MAX_WASM_ELEMENTS_PAGE))
    window = rows[start : start + cap]
    return {
        "entries": window,
        "has_element_section": has_element_section,
        "segment_count": segments,
        "count": len(window),
        "total": len(rows),
        "offset": start,
        "has_more": start + len(window) < len(rows),
        "scan_capped": scan_more,
        "truncated": truncated,
    }


def _skip_misc_immediates(data: bytes, sub: int, pos: int) -> int:
    """Skip a 0xFC (misc) instruction's immediates; raise on unknown subops."""
    if sub <= 7:  # trunc_sat: no immediates
        return pos
    if sub in (8, 10, 12, 14):  # memory.init/copy, table.init/copy: two indices
        pos = _skip_leb(data, pos)
        return _skip_leb(data, pos)
    if sub in (9, 11, 13, 15, 16, 17):  # data/elem.drop, fill/grow/size: one
        return _skip_leb(data, pos)
    raise _WasmParseError(f"unknown misc subop {sub}")


def _skip_simd_immediates(data: bytes, sub: int, pos: int) -> int:
    """Skip a 0xFD (SIMD) instruction's immediates; raise on unknown subops."""
    if sub <= 11 or sub in (92, 93):  # loads/stores and load_zero: memarg
        pos = _skip_leb(data, pos)
        return _skip_leb(data, pos)
    if sub in (12, 13):  # v128.const / i8x16.shuffle: 16 raw bytes
        return pos + 16
    if 21 <= sub <= 34:  # extract/replace lane: one lane byte
        return pos + 1
    if 84 <= sub <= 91:  # load/store lane: memarg + lane byte
        pos = _skip_leb(data, pos)
        return _skip_leb(data, pos) + 1
    if sub <= 275:  # plain vector ops (incl. relaxed SIMD): no immediates
        return pos
    raise _WasmParseError(f"unknown SIMD subop {sub}")


def _walk_body(code: bytes) -> tuple[list[int], int, int, bool]:
    """Walk one function body collecting direct-call targets.

    Returns (call targets in order, direct call sites, indirect call sites,
    decoded). The body is size-delimited by the code section, so on an opcode
    outside the walker's table the body is abandoned (decoded False) with the
    calls found so far kept, and the caller resumes at the next body.
    """
    callees: list[int] = []
    direct = 0
    indirect = 0
    try:
        declcount, pos = _read_uleb(code, 0)
        for _ in range(declcount):
            _n, pos = _read_uleb(code, pos)
            pos += 1  # the declared valtype
        if pos > len(code):
            raise _WasmParseError("locals run past the body")
        while pos < len(code):
            op = code[pos]
            pos += 1
            if op in _WASM_OPS_NO_IMMEDIATE:
                continue
            if op in _WASM_OPS_ONE_LEB:
                pos = _skip_leb(code, pos)
            elif op == 0x10 or op == 0x12:  # call / return_call
                target, pos = _read_uleb(code, pos)
                callees.append(target)
                direct += 1
            elif op == 0x11 or op == 0x13:  # call_indirect variants
                pos = _skip_leb(code, pos)  # typeidx
                pos = _skip_leb(code, pos)  # tableidx
                indirect += 1
            elif op == 0x0E:  # br_table: vec(label) + default label
                n, pos = _read_uleb(code, pos)
                for _ in range(n + 1):
                    pos = _skip_leb(code, pos)
            elif op == 0x1C:  # select t*: vec(valtype)
                n, pos = _read_uleb(code, pos)
                pos += n
            elif 0x28 <= op <= 0x3E:  # loads/stores: memarg
                pos = _skip_leb(code, pos)
                pos = _skip_leb(code, pos)
            elif op == 0x43:  # f32.const
                pos += 4
            elif op == 0x44:  # f64.const
                pos += 8
            elif op == 0xFC:
                sub, pos = _read_uleb(code, pos)
                pos = _skip_misc_immediates(code, sub, pos)
            elif op == 0xFD:
                sub, pos = _read_uleb(code, pos)
                pos = _skip_simd_immediates(code, sub, pos)
            elif op == 0xFE:  # atomics: memarg, except atomic.fence's flag byte
                sub, pos = _read_uleb(code, pos)
                if sub == 3:
                    pos += 1
                elif sub <= 0x4E:
                    pos = _skip_leb(code, pos)
                    pos = _skip_leb(code, pos)
                else:
                    raise _WasmParseError(f"unknown atomic subop {sub}")
            else:  # 0xFB GC prefix and anything newer
                raise _WasmParseError(f"unknown opcode {op:#x}")
            if pos > len(code):
                raise _WasmParseError("instruction runs past the body")
    except _WasmParseError:
        return callees, direct, indirect, False
    return callees, direct, indirect, True


def parse_wasm_calls(path: Path, *, offset: int = 0, limit: int = 100) -> JsonObject:
    """Extract each function's direct call targets (the call graph), wabt-free.

    Who calls whom, statically: the code section's instruction streams are
    walked in pure Python -- no wabt needed -- and every ``call`` /
    ``return_call`` target is collected per function, so an export can be traced
    down to the routine that does the work (join indices against wasm.functions
    for names; call_indirect dispatch is counted here and its possible targets
    enumerated by wasm.elements). Each row is index (the function's index in the
    module-wide space, where imports occupy [0, imported_count) and have no
    bodies), callees (the function's distinct direct targets, sorted; capped at
    100 per function with callees_clipped), call_sites and call_indirect_sites
    (instruction counts, so N calls to one helper still read as N), and decoded
    -- false when the body used an opcode outside the walker's table (e.g. a GC
    proposal instruction); the calls found up to that point are kept, and
    because bodies are size-delimited the walk resumes cleanly at the next
    function. Answers with has_code_section (false for a module with no code
    section -- then functions is empty and total 0, not an error),
    imported_count, and functions with count, total, offset and has_more so a
    filled page is not read as the whole graph; total is capped at 50000 with
    scan_capped when more may exist, and truncated is true when the section
    itself is malformed (rows read so far are still returned). A file that is
    not a WebAssembly module is refused as invalid_params, one over 16 MiB as
    too_large.
    """
    resolved = _require_existing_file(path, missing="input file not found")
    try:
        raw = resolved.read_bytes()
    except OSError as exc:
        raise JsReError("backend_error", f"input unreadable: {exc}", path=str(resolved)) from exc
    if raw[:4] != _WASM_MAGIC:
        raise JsReError("invalid_params", "not a WebAssembly module", path=str(resolved))
    bodies, truncated = _collect_section_bodies(
        raw, frozenset({_WASM_IMPORT_SECTION_ID, _WASM_CODE_SECTION_ID})
    )
    imported_count = 0
    if _WASM_IMPORT_SECTION_ID in bodies:
        func_imports, imp_trunc = _parse_func_imports(bodies[_WASM_IMPORT_SECTION_ID])
        imported_count = len(func_imports)
        truncated = truncated or imp_trunc
    has_code_section = _WASM_CODE_SECTION_ID in bodies
    rows: list[JsonObject] = []
    scan_more = False
    if has_code_section:
        body = bodies[_WASM_CODE_SECTION_ID]
        try:
            count, pos = _read_uleb(body, 0)
            for i in range(count):
                if len(rows) >= _MAX_WASM_CALLS_COLLECT:
                    scan_more = True
                    break
                size, pos = _read_uleb(body, pos)
                if pos + size > len(body):
                    raise _WasmParseError("function body runs past the section")
                callees, direct, indirect, decoded = _walk_body(body[pos : pos + size])
                pos += size
                distinct = sorted(set(callees))
                clipped = len(distinct) > _MAX_WASM_CALLEES
                rows.append(
                    {
                        "index": imported_count + i,
                        "callees": distinct[:_MAX_WASM_CALLEES],
                        "callees_clipped": clipped,
                        "call_sites": direct,
                        "call_indirect_sites": indirect,
                        "decoded": decoded,
                    }
                )
        except _WasmParseError:
            truncated = True
    start = max(0, int(offset))
    cap = max(1, min(int(limit), _MAX_WASM_CALLS_PAGE))
    window = rows[start : start + cap]
    return {
        "functions": window,
        "has_code_section": has_code_section,
        "imported_count": imported_count,
        "count": len(window),
        "total": len(rows),
        "offset": start,
        "has_more": start + len(window) < len(rows),
        "scan_capped": scan_more,
        "truncated": truncated,
    }


def parse_wasm_callers(
    path: Path, *, function: int, offset: int = 0, limit: int = 100
) -> JsonObject:
    """Find every function that directly calls a given function (xrefs), wabt-free.

    The reverse of wasm.calls: name a target function index and this walks every
    code-section body in pure Python -- no wabt needed -- and reports the
    functions whose bodies contain a direct call / return_call to it, the "xrefs
    to this function" a disassembler shows. It answers the first question of a
    triage -- who reaches this suspicious import or routine (resolve the target
    and the callers against wasm.functions for names) -- server-side, so a large
    module's whole call graph need not be paged through to filter it client-side.
    Each row is index (the caller's module-wide function index) and call_sites
    (how many call instructions in it target the function, so a helper invoked
    three times reads as 3) with decoded (false when that caller's body used an
    opcode outside the walker's table, meaning its count may be low). Indirect
    calls are invisible here by nature -- a call_indirect names no callee -- so
    wasm.elements enumerates a table's possible targets instead. Returns target
    (echoed back), has_code_section (false when the module has no code section --
    then callers is empty and total 0, not an error), imported_count,
    undecoded_bodies (functions the walker could not fully decode, whose calls to
    the target may be missed) and callers with count, total, offset and has_more
    so a filled page is not read as every caller; total is capped at 50000 with
    scan_capped when more may exist, and truncated is true when the code section
    itself is malformed (callers found so far are still returned). A file that is
    not a WebAssembly module is refused as invalid_params, one over 16 MiB as
    too_large.
    """
    resolved = _require_existing_file(path, missing="input file not found")
    try:
        raw = resolved.read_bytes()
    except OSError as exc:
        raise JsReError("backend_error", f"input unreadable: {exc}", path=str(resolved)) from exc
    if raw[:4] != _WASM_MAGIC:
        raise JsReError("invalid_params", "not a WebAssembly module", path=str(resolved))
    target = int(function)
    bodies, truncated = _collect_section_bodies(
        raw, frozenset({_WASM_IMPORT_SECTION_ID, _WASM_CODE_SECTION_ID})
    )
    imported_count = 0
    if _WASM_IMPORT_SECTION_ID in bodies:
        func_imports, imp_trunc = _parse_func_imports(bodies[_WASM_IMPORT_SECTION_ID])
        imported_count = len(func_imports)
        truncated = truncated or imp_trunc
    has_code_section = _WASM_CODE_SECTION_ID in bodies
    rows: list[JsonObject] = []
    scan_more = False
    undecoded = 0
    if has_code_section:
        body = bodies[_WASM_CODE_SECTION_ID]
        try:
            count, pos = _read_uleb(body, 0)
            for i in range(count):
                size, pos = _read_uleb(body, pos)
                if pos + size > len(body):
                    raise _WasmParseError("function body runs past the section")
                callees, _direct, _indirect, decoded = _walk_body(body[pos : pos + size])
                pos += size
                if not decoded:
                    undecoded += 1
                hits = sum(1 for callee in callees if callee == target)
                if hits:
                    if len(rows) >= _MAX_WASM_CALLERS_COLLECT:
                        scan_more = True
                        break
                    rows.append(
                        {
                            "index": imported_count + i,
                            "call_sites": hits,
                            "decoded": decoded,
                        }
                    )
        except _WasmParseError:
            truncated = True
    start = max(0, int(offset))
    cap = max(1, min(int(limit), _MAX_WASM_CALLERS_PAGE))
    window = rows[start : start + cap]
    return {
        "target": target,
        "callers": window,
        "has_code_section": has_code_section,
        "imported_count": imported_count,
        "undecoded_bodies": undecoded,
        "count": len(window),
        "total": len(rows),
        "offset": start,
        "has_more": start + len(window) < len(rows),
        "scan_capped": scan_more,
        "truncated": truncated,
    }


def _parse_producers(body: bytes) -> tuple[list[JsonObject], bool, bool]:
    """Flatten the producers section; return (rows, scan_more, truncated)."""
    rows: list[JsonObject] = []
    scan_more = False
    try:
        field_count, pos = _read_uleb(body, 0)
        for _ in range(field_count):
            field_name, pos = _read_wasm_name(body, pos)
            value_count, pos = _read_uleb(body, pos)
            for _ in range(value_count):
                name, pos = _read_wasm_name(body, pos)
                version, pos = _read_wasm_name(body, pos)
                if len(rows) >= _MAX_WASM_PRODUCERS_COLLECT:
                    scan_more = True
                    break
                rows.append({"field": field_name, "name": name, "version": version})
            if scan_more:
                break
    except _WasmParseError:
        return rows, scan_more, True
    return rows, scan_more, False


def parse_wasm_producers(path: Path, *, offset: int = 0, limit: int = 100) -> JsonObject:
    """Decode a WebAssembly module's build-toolchain fingerprint, wabt-free.

    The "producers" custom section records what built the module -- the source
    language, the compilers and tools it passed through, and the SDK -- so this
    is the provenance a triage opens with: knowing it came from Rust 1.75 via
    LLVM, or Emscripten, or wasm-bindgen, points straight at the right
    deobfuscation and naming strategy. Read in pure Python -- no wabt needed --
    and it says what wasm.sections cannot (that tool only reports the custom
    section exists). The section's fields (conventionally language, processed-by
    and sdk) are flattened to one row per tool: field (which of the three it came
    from), name (the language or tool, e.g. Rust, clang, wasm-bindgen) and
    version (a free-form string, empty when the producer left it blank). Returns
    has_producers_section (false when the module has none -- then producers is
    empty and total 0, not an error), and producers with count, total, offset
    and has_more so a filled page is not read as the whole list; total is capped
    at 10000 with scan_capped when more may exist, and truncated is true when the
    section is malformed (rows read so far are still returned). Note the section
    is self-reported and strippable, so its absence is not proof of anything. A
    file that is not a WebAssembly module is refused as invalid_params, one over
    16 MiB as too_large.
    """
    resolved = _require_existing_file(path, missing="input file not found")
    try:
        raw = resolved.read_bytes()
    except OSError as exc:
        raise JsReError("backend_error", f"input unreadable: {exc}", path=str(resolved)) from exc
    if raw[:4] != _WASM_MAGIC:
        raise JsReError("invalid_params", "not a WebAssembly module", path=str(resolved))
    body, truncated = _find_custom_section(raw, "producers")
    has_producers_section = body is not None
    rows: list[JsonObject] = []
    scan_more = False
    if body is not None:
        rows, scan_more, prod_trunc = _parse_producers(body)
        truncated = truncated or prod_trunc
    start = max(0, int(offset))
    cap = max(1, min(int(limit), _MAX_WASM_PRODUCERS_PAGE))
    window = rows[start : start + cap]
    return {
        "producers": window,
        "has_producers_section": has_producers_section,
        "count": len(window),
        "total": len(rows),
        "offset": start,
        "has_more": start + len(window) < len(rows),
        "scan_capped": scan_more,
        "truncated": truncated,
    }


def _parse_target_features(body: bytes) -> tuple[list[JsonObject], bool, bool]:
    """Parse the target_features section; return (rows, scan_more, truncated)."""
    rows: list[JsonObject] = []
    scan_more = False
    try:
        count, pos = _read_uleb(body, 0)
        for _ in range(count):
            prefix_byte = _byte_at(body, pos)
            pos += 1
            name, pos = _read_wasm_name(body, pos)
            if len(rows) >= _MAX_WASM_FEATURES_COLLECT:
                scan_more = True
                break
            rows.append(
                {
                    "name": name,
                    "prefix": _WASM_FEATURE_PREFIXES.get(prefix_byte, f"0x{prefix_byte:02x}"),
                }
            )
    except _WasmParseError:
        return rows, scan_more, True
    return rows, scan_more, False


def parse_wasm_features(path: Path, *, offset: int = 0, limit: int = 100) -> JsonObject:
    """List the WebAssembly features a module was built to use, wabt-free.

    The "target_features" custom section is the capability requirement a
    toolchain (LLVM / wasm-ld) records: which proposals beyond the MVP the
    module uses -- simd128, atomics (threads and shared memory),
    exception-handling, bulk-memory, reference-types, tail-call, sign-ext,
    multivalue and the like. Read in pure Python -- no wabt needed -- it tells a
    triage what runtime the module needs and how much of the modern instruction
    set to expect, which wasm.sections cannot (it only reports the custom
    section exists). It is the capability companion to wasm.producers'
    provenance. Each row is name (the feature) and prefix, the one-byte marker:
    "+" the feature is used, "-" it must not be enabled, "=" it is required
    exactly (an unknown marker byte renders as hex); wasm-ld emits "+" for
    everything a module actually uses, so in practice the rows are the used-
    feature set. Returns has_target_features_section (false when the module has
    none -- then features is empty and total 0, not an error) and features with
    count, total, offset and has_more so a filled page is not read as the whole
    set; total is capped at 10000 with scan_capped when more may exist, and
    truncated is true when the section is malformed (rows read so far are still
    returned). The section is self-reported and strippable, so its absence is
    not proof the features are unused. A file that is not a WebAssembly module is
    refused as invalid_params, one over 16 MiB as too_large.
    """
    resolved = _require_existing_file(path, missing="input file not found")
    try:
        raw = resolved.read_bytes()
    except OSError as exc:
        raise JsReError("backend_error", f"input unreadable: {exc}", path=str(resolved)) from exc
    if raw[:4] != _WASM_MAGIC:
        raise JsReError("invalid_params", "not a WebAssembly module", path=str(resolved))
    body, truncated = _find_custom_section(raw, "target_features")
    has_target_features_section = body is not None
    rows: list[JsonObject] = []
    scan_more = False
    if body is not None:
        rows, scan_more, feat_trunc = _parse_target_features(body)
        truncated = truncated or feat_trunc
    start = max(0, int(offset))
    cap = max(1, min(int(limit), _MAX_WASM_FEATURES_PAGE))
    window = rows[start : start + cap]
    return {
        "features": window,
        "has_target_features_section": has_target_features_section,
        "count": len(window),
        "total": len(rows),
        "offset": start,
        "has_more": start + len(window) < len(rows),
        "scan_capped": scan_more,
        "truncated": truncated,
    }


def parse_wasm_start(path: Path) -> JsonObject:
    """Report a WebAssembly module's start function -- what runs on load, wabt-free.

    The start section names the one function a runtime calls automatically when
    the module is instantiated, before any export is invoked, which makes it a
    prime spot for initialisation, self-unpacking or anti-analysis code -- the
    first thing to read when a module "does something" merely by loading. Read
    in pure Python -- no wabt needed. Unlike the listing tools this returns a
    scalar, because a module has at most one start function: has_start_section
    (false when the module declares none -- the common case, not an error),
    start_function (its module-wide function index, or null), and kind --
    "import" when that index falls in the imported range, which is unusual and
    worth noting, "local" for a module-defined function, or null when there is
    no start (resolve the index against wasm.functions for a name, and
    wasm.calls for what it goes on to invoke). imported_count is given as the
    context needed to read the index. truncated is true when the section is
    malformed. A file that is not a WebAssembly module is refused as
    invalid_params, one over 16 MiB as too_large.
    """
    resolved = _require_existing_file(path, missing="input file not found")
    try:
        raw = resolved.read_bytes()
    except OSError as exc:
        raise JsReError("backend_error", f"input unreadable: {exc}", path=str(resolved)) from exc
    if raw[:4] != _WASM_MAGIC:
        raise JsReError("invalid_params", "not a WebAssembly module", path=str(resolved))
    bodies, truncated = _collect_section_bodies(
        raw, frozenset({_WASM_IMPORT_SECTION_ID, _WASM_START_SECTION_ID})
    )
    imported_count = 0
    if _WASM_IMPORT_SECTION_ID in bodies:
        func_imports, imp_trunc = _parse_func_imports(bodies[_WASM_IMPORT_SECTION_ID])
        imported_count = len(func_imports)
        truncated = truncated or imp_trunc
    has_start_section = _WASM_START_SECTION_ID in bodies
    start_function: int | None = None
    kind: str | None = None
    if has_start_section:
        try:
            start_function, _pos = _read_uleb(bodies[_WASM_START_SECTION_ID], 0)
            kind = "import" if start_function < imported_count else "local"
        except _WasmParseError:
            truncated = True
    return {
        "has_start_section": has_start_section,
        "start_function": start_function,
        "kind": kind,
        "imported_count": imported_count,
        "truncated": truncated,
    }


_JS_SIMPLE_ESCAPES = {
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "b": "\b",
    "f": "\f",
    "v": "\v",
    "0": "\0",
    "\\": "\\",
    "'": "'",
    '"': '"',
    "`": "`",
    "/": "/",
    "\n": "",  # a backslash-newline line continuation contributes nothing
}


def _decode_js_escape(text: str, i: int) -> tuple[str, int]:
    """Decode one JS escape at ``text[i]`` (the char after the backslash).

    Returns (decoded, next_index). Handles the simple one-char escapes plus
    ``\\xHH`` / ``\\uHHHH`` / ``\\u{...}``; a malformed hex escape degrades to
    the literal characters rather than raising, so a best-effort scan never
    dies on bad input.
    """
    if i >= len(text):
        return "\\", i
    char = text[i]
    if char == "x" and i + 3 <= len(text):
        hexits = text[i + 1 : i + 3]
        try:
            return chr(int(hexits, 16)), i + 3
        except ValueError:
            return "x", i + 1
    if char == "u":
        if i + 1 < len(text) and text[i + 1] == "{":
            close = text.find("}", i + 2)
            if close != -1:
                try:
                    return chr(int(text[i + 2 : close], 16)), close + 1
                except ValueError:
                    return "u", i + 1
        elif i + 5 <= len(text):
            hexits = text[i + 1 : i + 5]
            try:
                return chr(int(hexits, 16)), i + 5
            except ValueError:
                return "u", i + 1
    return _JS_SIMPLE_ESCAPES.get(char, char), i + 1


def _scan_js_string_literals(
    text: str, *, min_len: int, collect_cap: int, str_cap: int
) -> tuple[list[str], bool, bool]:
    """Extract distinct JS string literals in first-seen order (best-effort).

    A single left-to-right pass that skips ``//`` and ``/* */`` comments (the
    biggest source of quote-shaped false positives) and then collects the
    contents of ``'``, ``"`` and ``` ``` ``` literals, decoding backslash
    escapes so an obfuscated ``\\x68\\x74\\x74\\x70`` reads back as ``http``.
    It does not track regex literals, so a divide/regex ambiguity can misread a
    ``/.../`` containing a quote -- the accepted cost of not lexing JS fully.
    Literals shorter than min_len are dropped and longer than str_cap clipped;
    the list is de-duplicated. Returns (strings, scan_more, truncated), where
    scan_more is True once collect_cap distinct literals are held and another
    is seen, and truncated is True when the text ended inside an open literal
    or block comment (that unterminated run is not emitted).
    """
    result: dict[str, None] = {}
    scan_more = False
    truncated = False
    n = len(text)
    i = 0
    while i < n:
        char = text[i]
        if char == "/" and i + 1 < n and text[i + 1] == "/":
            nl = text.find("\n", i + 2)
            i = n if nl == -1 else nl + 1
            continue
        if char == "/" and i + 1 < n and text[i + 1] == "*":
            close = text.find("*/", i + 2)
            if close == -1:
                truncated = True
                break
            i = close + 2
            continue
        if char in "'\"`":
            quote = char
            i += 1
            chars: list[str] = []
            closed = False
            while i < n:
                cur = text[i]
                if cur == "\\":
                    decoded, i = _decode_js_escape(text, i + 1)
                    chars.append(decoded)
                    continue
                if cur == quote:
                    closed = True
                    i += 1
                    break
                chars.append(cur)
                i += 1
            if not closed:
                truncated = True
                break
            value = "".join(chars)[:str_cap]
            if len(value) < min_len or value in result:
                continue
            if len(result) >= collect_cap:
                scan_more = True
                break
            result[value] = None
            continue
        i += 1
    return list(result.keys()), scan_more, truncated


def scan_js_strings(
    path: Path,
    *,
    offset: int = 0,
    limit: int = 100,
    min_length: int = _JS_DEFAULT_MIN_STRING,
) -> JsonObject:
    """Extract string literals from a JavaScript file in pure Python, node-free.

    `strings` for JavaScript: it surfaces the quoted literals -- the URLs, API
    endpoints, file paths, error messages and embedded secrets an app hard-codes
    -- so unlike js.deobfuscate / js.beautify it needs no webcrack or Node
    installed. It reads the source as text and makes one comment-aware pass over
    ``'``/``"``/`` `` `` literals, decoding backslash escapes so an obfuscated
    ``\\x68\\x74\\x74\\x70`` or ``\\u002f`` reads back as ``http`` / ``/``. It
    does not fully lex JS: regex literals are not tracked, so a divide/regex
    ambiguity can occasionally misread one (the accepted cost of a robust
    best-effort scan over a fragile parser). Literals shorter than min_length
    (default 4) are dropped and longer than 2048 characters clipped; results are
    de-duplicated and kept in first-appearance order. Answers with input_bytes
    (the scanned size), min_length, and strings with count, total, offset and
    has_more so a filled page is not read as every literal; total is capped at
    50000 with scan_capped when more may exist, and truncated is true when the
    text ended inside an open literal or block comment. A missing file is
    not_found, one over 16 MiB too_large.
    """
    resolved = _require_existing_file(path, missing="input file not found")
    try:
        raw = resolved.read_bytes()
    except OSError as exc:
        raise JsReError("backend_error", f"input unreadable: {exc}", path=str(resolved)) from exc
    text = raw.decode("utf-8", errors="replace")
    min_len = max(1, min(int(min_length), _JS_MAX_MIN_STRING))
    found, scan_more, truncated = _scan_js_string_literals(
        text,
        min_len=min_len,
        collect_cap=_MAX_JS_STRINGS_COLLECT,
        str_cap=_MAX_JS_STRING_LEN,
    )
    start = max(0, int(offset))
    cap = max(1, min(int(limit), _MAX_JS_STRINGS_PAGE))
    window = found[start : start + cap]
    return {
        "strings": window,
        "input_bytes": len(raw),
        "min_length": min_len,
        "count": len(window),
        "total": len(found),
        "offset": start,
        "has_more": start + len(window) < len(found),
        "scan_capped": scan_more,
        "truncated": truncated,
    }


# A scheme, "://", then a run of URL-legal bytes. The trailing class excludes
# whitespace, quotes, brackets and backslashes, so the match stops at the
# literal's edge; the bounded {1,2048} keeps it linear with no backtracking.
_JS_URL_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9+.\-]{0,31}://[^\s\"'`<>\\)\]}]{1,2048}")
# Punctuation that commonly trails a URL in prose rather than belonging to it.
_JS_URL_TRAILING = ".,;:!?)]}'\""


def _extract_js_endpoints(
    literals: list[str], *, collect_cap: int
) -> tuple[list[JsonObject], bool]:
    """Pull scheme://host URLs out of already-decoded string literals.

    Returns (rows, scan_more). Each row is url and host (the authority after
    ``://`` up to the first ``/?#``, with any ``userinfo@`` dropped). URLs are
    de-duplicated in first-seen order; scan_more is True once collect_cap
    distinct URLs are held and another is seen.
    """
    seen: dict[str, str] = {}
    scan_more = False
    for literal in literals:
        for match in _JS_URL_RE.finditer(literal):
            url = match.group().rstrip(_JS_URL_TRAILING)
            if not url or url in seen:
                continue
            if len(seen) >= collect_cap:
                scan_more = True
                break
            authority = url.split("://", 1)[1]
            for sep in ("/", "?", "#"):
                authority = authority.split(sep, 1)[0]
            host = authority.rsplit("@", 1)[-1]
            seen[url] = host
        if scan_more:
            break
    rows = [{"url": url, "host": host} for url, host in seen.items()]
    return rows, scan_more


def scan_js_endpoints(path: Path, *, offset: int = 0, limit: int = 100) -> JsonObject:
    """Extract the URLs a JavaScript file talks to, node-free.

    The "what does this bundle contact" pivot: it surfaces the ``scheme://host``
    URLs -- http, https, ws, wss, ftp and the like -- hard-coded in a script's
    string literals, the C2/API/CDN hosts that are the first IOCs of web triage.
    It reuses js.strings' comment-aware, escape-decoding literal scan, so a URL
    obfuscated as ``\\x68\\x74\\x74\\x70...`` is caught once decoded, and needs
    no webcrack or Node. To stay high-signal it matches only URLs carrying a
    scheme (schemeless relative paths like ``/api/x`` are left to js.strings)
    and reports each url with its host (the authority after ``://``, userinfo
    stripped). Results are de-duplicated by url in first-appearance order.
    Answers with input_bytes and endpoints with count, total, offset and
    has_more so a filled page is not read as every URL; total is capped at
    10000 with scan_capped when more may exist, and truncated is true when the
    text ended inside an open literal or block comment. A missing file is
    not_found, one over 16 MiB too_large.
    """
    resolved = _require_existing_file(path, missing="input file not found")
    try:
        raw = resolved.read_bytes()
    except OSError as exc:
        raise JsReError("backend_error", f"input unreadable: {exc}", path=str(resolved)) from exc
    text = raw.decode("utf-8", errors="replace")
    literals, literal_more, truncated = _scan_js_string_literals(
        text,
        min_len=1,
        collect_cap=_MAX_JS_STRINGS_COLLECT,
        str_cap=_MAX_JS_STRING_LEN,
    )
    found, endpoint_more = _extract_js_endpoints(literals, collect_cap=_MAX_JS_ENDPOINTS_COLLECT)
    # Either cap -- the literal scan's or the endpoint dedup's -- means more
    # URLs may exist, so both fold into the one scan_capped the caller reads.
    scan_more = endpoint_more or literal_more
    start = max(0, int(offset))
    cap = max(1, min(int(limit), _MAX_JS_ENDPOINTS_PAGE))
    window = found[start : start + cap]
    return {
        "endpoints": window,
        "input_bytes": len(raw),
        "count": len(window),
        "total": len(found),
        "offset": start,
        "has_more": start + len(window) < len(found),
        "scan_capped": scan_more,
        "truncated": truncated,
    }


def _run(
    cmd: list[str], *, timeout: float, maximum: float = _MAX_TIMEOUT_S
) -> tuple[str, str, int]:
    try:
        timeout = clamp_cli_timeout(timeout, maximum=maximum)
    except InvalidTimeout as exc:
        raise JsReError("invalid_params", str(exc)) from exc
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    try:
        completed = run_bounded(cmd, timeout=timeout, creationflags=creationflags)
    except TimedOut as exc:
        # webcrack runs under node, which the launcher starts as a child, so
        # the deadline has to reach it too.
        raise JsReError(
            "timeout", "tool timed out", timeout=timeout, killed_pids=exc.killed
        ) from exc
    except OSError as exc:
        raise JsReError("backend_error", f"failed to launch {cmd[0]}: {exc}") from exc
    stdout = completed.stdout.decode("utf-8", errors="replace")
    stderr = completed.stderr.decode("utf-8", errors="replace")
    return stdout, stderr, int(completed.returncode)


def _bounded_output(text: str, key: str, *, include_bytes: bool) -> JsonObject:
    payload = text.encode("utf-8", errors="replace")
    result: JsonObject = {
        key: payload[:_MAX_INLINE].decode("utf-8", errors="ignore"),
        "truncated": len(payload) > _MAX_INLINE,
    }
    if include_bytes:
        result["bytes"] = len(payload)
    return result


def _note_nonzero_exit(result: JsonObject, *, code: int, stderr: str) -> JsonObject:
    """Say when the tool exited non-zero but still produced output.

    These CLIs are kept on the "return what we got" path on purpose -- webcrack
    exits non-zero on a partial deobfuscation while still emitting usable code,
    and wasm-objdump can print sections before it trips on a later one. But a
    clean pass and a bail-out that happened to print something were otherwise
    indistinguishable: the reply carried no exit status, so an unattended agent
    read a truncated-because-the-tool-died result as the finished article.
    ``tool_failed`` is distinct from ``truncated`` (which is only ever "we cut
    the text at the inline cap"): it means the child itself signalled failure,
    so the output may be incomplete for a reason we cannot see.
    """
    if code != 0:
        result["exit_code"] = code
        result["tool_failed"] = True
        result["stderr"] = stderr[:_MAX_STDERR]
    return result


class JsClient:
    """webcrack-backed JavaScript deobfuscation and bundle unpacking."""

    def __init__(self, executable: Path | None = None) -> None:
        self.executable = executable or _discover_webcrack()

    @property
    def available(self) -> bool:
        return self.executable is not None

    def _require_input(self, path: Path) -> Path:
        if self.executable is None:
            raise JsReError(
                "capability_unavailable", "webcrack is not configured (needs Node 22/24)"
            )
        return _require_existing_file(path, missing="input file not found")

    def deobfuscate(self, path: Path, *, timeout: float = 120.0) -> JsonObject:
        resolved = self._require_input(path)
        stdout, stderr, code = _run(
            [str(self.executable), str(resolved)], timeout=timeout, maximum=_MAX_TIMEOUT_S
        )
        if code != 0 and not stdout:
            raise JsReError(
                "backend_error", "webcrack failed", exit_code=code, stderr=stderr[:_MAX_STDERR]
            )
        return _note_nonzero_exit(
            _bounded_output(stdout, "code", include_bytes=True), code=code, stderr=stderr
        )

    def beautify(self, path: Path, *, timeout: float = 120.0) -> JsonObject:
        # webcrack always unminifies; expose it under a formatting-focused name.
        return self.deobfuscate(path, timeout=timeout)

    def unpack_bundle(
        self,
        path: Path,
        out_dir: Path,
        *,
        timeout: float = 300.0,
        offset: int = 0,
        limit: int = 100,
    ) -> JsonObject:
        resolved = self._require_input(path)
        out_dir.mkdir(parents=True, exist_ok=True)
        stdout, stderr, code = _run(
            [str(self.executable), str(resolved), "-o", str(out_dir)],
            timeout=timeout,
            maximum=_MAX_UNPACK_TIMEOUT_S,
        )
        files, file_count, listed_more = _capped_file_listing(out_dir, cap=_MAX_COUNTED_FILES)
        if code != 0 and not files:
            raise JsReError(
                "backend_error",
                "webcrack unpack failed",
                exit_code=code,
                stderr=stderr[:_MAX_STDERR],
            )
        start = max(0, int(offset))
        cap = max(1, min(int(limit), _MAX_LISTED_FILES))
        window = files[start : start + cap]
        result: JsonObject = {
            "output_dir": str(out_dir),
            "file_count": file_count,
            "files": window,
            "count": len(window),
            "total": file_count,
            "offset": start,
            "has_more": start + len(window) < file_count,
            "listing_truncated": listed_more,
        }
        return _note_nonzero_exit(result, code=code, stderr=stderr)


class WasmClient:
    """wabt-backed WebAssembly inspection (wasm2wat, wasm-objdump)."""

    def __init__(self, wabt: Path | None = None) -> None:
        self._wasm2wat = _resolve_wabt_tool(wabt, "wasm2wat")
        self._objdump = _resolve_wabt_tool(wabt, "wasm-objdump")

    @property
    def available(self) -> bool:
        return self._wasm2wat is not None

    def _require_input(self, path: Path, tool: Path | None, name: str) -> Path:
        if tool is None:
            raise JsReError("capability_unavailable", f"{name} (wabt) is not configured")
        resolved = _require_existing_file(path, missing="wasm file not found")
        # The size cap runs first (above): an oversized non-module is still
        # refused as too_large, not misreported as a bad-magic file.
        if not _looks_like_wasm(resolved):
            raise JsReError(
                "invalid_params",
                "not a WebAssembly module: missing the \\0asm magic",
                path=str(resolved),
            )
        return resolved

    def wat(self, path: Path, *, timeout: float = 120.0) -> JsonObject:
        resolved = self._require_input(path, self._wasm2wat, "wasm2wat")
        assert self._wasm2wat is not None
        stdout, stderr, code = _run([str(self._wasm2wat), str(resolved)], timeout=timeout)
        if code != 0 and not stdout:
            raise JsReError(
                "backend_error", "wasm2wat failed", exit_code=code, stderr=stderr[:_MAX_STDERR]
            )
        return _note_nonzero_exit(
            _bounded_output(stdout, "wat", include_bytes=True), code=code, stderr=stderr
        )

    def info(self, path: Path, *, timeout: float = 120.0) -> JsonObject:
        resolved = self._require_input(path, self._objdump, "wasm-objdump")
        assert self._objdump is not None
        stdout, stderr, code = _run(
            [str(self._objdump), "-h", "-x", str(resolved)], timeout=timeout
        )
        if code != 0 and not stdout:
            raise JsReError(
                "backend_error", "wasm-objdump failed", exit_code=code, stderr=stderr[:_MAX_STDERR]
            )
        return _note_nonzero_exit(
            _bounded_output(stdout, "objdump", include_bytes=False), code=code, stderr=stderr
        )


def _discover_webcrack() -> Path | None:
    found = shutil.which("webcrack")
    return Path(found) if found else None


def _resolve_wabt_tool(wabt: Path | None, tool: str) -> Path | None:
    exe = tool + (".exe" if os.name == "nt" else "")
    if wabt is not None:
        candidate = wabt if wabt.name.lower().startswith(tool) else wabt / exe
        if candidate.is_file():
            return candidate
        # wabt may point at the bin directory.
        alt = wabt / "bin" / exe
        if alt.is_file():
            return alt
    found = shutil.which(tool)
    return Path(found) if found else None
