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
        raise JsReError(
            "backend_error", f"input unreadable: {exc}", path=str(resolved)
        ) from exc
    if raw[:4] != _WASM_MAGIC:
        raise JsReError(
            "invalid_params", "not a WebAssembly module", path=str(resolved)
        )
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
        raise JsReError(
            "backend_error", f"input unreadable: {exc}", path=str(resolved)
        ) from exc
    if raw[:4] != _WASM_MAGIC:
        raise JsReError(
            "invalid_params", "not a WebAssembly module", path=str(resolved)
        )
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
        raise JsReError(
            "backend_error", f"input unreadable: {exc}", path=str(resolved)
        ) from exc
    if raw[:4] != _WASM_MAGIC:
        raise JsReError(
            "invalid_params", "not a WebAssembly module", path=str(resolved)
        )
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
        raise JsReError(
            "backend_error", f"input unreadable: {exc}", path=str(resolved)
        ) from exc
    if raw[:4] != _WASM_MAGIC:
        raise JsReError(
            "invalid_params", "not a WebAssembly module", path=str(resolved)
        )
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


def _collect_section_bodies(
    raw: bytes, ids: frozenset[int]
) -> tuple[dict[int, bytes], bool]:
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


def parse_wasm_functions(
    path: Path, *, offset: int = 0, limit: int = 100
) -> JsonObject:
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
        raise JsReError(
            "backend_error", f"input unreadable: {exc}", path=str(resolved)
        ) from exc
    if raw[:4] != _WASM_MAGIC:
        raise JsReError(
            "invalid_params", "not a WebAssembly module", path=str(resolved)
        )
    wanted = frozenset(
        {_WASM_TYPE_SECTION_ID, _WASM_IMPORT_SECTION_ID, _WASM_FUNCTION_SECTION_ID}
    )
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
        local_typeidxs, fn_trunc = _parse_function_section(
            bodies[_WASM_FUNCTION_SECTION_ID]
        )
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
        raise JsReError(
            "backend_error", f"input unreadable: {exc}", path=str(resolved)
        ) from exc
    if raw[:4] != _WASM_MAGIC:
        raise JsReError(
            "invalid_params", "not a WebAssembly module", path=str(resolved)
        )
    bodies, truncated = _collect_section_bodies(
        raw, frozenset({_WASM_DATA_SECTION_ID})
    )
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


def parse_wasm_globals(
    path: Path, *, offset: int = 0, limit: int = 100
) -> JsonObject:
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
        raise JsReError(
            "backend_error", f"input unreadable: {exc}", path=str(resolved)
        ) from exc
    if raw[:4] != _WASM_MAGIC:
        raise JsReError(
            "invalid_params", "not a WebAssembly module", path=str(resolved)
        )
    bodies, truncated = _collect_section_bodies(
        raw, frozenset({_WASM_IMPORT_SECTION_ID, _WASM_GLOBAL_SECTION_ID})
    )
    global_imports: list[tuple[str, str, int, int]] = []
    local_globals: list[tuple[int, int]] = []
    if _WASM_IMPORT_SECTION_ID in bodies:
        global_imports, imp_trunc = _parse_global_imports(
            bodies[_WASM_IMPORT_SECTION_ID]
        )
        truncated = truncated or imp_trunc
    if _WASM_GLOBAL_SECTION_ID in bodies:
        local_globals, glob_trunc = _parse_global_section(
            bodies[_WASM_GLOBAL_SECTION_ID]
        )
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
                row.update(
                    {"mode": "active", "memory_index": 0, "memory_offset": memory_offset}
                )
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
        raise JsReError(
            "backend_error", f"input unreadable: {exc}", path=str(resolved)
        ) from exc
    if raw[:4] != _WASM_MAGIC:
        raise JsReError(
            "invalid_params", "not a WebAssembly module", path=str(resolved)
        )
    bodies, truncated = _collect_section_bodies(
        raw, frozenset({_WASM_DATA_SECTION_ID})
    )
    has_data_section = _WASM_DATA_SECTION_ID in bodies
    rows: list[JsonObject] = []
    scan_more = False
    if has_data_section:
        rows, scan_more, body_truncated = _parse_data_section(
            bodies[_WASM_DATA_SECTION_ID]
        )
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
