"""webcrack (JS) and wabt (WASM) wrapped as bounded one-shot subprocesses.

Both CLIs are optional and user-provided, exactly like UPX/DIE: a missing tool
degrades to ``capability_unavailable`` rather than blocking readiness. webcrack
needs Node.js 22 or 24; wabt provides ``wasm2wat`` and ``wasm-objdump``.
"""

from __future__ import annotations

import os
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
