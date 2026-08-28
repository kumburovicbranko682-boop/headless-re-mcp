"""Dependency-free structured read of a WebAssembly module's shape.

wasm.wat and wasm.info shell out to wabt (wasm2wat / wasm-objdump) and hand
back a wall of text an agent must then grep -- and when wabt is not installed
the whole wasm line is capability_unavailable. This reads the module's binary
sections directly: no wabt, no subprocess, pure Python. It returns the two
things a triage pass wants structured -- the import section (the host interface
the module depends on: ``env.*`` JS glue, ``wasi_snapshot_preview1.*`` syscalls)
and the export section (its entry points) -- plus a one-line-per-section
overview and the start function when present.

Only the section framing and the import/export/start sections are decoded;
every other section (type, code, data, ...) is skipped by its declared size, so
a huge code section costs nothing here. Every read is bounds-checked against the
buffer and the section, LEB128 integers are length-bounded, the listed vectors
are capped, and the section walk is counted, so a malformed or hostile module
raises WasmParseError rather than looping, over-reading, or over-allocating.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from contextlib import suppress
from typing import Any

from headless_re_mcp.backends.common.endpoint_scan import iter_endpoint_matches
from headless_re_mcp.backends.common.secret_scan import iter_secret_matches

JsonObject = dict[str, Any]

WASM_MAGIC = b"\x00asm"

# external_kind (import/export descriptor tag) -> readable name.
_KIND_NAMES = {0: "func", 1: "table", 2: "memory", 3: "global"}

# valtype byte -> readable name, covering the MVP numeric types, the vector type
# (v128) and the reference types. A byte outside this set (a GC/typed-ref heap
# type, or corruption) is rendered as its hex so a signature is never silently
# wrong; it just reads "0x6e" instead of a name.
_VALTYPES = {
    0x7F: "i32",
    0x7E: "i64",
    0x7D: "f32",
    0x7C: "f64",
    0x7B: "v128",
    0x70: "funcref",
    0x6F: "externref",
}

_SECTION_NAMES = {
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

# A single import/export name; real ones are short identifiers. A length past
# this is a malformed/hostile module, refused before allocating the slice.
_MAX_NAME_BYTES = 4096
# Section records to enumerate before giving up: a real module has a dozen or so,
# and each record consumes >=2 bytes so a 16 MiB module cannot hold many, but the
# count is bounded explicitly rather than trusting that.
_MAX_SECTIONS = 4096
# LEB128 unsigned: 10 bytes covers a u64; a u32 index/size uses at most 5. Ten is
# the ceiling so a run of 0x80 continuation bytes cannot spin the decoder.
_MAX_LEB_BYTES = 10
# Function-name entries collected from the name section before the scan stops. A
# real module names one entry per function; a hostile name section could declare
# a huge namemap, so bound what is materialised (scan_capped when hit).
_MAX_NAMES_COLLECT = 50000
# Printable strings pulled from the data section before the scan stops. A real
# module's rodata holds thousands; bound what is materialised (scan_capped when
# hit) so an all-data module cannot grow the answer without bound.
_MAX_DATA_STRINGS_COLLECT = 100000
# One extracted string's on-disk run can be an embedded JSON/base64 blob; clip
# the returned text (size still reports the full run) so one string cannot bloat
# the page.
_MAX_STRING_TEXT = 4096
# A caller-supplied minimum run length is clamped to this so a value of 0 does
# not turn every byte into a "string".
_MIN_STRING_LEN_MAX = 256
# Distinct endpoints aggregated from the data section before the scan stops. A
# real module reaches a handful of backends; bound what is materialised
# (scan_capped when hit) so a URL-dense module cannot grow the answer forever.
_MAX_DATA_ENDPOINTS_COLLECT = 50000
# Distinct URL hosts summarised; a hostile module could embed many.
_MAX_DATA_HOSTS = 512
# Distinct credential findings aggregated from the data section before the scan
# stops (scan_capped when hit); the matched value is clipped so one embedded blob
# cannot bloat a finding.
_MAX_DATA_SECRETS_COLLECT = 20000
_MAX_DATA_SECRET_VALUE = 512
# Function-table caps. A real module has thousands of functions/types; these bound
# what wasm.functions materialises (scan_capped when hit) so a hostile section
# cannot grow the answer without bound. The per-functype vector cap bounds one
# signature's parameter/result count.
_MAX_TYPES_COLLECT = 200000
_MAX_FUNCTIONS_COLLECT = 200000
_MAX_TYPE_VEC = 4096


class WasmParseError(ValueError):
    """The bytes are not a WebAssembly module we can read structurally."""


def _uleb(data: bytes, pos: int) -> tuple[int, int]:
    """Read one unsigned LEB128 integer, returning (value, next_pos)."""
    result = 0
    shift = 0
    read = 0
    while True:
        if pos >= len(data):
            raise WasmParseError("truncated LEB128 integer")
        byte = data[pos]
        pos += 1
        read += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        if read >= _MAX_LEB_BYTES:
            raise WasmParseError("LEB128 integer too long")
        shift += 7


def _name(data: bytes, pos: int) -> tuple[str, int]:
    """Read a length-prefixed UTF-8 name, returning (text, next_pos)."""
    length, pos = _uleb(data, pos)
    if length > _MAX_NAME_BYTES:
        raise WasmParseError("name length exceeds bound")
    end = pos + length
    if end > len(data):
        raise WasmParseError("name overruns module")
    return data[pos:end].decode("utf-8", "replace"), end


def _skip_limits(data: bytes, pos: int) -> int:
    """Advance past a limits record (flags, min, and max when the flag is set)."""
    flags, pos = _uleb(data, pos)
    _min, pos = _uleb(data, pos)
    if flags & 0x01:
        _max, pos = _uleb(data, pos)
    return pos


def _need(pos: int, count: int, end: int, what: str) -> None:
    if pos + count > end:
        raise WasmParseError(f"{what} overruns section")


def _parse_imports(
    data: bytes, pos: int, end: int, *, cap: int
) -> tuple[list[JsonObject], int]:
    count, pos = _uleb(data, pos)
    items: list[JsonObject] = []
    parsed = 0
    while parsed < count and pos < end:
        if len(items) >= cap:
            # A full page is collected; the declared vector length is the total.
            break
        module, pos = _name(data, pos)
        field, pos = _name(data, pos)
        _need(pos, 1, end, "import kind")
        kind = data[pos]
        pos += 1
        entry: JsonObject = {
            "module": module,
            "name": field,
            "kind": _KIND_NAMES.get(kind, str(kind)),
        }
        if kind == 0:  # func: type index
            type_index, pos = _uleb(data, pos)
            entry["type_index"] = type_index
        elif kind == 1:  # table: reftype byte then limits
            _need(pos, 1, end, "table reftype")
            pos = _skip_limits(data, pos + 1)
        elif kind == 2:  # memory: limits
            pos = _skip_limits(data, pos)
        elif kind == 3:  # global: valtype byte + mutability byte
            _need(pos, 2, end, "global type")
            pos += 2
        else:
            raise WasmParseError(f"unknown import kind {kind}")
        if pos > end:
            raise WasmParseError("import entry overruns section")
        items.append(entry)
        parsed += 1
    return items, count


def _parse_exports(
    data: bytes, pos: int, end: int, *, cap: int
) -> tuple[list[JsonObject], int]:
    count, pos = _uleb(data, pos)
    items: list[JsonObject] = []
    parsed = 0
    while parsed < count and pos < end:
        if len(items) >= cap:
            break
        name, pos = _name(data, pos)
        _need(pos, 1, end, "export kind")
        kind = data[pos]
        pos += 1
        index, pos = _uleb(data, pos)
        if pos > end:
            raise WasmParseError("export entry overruns section")
        items.append(
            {"name": name, "kind": _KIND_NAMES.get(kind, str(kind)), "index": index}
        )
        parsed += 1
    return items, count


def _iter_sections(data: bytes) -> Iterator[tuple[int, int, int]]:
    """Yield (section_id, body_start, body_end) for each top-level section.

    Validates the magic once and the framing of every section (size never runs
    past the buffer, the record count is bounded); the caller decodes only the
    bodies it cares about and lets the rest go by.
    """
    if len(data) < 8 or data[:4] != WASM_MAGIC:
        raise WasmParseError("not a WebAssembly module (bad magic)")
    pos = 8
    total_len = len(data)
    records = 0
    while pos < total_len:
        records += 1
        if records > _MAX_SECTIONS:
            raise WasmParseError("too many sections")
        sec_id = data[pos]
        pos += 1
        size, pos = _uleb(data, pos)
        body = pos
        end = pos + size
        if end > total_len:
            raise WasmParseError("section overruns module")
        yield sec_id, body, end
        pos = end


def summarize(data: bytes, *, max_imports: int = 1000, max_exports: int = 1000) -> JsonObject:
    """Parse a wasm module's shape: version, sections, imports, exports, start.

    Raises WasmParseError when the bytes are not a module we can read. The
    imports/exports lists are capped at ``max_imports``/``max_exports``; the
    ``*_total`` fields carry the declared vector length so a capped page is not
    read as the whole section.
    """
    if len(data) < 8 or data[:4] != WASM_MAGIC:
        raise WasmParseError("not a WebAssembly module (bad magic)")
    version = int.from_bytes(data[4:8], "little")
    sections: list[JsonObject] = []
    imports: list[JsonObject] = []
    exports: list[JsonObject] = []
    imports_total = 0
    exports_total = 0
    start_function: int | None = None
    for sec_id, body, end in _iter_sections(data):
        record: JsonObject = {
            "id": sec_id,
            "name": _SECTION_NAMES.get(sec_id, str(sec_id)),
            "size": end - body,
        }
        if sec_id == 0:  # custom: a name, then opaque bytes -- surface the name
            with suppress(WasmParseError):
                record["custom_name"], _ = _name(data, body)
        sections.append(record)
        if sec_id == 2:
            imports, imports_total = _parse_imports(data, body, end, cap=max_imports)
        elif sec_id == 7:
            exports, exports_total = _parse_exports(data, body, end, cap=max_exports)
        elif sec_id == 8:
            start_function, _ = _uleb(data, body)
    result: JsonObject = {
        "version": version,
        "sections": sections,
        "imports": imports,
        "imports_count": len(imports),
        "imports_total": imports_total,
        "imports_truncated": imports_total > len(imports),
        "exports": exports,
        "exports_count": len(exports),
        "exports_total": exports_total,
        "exports_truncated": exports_total > len(exports),
    }
    if start_function is not None:
        result["start_function"] = start_function
    return result


def _parse_namemap(
    data: bytes, pos: int, end: int, *, needle: str
) -> tuple[list[JsonObject], bool]:
    """Parse a namemap (vec of {index, name}) from the function-names subsection.

    Filters by ``needle`` (substring, case-sensitive: wasm names are symbols)
    while scanning, and stops collecting at ``_MAX_NAMES_COLLECT`` (returning
    scan_capped True) so a hostile namemap cannot materialise without bound. The
    whole vector is still walked so an entry past the collect cap that matches
    the filter is not silently dropped from the count -- only from the list.
    """
    count, pos = _uleb(data, pos)
    collected: list[JsonObject] = []
    seen = 0
    capped = False
    while seen < count and pos < end:
        index, pos = _uleb(data, pos)
        name, pos = _name(data, pos)
        if pos > end:
            raise WasmParseError("name map entry overruns subsection")
        seen += 1
        if needle and needle not in name:
            continue
        if len(collected) >= _MAX_NAMES_COLLECT:
            capped = True
            break
        collected.append({"index": index, "name": name})
    return collected, capped


def _skip_leb(data: bytes, pos: int) -> int:
    """Advance past one LEB128 integer (the continuation scheme is sign-agnostic)."""
    read = 0
    while pos < len(data):
        byte = data[pos]
        pos += 1
        read += 1
        if not byte & 0x80:
            return pos
        if read >= _MAX_LEB_BYTES:
            raise WasmParseError("LEB128 integer too long")
    raise WasmParseError("truncated LEB128 integer")


def _skip_const_expr(data: bytes, pos: int, end: int) -> int:
    """Advance past a data segment's offset init-expr, up to and past its end (0x0b).

    Data offsets are constant expressions -- in practice a single i32/i64.const,
    a global.get, or a ref.* -- terminated by the end opcode. Only those forms
    are modelled; anything else raises so the caller can stop rather than
    misread the byte stream.
    """
    while pos < end:
        op = data[pos]
        pos += 1
        if op == 0x0B:  # end
            return pos
        if op in (0x41, 0x42):  # i32.const / i64.const: signed LEB operand
            pos = _skip_leb(data, pos)
        elif op == 0x43:  # f32.const: 4 raw bytes
            pos += 4
        elif op == 0x44:  # f64.const: 8 raw bytes
            pos += 8
        elif op in (0x23, 0xD2):  # global.get / ref.func: index LEB operand
            pos = _skip_leb(data, pos)
        elif op == 0xD0:  # ref.null: a reftype byte
            pos += 1
        else:
            raise WasmParseError(f"unsupported const-expr opcode {op:#x}")
    raise WasmParseError("const expr not terminated")


def _collect_runs(
    payload: bytes,
    base: int,
    pattern: re.Pattern[bytes],
    needle: str,
    results: list[JsonObject],
) -> bool:
    """Append printable runs from ``payload`` to ``results``; True when capped."""
    for match in pattern.finditer(payload):
        raw = match.group()
        text = raw.decode("ascii", "replace")
        if needle and needle not in text.lower():
            continue
        if len(results) >= _MAX_DATA_STRINGS_COLLECT:
            return True
        offset = base + match.start()
        if len(text) > _MAX_STRING_TEXT:
            results.append(
                {
                    "offset": offset,
                    "text": text[:_MAX_STRING_TEXT],
                    "size": len(raw),
                    "text_truncated": True,
                }
            )
        else:
            results.append({"offset": offset, "text": text, "size": len(raw)})
    return False


def parse_data_strings(
    data: bytes, *, min_length: int = 4, name_filter: str = ""
) -> tuple[list[JsonObject], bool, bool]:
    """Extract printable ASCII strings from the module's data section.

    Returns ``(strings, has_data_section, scan_capped)``. The data (id 11)
    section is where a wasm module's rodata lives -- the URLs, error messages,
    format strings and embedded symbols a triage pass greps for -- and this is
    the ``strings`` of that section: runs of printable ASCII (0x20-0x7e) at least
    ``min_length`` long, in scan order (ascending module offset). Each data
    segment is parsed so only its payload bytes are scanned (the segment's flags,
    offset init-expr and length prefix are skipped), which keeps a length byte
    that happens to be printable from being glued onto the front of the first
    string. When the module has no data section -- a module that ships no
    initialised memory -- has_data_section is False and the list is empty, which
    is the answer, not an error. Each row is ``{offset (module-absolute byte
    offset), text, size}`` plus text_truncated when a single run exceeded the
    text clip. ``name_filter`` keeps only runs whose text contains that substring
    (case-insensitive: data strings are prose and URLs, not symbols); total is
    then the match count. Collection stops at the ceiling (scan_capped True) so an
    all-data module cannot materialise without bound. A segment whose framing the
    parser cannot follow ends the scan best-effort with what was collected, rather
    than discarding every string over one unexpected byte.
    """
    length = min_length if isinstance(min_length, int) and not isinstance(min_length, bool) else 4
    length = max(1, min(length, _MIN_STRING_LEN_MAX))
    needle = name_filter.lower() if isinstance(name_filter, str) else ""
    pattern = re.compile(b"[\x20-\x7e]{%d,}" % length)
    results: list[JsonObject] = []
    has_data = False
    scan_capped = False
    for sec_id, body, end in _iter_sections(data):
        if sec_id != 11:
            continue
        has_data = True
        try:
            count, pos = _uleb(data, body)
            parsed = 0
            while parsed < count and pos < end:
                flags, pos = _uleb(data, pos)
                if flags == 0:  # active, memory 0: offset expr then bytes
                    pos = _skip_const_expr(data, pos, end)
                elif flags == 1:  # passive: bytes only
                    pass
                elif flags == 2:  # active, explicit memidx: memidx, expr, bytes
                    _memidx, pos = _uleb(data, pos)
                    pos = _skip_const_expr(data, pos, end)
                else:
                    # An encoding we do not model; stop rather than misread.
                    break
                nbytes, pos = _uleb(data, pos)
                payload_end = pos + nbytes
                if payload_end > end:
                    break
                if _collect_runs(data[pos:payload_end], pos, pattern, needle, results):
                    scan_capped = True
                    break
                pos = payload_end
                parsed += 1
        except WasmParseError:
            # Best-effort: keep the strings collected before the anomaly. The
            # module framing itself was already validated by _iter_sections; this
            # only guards the segment-internal walk.
            pass
        # The data section is unique in a module; no need to walk further.
        break
    return results, has_data, scan_capped


def parse_data_endpoints(
    data: bytes, *, include_paths: bool = True, name_filter: str = ""
) -> tuple[list[JsonObject], list[str], bool, bool, bool]:
    """Extract network endpoints (URLs, request paths) from the data section.

    Returns ``(endpoints, hosts, hosts_truncated, has_data_section, scan_capped)``.
    The endpoint companion to parse_data_strings(): it reuses that section walk to
    pull the printable runs of a module's rodata, then runs the *same* URL/path
    recogniser js.endpoints and apk.endpoints use over each run -- so a wasm
    module compiled from Rust/Go/C++ gives up the backends it calls (the fetch
    hosts, the api paths) without shelling out to wabt and grepping. Endpoints are
    deduplicated: each row is ``{value, kind (url|path), scheme, host, count
    (occurrences), first_offset (module-absolute byte offset of the earliest run
    it was seen in)}``, sorted by count then value. ``hosts`` is the distinct host
    set of the URL endpoints, capped (hosts_truncated when over). When the module
    has no data section, has_data_section is False and the list is empty -- the
    answer, not an error. ``name_filter`` keeps only endpoints whose value or host
    contains that substring (case-insensitive), applied before the host summary
    and paging so total is the match count. scan_capped is carried from the string
    walk or set when the distinct-endpoint ceiling is hit.
    """
    rows, has_data, scan_capped = parse_data_strings(data, min_length=1, name_filter="")
    aggregates: dict[str, JsonObject] = {}

    def add(value: str, kind: str, scheme: str, host: str, offset: int) -> bool:
        nonlocal scan_capped
        current = aggregates.get(value)
        if current is None:
            if len(aggregates) >= _MAX_DATA_ENDPOINTS_COLLECT:
                scan_capped = True
                return False
            aggregates[value] = {
                "value": value,
                "kind": kind,
                "scheme": scheme,
                "host": host,
                "count": 1,
                "first_offset": offset,
            }
        else:
            current["count"] = int(current["count"]) + 1
            if offset < int(current["first_offset"]):
                current["first_offset"] = offset
        return True

    stop = False
    for row in rows:
        text = str(row.get("text", ""))
        offset = int(row.get("offset", 0))
        for value, kind, scheme, host in iter_endpoint_matches(
            text, include_paths=include_paths
        ):
            if not add(value, kind, scheme, host, offset):
                stop = True
                break
        if stop:
            break

    needle = name_filter.strip().lower() if isinstance(name_filter, str) else ""
    endpoints = list(aggregates.values())
    if needle:
        endpoints = [
            e
            for e in endpoints
            if needle in str(e["value"]).lower() or needle in str(e["host"]).lower()
        ]
    endpoints.sort(key=lambda e: (-int(e["count"]), str(e["value"])))
    host_set = sorted({str(e["host"]) for e in endpoints if e["kind"] == "url" and e["host"]})
    hosts_truncated = len(host_set) > _MAX_DATA_HOSTS
    return endpoints, host_set[:_MAX_DATA_HOSTS], hosts_truncated, has_data, scan_capped


def parse_data_secrets(
    data: bytes, *, name_filter: str = "", include_generic: bool = False
) -> tuple[list[JsonObject], list[str], bool, bool]:
    """Detect embedded credentials in a module's data (rodata) section.

    Returns ``(secrets, detectors, has_data_section, scan_capped)``. The
    credential companion to parse_data_strings(): it reuses that section walk to
    pull the printable runs of a module's rodata, then runs the *same*
    high-precision detector table js.secrets and apk.secrets use over each run --
    so a wasm module compiled from Rust/Go/C++ that baked in an AWS/Google/GitHub
    key, a JWT or a PEM private-key header gives it up without shelling out to
    wabt and grepping. Findings are deduplicated by (detector, value): each row is
    ``{detector, value (the matched credential, clipped with value_truncated when
    long), count (occurrences), first_offset (module-absolute byte offset of the
    earliest run it was seen in)}``, sorted by detector then count then value.
    ``detectors`` is the distinct detector set present. When the module has no data
    section, has_data_section is False and the list is empty -- the answer, not an
    error. ``include_generic`` adds a whole-run high-entropy base64/hex catch-all
    for a run no specific detector claimed (off by default; it trades recall for
    precision). ``name_filter`` keeps only findings whose detector or value
    contains that substring (case-insensitive), applied before paging so total is
    the match count. scan_capped is carried from the string walk or set when the
    distinct-finding ceiling is hit.
    """
    rows, has_data, scan_capped = parse_data_strings(data, min_length=1, name_filter="")
    aggregates: dict[tuple[str, str], JsonObject] = {}

    def add(detector: str, value: str, offset: int) -> bool:
        nonlocal scan_capped
        key = (detector, value)
        current = aggregates.get(key)
        if current is None:
            if len(aggregates) >= _MAX_DATA_SECRETS_COLLECT:
                scan_capped = True
                return False
            row: JsonObject = {
                "detector": detector,
                "value": value[:_MAX_DATA_SECRET_VALUE],
                "count": 1,
                "first_offset": offset,
            }
            if len(value) > _MAX_DATA_SECRET_VALUE:
                row["value_truncated"] = True
            aggregates[key] = row
        else:
            current["count"] = int(current["count"]) + 1
            if offset < int(current["first_offset"]):
                current["first_offset"] = offset
        return True

    stop = False
    for row in rows:
        text = str(row.get("text", ""))
        offset = int(row.get("offset", 0))
        for detector, value in iter_secret_matches(text, include_generic=include_generic):
            if not add(detector, value, offset):
                stop = True
                break
        if stop:
            break

    needle = name_filter.strip().lower() if isinstance(name_filter, str) else ""
    secrets = list(aggregates.values())
    if needle:
        secrets = [
            s
            for s in secrets
            if needle in str(s["detector"]).lower() or needle in str(s["value"]).lower()
        ]
    secrets.sort(key=lambda s: (str(s["detector"]), -int(s["count"]), str(s["value"])))
    detectors = sorted({str(s["detector"]) for s in secrets})
    return secrets, detectors, has_data, scan_capped


def parse_function_names(
    data: bytes, *, name_filter: str = ""
) -> tuple[str, list[JsonObject], bool, bool]:
    """Decode the ``name`` custom section: module name and function-index names.

    Returns ``(module_name, entries, has_name_section, scan_capped)``. ``entries``
    are the function names ({index, name}) from subsection 1, filtered by
    ``name_filter``. When the module carries no ``name`` section -- the common
    case for a stripped release build -- has_name_section is False and entries is
    empty, which is itself the answer rather than an error. Only the module-name
    (0) and function-name (1) subsections are decoded; local/label/other
    subsections are skipped by their declared size.
    """
    needle = name_filter if isinstance(name_filter, str) else ""
    for sec_id, body, end in _iter_sections(data):
        if sec_id != 0:
            continue
        section_name, cursor = _name(data, body)
        if section_name != "name":
            continue
        module_name = ""
        entries: list[JsonObject] = []
        scan_capped = False
        pos = cursor
        while pos < end:
            sub_id = data[pos]
            pos += 1
            sub_size, pos = _uleb(data, pos)
            sub_end = pos + sub_size
            if sub_end > end:
                raise WasmParseError("name subsection overruns section")
            if sub_id == 0:  # module name
                with suppress(WasmParseError):
                    module_name, _ = _name(data, pos)
            elif sub_id == 1:  # function names
                found, scan_capped = _parse_namemap(data, pos, sub_end, needle=needle)
                entries.extend(found)
            pos = sub_end
        return module_name, entries, True, scan_capped
    return "", [], False, False


def _read_valtypes(data: bytes, pos: int, end: int) -> tuple[list[str], int]:
    """Read a vec(valtype), returning (names, next_pos). Each valtype is one byte."""
    count, pos = _uleb(data, pos)
    names: list[str] = []
    read = 0
    while read < count:
        if pos >= end:
            raise WasmParseError("valtype vector overruns section")
        if len(names) < _MAX_TYPE_VEC:
            byte = data[pos]
            names.append(_VALTYPES.get(byte, f"{byte:#x}"))
        pos += 1
        read += 1
    return names, pos


def _parse_types(data: bytes, pos: int, end: int) -> list[JsonObject]:
    """Parse the type section: a vec of function types ``{params, results}``.

    Best-effort: a form we do not model (a GC struct/array type, or corruption)
    ends the walk with the function types decoded so far, so the common low type
    indices still resolve to signatures rather than the whole section being lost.
    """
    count, pos = _uleb(data, pos)
    types: list[JsonObject] = []
    parsed = 0
    while parsed < count and pos < end and len(types) < _MAX_TYPES_COLLECT:
        try:
            if pos >= end:
                break
            tag = data[pos]
            pos += 1
            if tag != 0x60:  # only plain function types are modelled
                break
            params, pos = _read_valtypes(data, pos, end)
            results, pos = _read_valtypes(data, pos, end)
        except WasmParseError:
            break
        if pos > end:
            break
        types.append({"params": params, "results": results})
        parsed += 1
    return types


def _collect_func_imports(
    data: bytes, pos: int, end: int
) -> tuple[list[JsonObject], int, bool]:
    """Return (function imports collected, total func-import count, capped).

    Only kind==func imports are returned (each ``{module, field, type_index}``),
    but every import is walked so the returned count is the number of function
    imports -- which is where the module's own functions start numbering.
    """
    count, pos = _uleb(data, pos)
    funcs: list[JsonObject] = []
    func_count = 0
    capped = False
    parsed = 0
    while parsed < count and pos < end:
        try:
            module, pos = _name(data, pos)
            field, pos = _name(data, pos)
            _need(pos, 1, end, "import kind")
            kind = data[pos]
            pos += 1
            if kind == 0:  # func
                type_index, pos = _uleb(data, pos)
                if len(funcs) >= _MAX_FUNCTIONS_COLLECT:
                    capped = True
                else:
                    funcs.append(
                        {"module": module, "field": field, "type_index": type_index}
                    )
                func_count += 1
            elif kind == 1:  # table
                _need(pos, 1, end, "table reftype")
                pos = _skip_limits(data, pos + 1)
            elif kind == 2:  # memory
                pos = _skip_limits(data, pos)
            elif kind == 3:  # global
                _need(pos, 2, end, "global type")
                pos += 2
            else:
                break
        except WasmParseError:
            break
        if pos > end:
            break
        parsed += 1
    return funcs, func_count, capped


def _parse_func_section(data: bytes, pos: int, end: int) -> tuple[list[int], int, bool]:
    """Parse the function section: a vec of type indices, one per local function.

    Returns (type indices collected, declared count, capped).
    """
    count, pos = _uleb(data, pos)
    out: list[int] = []
    capped = False
    parsed = 0
    while parsed < count and pos < end:
        try:
            type_index, pos = _uleb(data, pos)
        except WasmParseError:
            break
        if len(out) >= _MAX_FUNCTIONS_COLLECT:
            capped = True
        else:
            out.append(type_index)
        parsed += 1
    return out, count, capped


def _parse_code_sizes(data: bytes, pos: int, end: int) -> tuple[list[int], bool]:
    """Parse the code section, returning (per-function body byte sizes, capped).

    Only each entry's declared body size is read; the body itself is skipped, so
    a huge code section costs a size read per function, not a decode.
    """
    count, pos = _uleb(data, pos)
    sizes: list[int] = []
    capped = False
    parsed = 0
    while parsed < count and pos < end:
        try:
            body_size, pos = _uleb(data, pos)
        except WasmParseError:
            break
        if pos + body_size > end:
            break
        if len(sizes) >= _MAX_FUNCTIONS_COLLECT:
            capped = True
        else:
            sizes.append(body_size)
        pos += body_size
        parsed += 1
    return sizes, capped


def _func_exports_by_index(data: bytes, pos: int, end: int) -> dict[int, list[str]]:
    """Map function index -> exported name(s) from the export section (kind func)."""
    count, pos = _uleb(data, pos)
    out: dict[int, list[str]] = {}
    parsed = 0
    while parsed < count and pos < end and len(out) < _MAX_FUNCTIONS_COLLECT:
        try:
            name, pos = _name(data, pos)
            _need(pos, 1, end, "export kind")
            kind = data[pos]
            pos += 1
            index, pos = _uleb(data, pos)
        except WasmParseError:
            break
        if pos > end:
            break
        if kind == 0:
            out.setdefault(index, []).append(name)
        parsed += 1
    return out


def _signature(type_index: int | None, types: list[JsonObject]) -> tuple[list[str], list[str], str]:
    """Resolve a type index to (params, results, readable) against the type list."""
    if type_index is None or type_index < 0 or type_index >= len(types):
        return [], [], ""
    entry = types[type_index]
    params = [str(p) for p in entry.get("params", [])]
    results = [str(r) for r in entry.get("results", [])]
    readable = f"({', '.join(params)}) -> ({', '.join(results)})"
    return params, results, readable


def parse_functions(
    data: bytes, *, include_imports: bool = True, name_filter: str = ""
) -> tuple[list[JsonObject], JsonObject, bool]:
    """Build the module's function table: index -> name, signature, size, origin.

    Returns ``(functions, summary, scan_capped)``. This is the ``functions`` of a
    wasm module -- the inventory r2.functions / ghidra.functions give a native
    binary, which wasm.summary (imports/exports only) and wasm.names (names only)
    each show a slice of. It joins four sections the other wasm tools skip: the
    type section (each function's signature), the import section (imported
    functions, which occupy the low function indices), the function section (the
    module's own functions and their type), and the code section (each local
    function's body byte size), then layers the export names and the ``name``
    section over the resulting function-index space.

    Each row is ``{index (the module's function index -- what a call operand and
    an export index refer to), name (from the name section, else the export name,
    else ""), origin ("import" | "local"), type_index, params, results (valtype
    name lists), signature (readable, e.g. "(i32, i32) -> (i32)"), exported}``,
    plus ``module``/``field`` for an import, ``export_name`` when exported, and
    ``code_size`` for a local function when the code section is present. Rows are
    in function-index order (imports first, then locals). ``summary`` carries the
    module totals ``{imported_total, local_total, type_count, has_type_section,
    has_function_section, has_code_section}`` (pre-filter, so the module's true
    size is known regardless of the filter). ``include_imports`` false drops the
    imported functions to leave only the module's own code. ``name_filter`` keeps
    rows whose name, export name or ``module.field`` contains that substring
    (case-sensitive: wasm names are symbols). Every section decode is best-effort
    and bounded, so a malformed or hostile section degrades to a partial table
    (scan_capped True when a collect ceiling was hit) rather than raising.
    """
    types: list[JsonObject] = []
    func_imports: list[JsonObject] = []
    func_import_total = 0
    local_type_indices: list[int] = []
    local_total = 0
    code_sizes: list[int] = []
    exports_by_index: dict[int, list[str]] = {}
    has_type = has_function = has_code = False
    scan_capped = False

    for sec_id, body, end in _iter_sections(data):
        if sec_id == 1:
            has_type = True
            with suppress(WasmParseError):
                types = _parse_types(data, body, end)
        elif sec_id == 2:
            with suppress(WasmParseError):
                func_imports, func_import_total, capped = _collect_func_imports(data, body, end)
                scan_capped = scan_capped or capped
        elif sec_id == 3:
            has_function = True
            with suppress(WasmParseError):
                local_type_indices, local_total, capped = _parse_func_section(data, body, end)
                scan_capped = scan_capped or capped
        elif sec_id == 7:
            with suppress(WasmParseError):
                exports_by_index = _func_exports_by_index(data, body, end)
        elif sec_id == 10:
            has_code = True
            with suppress(WasmParseError):
                code_sizes, capped = _parse_code_sizes(data, body, end)
                scan_capped = scan_capped or capped

    _module_name, name_entries, _has_names, names_capped = parse_function_names(data)
    scan_capped = scan_capped or names_capped
    name_map = {int(e["index"]): str(e["name"]) for e in name_entries}

    def _row(index: int, origin: str, type_index: int | None) -> JsonObject:
        params, results, readable = _signature(type_index, types)
        exported = exports_by_index.get(index)
        name = name_map.get(index, "")
        if not name and exported:
            name = exported[0]
        row: JsonObject = {
            "index": index,
            "name": name,
            "origin": origin,
            "type_index": type_index,
            "params": params,
            "results": results,
            "signature": readable,
            "exported": bool(exported),
        }
        if exported:
            row["export_name"] = exported[0]
        return row

    rows: list[JsonObject] = []
    for idx, imp in enumerate(func_imports):
        row = _row(idx, "import", imp.get("type_index"))
        row["module"] = imp["module"]
        row["field"] = imp["field"]
        rows.append(row)
    base = func_import_total
    for offset, type_index in enumerate(local_type_indices):
        row = _row(base + offset, "local", type_index)
        if offset < len(code_sizes):
            row["code_size"] = code_sizes[offset]
        rows.append(row)

    if not include_imports:
        rows = [r for r in rows if r["origin"] == "local"]

    if name_filter:
        def _keep(row: JsonObject) -> bool:
            hay = [str(row.get("name", "")), str(row.get("export_name", ""))]
            if row["origin"] == "import":
                hay.append(f'{row.get("module", "")}.{row.get("field", "")}')
            return any(name_filter in text for text in hay)

        rows = [r for r in rows if _keep(r)]

    summary: JsonObject = {
        "imported_total": func_import_total,
        "local_total": local_total,
        "type_count": len(types),
        "has_type_section": has_type,
        "has_function_section": has_function,
        "has_code_section": has_code,
    }
    return rows, summary, scan_capped
