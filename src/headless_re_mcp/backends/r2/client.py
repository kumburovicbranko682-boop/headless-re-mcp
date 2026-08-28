from __future__ import annotations

import bisect
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.common.bounded_run import TimedOut, run_bounded
from headless_re_mcp.backends.r2.mapping import (
    _MAX_ITEMS,
    _item_va,
    address_dict,
    enrich_r2_payload,
    parse_r2_arrays,
    parse_r2_json,
    pe_preferred_base,
)

JsonObject = dict[str, Any]
_MAX_OUTPUT = 1_000_000
# A single r2.read window. Enough for a data blob, a jump table, or a chunk of
# an embedded key/certificate, while bounding the pxj int-array output (each
# byte costs ~4 chars of JSON, so 64 KiB stays well under _MAX_OUTPUT).
_MAX_READ_BYTES = 64 * 1024
# The longest byte pattern r2.search accepts (a magic, a crypto constant, a
# marker): long enough for any realistic signature, short enough that the
# whitelisted /xj command stays small.
_MAX_SEARCH_BYTES = 256
# Cap how many hits r2 itself emits, so a 2-byte pattern in a large image cannot
# produce a JSON blob that overruns _MAX_OUTPUT and gets truncated mid-array.
# Kept equal to mapping._MAX_ITEMS (4096): r2 stops at the same ceiling the
# enrich step would trim to, so the truncation disclosure stays honest.
_SEARCH_MAXHITS_COMMAND = "e search.maxhits=4096"
# r2.callgraph edge caps. A hot leaf (an allocator, a logging helper) can carry
# thousands of inbound call sites, so the edge list pages rather than
# hard-truncates; the collect ceiling only bounds a pathological fan-in from
# building an unbounded list before paging.
_MAX_CALLGRAPH_COLLECT = 20_000
_MAX_CALLGRAPH_PAGE = 1000
_ALLOWED = frozenset(
    {
        "i",
        "ii",
        "iI",
        "is",
        "il",
        "ilj",
        "ie",
        "aflj",
        "izj",
        "izzj",
        "iij",
        "iEj",
        "iSj",
        "isj",
        "iej",
        "irj",
        "pdj",
        "axj",
        "aa",
        _SEARCH_MAXHITS_COMMAND,
    }
)
_PDJ_COMMAND = re.compile(r"pdj ([1-9][0-9]*) @ (?:0x[0-9a-fA-F]+|[0-9]+)\Z")
# pdfj @ addr: disassemble the whole function at addr (respects basic-block and
# jump boundaries, resolves call targets), unlike the linear pdj window.
_PDFJ_COMMAND = re.compile(r"pdfj @ (?:0x[0-9a-fA-F]+|[0-9]+)\Z")
# pxj <n> @ addr: read n raw bytes at a virtual address as a JSON int array.
_PXJ_COMMAND = re.compile(r"pxj ([1-9][0-9]*) @ (?:0x[0-9a-fA-F]+|[0-9]+)\Z")
# /xj <hexpairs>: search the mapped bytes for an exact pattern. Even-length hex
# only -- r2.search builds the pattern from bytes, so the command can never
# carry anything but whole bytes (and thus cannot inject r2 command syntax).
_XJ_COMMAND = re.compile(r"/xj (?:[0-9a-f]{2})+\Z")
# axj (whole DB), axtj (refs to), axfj (refs from), each seeked with ``@ addr``.
# r2 6.x makes ``axj @ addr`` return nothing, so xrefs queries axtj/axfj, which
# honour the seek on every version; axj stays whitelisted for the enrich filter
# path and older builds.
_AXREF_COMMAND = re.compile(r"ax[tf]?j @ (?:0x[0-9a-fA-F]+|[0-9]+)\Z")
# afij @ addr: JSON info for the function containing addr ([] when none).
# fdj @ addr: JSON for the flag (symbol/string) nearest at-or-before addr.
# r2.resolve runs both to answer "what is at this address" -- the reverse of the
# address-emitting readers (xrefs/relocations/search/read/disasm).
_AFIJ_COMMAND = re.compile(r"afij @ (?:0x[0-9a-fA-F]+|[0-9]+)\Z")
_FDJ_COMMAND = re.compile(r"fdj @ (?:0x[0-9a-fA-F]+|[0-9]+)\Z")
# afbj @ addr: the basic blocks of the function containing addr (start, size,
# jump/fail successors, instruction count). r2.cfg runs it beside afij to build
# a function's control-flow graph -- nodes and branch edges, the native twin of
# static.cfg.
_AFBJ_COMMAND = re.compile(r"afbj @ (?:0x[0-9a-fA-F]+|[0-9]+)\Z")


def _is_invalid_op(item: JsonObject) -> bool:
    """Whether an r2 disasm row is an undecodable byte rather than an opcode.

    radare2 tags these ``type: "invalid"`` on 5.x but ``type: "ill"`` (with
    ``opcode: "invalid"``) on 6.x. Matching only the old spelling made
    ``invalid_count`` read 0 for a header or a data hole on a current r2, the
    exact "this address is not code" signal the field exists to give.
    """
    if str(item.get("type", "")).strip().lower() in {"invalid", "ill"}:
        return True
    return str(item.get("opcode", "")).strip().lower() == "invalid"


class R2Error(RuntimeError):
    def __init__(self, code: str, message: str, **details: object) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


def _require_allowed_command(command: str) -> None:
    if command in _ALLOWED:
        return
    pdj = _PDJ_COMMAND.fullmatch(command)
    if pdj is not None and int(pdj.group(1)) <= 512:
        return
    if _PDFJ_COMMAND.fullmatch(command) is not None:
        return
    pxj = _PXJ_COMMAND.fullmatch(command)
    if pxj is not None and int(pxj.group(1)) <= _MAX_READ_BYTES:
        return
    if _XJ_COMMAND.fullmatch(command) is not None:
        return
    if _AXREF_COMMAND.fullmatch(command) is not None:
        return
    if _AFIJ_COMMAND.fullmatch(command) is not None:
        return
    if _FDJ_COMMAND.fullmatch(command) is not None:
        return
    if _AFBJ_COMMAND.fullmatch(command) is not None:
        return
    raise R2Error("invalid_params", "r2 command not whitelisted", command=command)


def _decode_r2_values(raw: str) -> list[Any]:
    """Every top-level JSON value in an r2 stream, arrays and objects alike.

    ``parse_r2_json`` returns only the first value and ``parse_r2_arrays`` only
    the arrays; ``r2.resolve`` runs two commands that print an array (``afij``)
    then an object (``fdj``), so it needs both. Decodes at each ``[``/``{`` and
    jumps past the value's inner brackets, so an ``str.[...]`` flag name or an
    ``[x] Analyze`` banner in between is stepped over rather than mis-parsed.
    """
    text = raw or ""
    decoder = json.JSONDecoder()
    values: list[Any] = []
    index = 0
    length = len(text)
    while index < length:
        if text[index] not in "[{":
            index += 1
            continue
        try:
            value, end = decoder.raw_decode(text, index)
        except json.JSONDecodeError:
            index += 1
            continue
        values.append(value)
        index = end
    return values


def _resolve_function(
    afij_val: Any,
    address: int,
    *,
    module: str,
    image_base: int | None,
    architecture: Any,
) -> JsonObject | None:
    """The function containing ``address`` from an ``afij`` array, or None.

    afij prints a one-element array for the function whose bounds contain the
    address and an empty array when the address is not inside any analysed
    function; the empty case is a null function, not an error.
    """
    if not isinstance(afij_val, list) or not afij_val:
        return None
    entry = afij_val[0]
    if not isinstance(entry, dict):
        return None
    # r2 5.x names the function start ``offset``; r2 6.x renamed it ``addr``.
    start = _item_va(entry, ("offset", "addr", "vaddr"))
    func: JsonObject = {"name": entry.get("name")}
    if isinstance(entry.get("size"), int):
        func["size"] = entry["size"]
    if isinstance(entry.get("signature"), str) and entry["signature"]:
        func["signature"] = entry["signature"]
    if isinstance(entry.get("type"), str) and entry["type"]:
        func["type"] = entry["type"]
    if start is not None:
        func["addr"] = start
        func["delta"] = address - start
        mapped = address_dict(
            start, module=module, image_base=image_base, architecture=architecture
        )
        if mapped is not None:
            func["address"] = mapped
    return func


def _resolve_flag(
    fdj_val: Any,
    address: int,
    *,
    module: str,
    image_base: int | None,
    architecture: Any,
) -> JsonObject | None:
    """The nearest flag at-or-before ``address`` from an ``fdj`` object, or None.

    fdj names the flag (a symbol, import thunk, or ``str.`` literal) nearest at
    or before the address. Its ``offset`` is that flag's own address, present
    when the flag precedes the queried address and omitted when the flag sits
    exactly on it -- so a missing offset means delta 0. An empty object (no
    ``name``) means the image has no flags to resolve against, hence None.
    """
    if not isinstance(fdj_val, dict) or not fdj_val.get("name"):
        return None
    flag: JsonObject = {"name": str(fdj_val.get("name"))}
    realname = fdj_val.get("realname")
    if isinstance(realname, str) and realname:
        flag["realname"] = realname
    flag_va = _item_va(fdj_val, ("offset", "addr", "vaddr"))
    if flag_va is not None:
        flag["addr"] = flag_va
        flag["delta"] = address - flag_va
        mapped = address_dict(
            flag_va, module=module, image_base=image_base, architecture=architecture
        )
        if mapped is not None:
            flag["address"] = mapped
    else:
        flag["delta"] = 0
    return flag


def _switch_targets(switch_op: Any) -> list[tuple[int, str]]:
    """Case (and default) targets of a jump table, from a block's ``switch_op``.

    r2 tags a jump-table block with ``switch_op`` carrying the table's cases; the
    plain ``jump``/``fail`` pair cannot express a fan-out, so without this a
    ``switch`` on many values would lose every arm but one. The structure drifts
    across versions, so read each case's target under any of the keys r2 has
    used and skip anything unshaped rather than guess.
    """
    if not isinstance(switch_op, dict):
        return []
    out: list[tuple[int, str]] = []
    cases = switch_op.get("cases")
    if isinstance(cases, list):
        for case in cases:
            if not isinstance(case, dict):
                continue
            dst = _item_va(case, ("jump", "addr", "offset"))
            if dst is not None:
                out.append((dst, "switch"))
    default = _item_va(switch_op, ("def", "default"))
    if default is not None:
        out.append((default, "switch_default"))
    return out


class R2Client:
    def __init__(self, executable: Path | None = None) -> None:
        self.executable = executable or _discover()

    @property
    def available(self) -> bool:
        return self.executable is not None and self.executable.is_file()

    def open(self, binary: Path, *, timeout: float = 30.0) -> JsonObject:
        """Validate that r2 can open ``binary`` (one-shot; no persistent pipe)."""
        if not binary.is_file():
            raise R2Error("not_found", "binary not found", path=str(binary))
        data = self.run(binary, ["i"], timeout=timeout)
        return {
            "opened": True,
            "binary": str(binary),
            "info": data.get("raw", "")[:8000],
            "note": "r2.open is one-shot validation; subsequent tools reopen the binary",
        }

    def disasm(
        self,
        binary: Path,
        address: int,
        *,
        count: int = 32,
        timeout: float = 30.0,
    ) -> JsonObject:
        if type(address) is not int or address < 0:
            raise R2Error("invalid_params", "address must be a non-negative int")
        if type(count) is not int or not 1 <= count <= 512:
            raise R2Error("invalid_params", "count must be 1..512")
        cmd = f"pdj {count} @ {address}"
        data = self.run(binary, ["aa", cmd], timeout=timeout)
        data = dict(data)
        data["address"] = address
        data["count"] = count
        enriched = enrich_r2_payload(data, binary=binary)
        # Point pdj at data, padding, or unmapped memory and r2 still returns a
        # row per byte -- each tagged type "invalid" with no opcode. Structurally
        # that is indistinguishable from a decoded run, so an agent that only
        # reads count/items would treat header bytes as instructions. Count the
        # undecodable rows out loud so "this address is not code" is legible
        # without walking every item.
        items = enriched.get("items")
        if isinstance(items, list):
            enriched["invalid_count"] = sum(
                1 for item in items if isinstance(item, dict) and _is_invalid_op(item)
            )
        return enriched

    def xrefs(
        self,
        binary: Path,
        address: int,
        *,
        timeout: float = 30.0,
    ) -> JsonObject:
        if type(address) is not int or address < 0:
            raise R2Error("invalid_params", "address must be a non-negative int")
        # "References to and from address." The old single ``axj @ addr`` listed
        # the whole database and ignored the seek on every version, and on r2 6.x
        # it returns nothing at all -- so xrefs silently went empty on a current
        # r2. ``axtj``/``axfj`` are seeked by r2 itself on both 5.x and 6.x: axtj
        # yields the rows that reference `address` (it is their target), axfj the
        # rows `address` references (it is their origin). Query both in one
        # analysis pass and normalise each into a {from, to} pair so the endpoint
        # the caller did not name is filled with the address they asked about.
        to_cmd = f"axtj @ {address}"
        from_cmd = f"axfj @ {address}"
        data = self.run(binary, ["aa", to_cmd, from_cmd], timeout=timeout)
        arrays = parse_r2_arrays(str(data.get("raw") or ""))
        to_rows = arrays[0] if len(arrays) >= 1 else []
        from_rows = arrays[1] if len(arrays) >= 2 else []
        merged: list[JsonObject] = []
        for row in to_rows:
            if not isinstance(row, dict):
                continue
            origin = _item_va(row, ("from", "fromaddr", "addr"))
            merged.append({**row, "from": origin, "to": address, "direction": "to"})
        for row in from_rows:
            if not isinstance(row, dict):
                continue
            target = _item_va(row, ("to", "toaddr", "addr"))
            merged.append({**row, "from": address, "to": target, "direction": "from"})
        payload: JsonObject = {
            "raw": json.dumps(merged),
            "commands": ["aa", to_cmd, from_cmd],
            "address": address,
        }
        return enrich_r2_payload(payload, binary=binary)

    def read_bytes(
        self,
        binary: Path,
        address: int,
        *,
        size: int = 64,
        timeout: float = 30.0,
    ) -> JsonObject:
        """Read ``size`` raw bytes at virtual address ``address`` from the image.

        ``r2.disasm`` decodes an address as code; this reads it as data. A data
        xref lands on a global, a jump table, or an embedded key/blob that has no
        opcodes -- point ``pdj`` there and every byte comes back as an
        ``invalid`` row, so only the raw bytes carry the content. ``pxj`` returns
        those bytes as a JSON int array (no analysis pass needed), which this
        collapses to a hex string. A short read (fewer bytes than asked) means
        the window ran off the end of the mapped region; it is disclosed rather
        than silently padded so a partial blob is not read as the whole thing.
        """
        if type(address) is not int or address < 0:
            raise R2Error("invalid_params", "address must be a non-negative int")
        if type(size) is not int or not 1 <= size <= _MAX_READ_BYTES:
            raise R2Error("invalid_params", f"size must be 1..{_MAX_READ_BYTES}")
        cmd = f"pxj {size} @ {address}"
        # pxj reads the mapped bytes directly, so skip the ``aa`` analysis the
        # code-facing tools run -- it would only slow a plain byte read.
        data = self.run(binary, [cmd], timeout=timeout)
        parsed = parse_r2_json(str(data.get("raw") or ""))
        values = parsed if isinstance(parsed, list) else []
        blob = bytes(int(v) & 0xFF for v in values if isinstance(v, int))
        arch, image_base = pe_preferred_base(binary)
        result: JsonObject = {
            "commands": [cmd],
            "module": binary.name,
            "size": size,
            "encoding": "hex",
            "data": blob.hex(),
            "count": len(blob),
            "parsed": parsed is not None,
            "address_va": address,
        }
        if image_base is not None:
            result["image_base"] = image_base
        if arch is not None:
            result["architecture"] = arch.value
        mapped = address_dict(
            address, module=binary.name, image_base=image_base, architecture=arch
        )
        if mapped is not None:
            result["address"] = mapped
        if len(blob) < size:
            result["short_read"] = True
        return result

    def search(
        self,
        binary: Path,
        query: str,
        *,
        kind: str = "text",
        timeout: float = 30.0,
    ) -> JsonObject:
        """Find every occurrence of an exact byte pattern in the mapped image.

        ``r2.strings`` lists the strings r2 auto-detected, but finds nothing you
        name that it did not: a file magic, a crypto constant, a marker r2 did
        not classify as a string, a non-printable byte pattern. This searches the
        mapped bytes for an exact pattern with ``/xj`` and maps each hit to an
        address. A ``text`` query is UTF-8 encoded to a byte pattern; a ``hex``
        query is the raw pattern as hex pairs (spaces and a ``0x`` prefix are
        tolerated). Either way the command only ever carries hex digits, so a
        query can never inject r2 command syntax. r2's own hit count is capped so
        a short pattern in a large image cannot flood the output.
        """
        if kind not in {"text", "hex"}:
            raise R2Error("invalid_params", "kind must be 'text' or 'hex'")
        if not isinstance(query, str) or query == "":
            raise R2Error("invalid_params", "query is required")
        if kind == "text":
            pattern = query.encode("utf-8")
        else:
            cleaned = query.strip().lower().replace(" ", "")
            if cleaned.startswith("0x"):
                cleaned = cleaned[2:]
            try:
                pattern = bytes.fromhex(cleaned)
            except ValueError as exc:
                raise R2Error(
                    "invalid_params", "hex query must be whole bytes (even-length hex)"
                ) from exc
        if not 1 <= len(pattern) <= _MAX_SEARCH_BYTES:
            raise R2Error(
                "invalid_params", f"pattern must be 1..{_MAX_SEARCH_BYTES} bytes"
            )
        hexpairs = pattern.hex()
        cmd = f"/xj {hexpairs}"
        # ``e search.maxhits=...`` caps r2's own output; ``/xj`` needs no analysis
        # pass, so no ``aa``. run() enriches the JSON array into address-mapped
        # items (r2 6.x names the hit offset ``addr``, which the mapping reads).
        data = self.run(binary, [_SEARCH_MAXHITS_COMMAND, cmd], timeout=timeout)
        # Echo what was searched, so an empty result reads as "pattern absent"
        # (not "bad query"), and the byte pattern a text query encoded to is
        # visible for a follow-up hex search or an r2.read at a hit.
        data["query"] = query
        data["kind"] = kind
        data["pattern_hex"] = hexpairs
        data["pattern_len"] = len(pattern)
        return data

    def disasm_function(
        self,
        binary: Path,
        address: int,
        *,
        timeout: float = 30.0,
    ) -> JsonObject:
        """Disassemble the whole function at ``address`` as radare2 analyses it.

        Where ``r2.disasm`` reads a fixed count of instructions linearly from an
        address, this disassembles a *function*: r2's analysis bounds it, so the
        listing stops where the function ends and each op's ``disasm`` names the
        call targets and data it references (``call sym.foo``, ``lea ... str.bar``)
        rather than raw operands. It is the r2 line's function view, the seam from
        ``r2.functions`` (pick a function) to reading what it actually does.
        Runs ``pdfj``. An address that is not inside a known function comes back
        as a clean empty op list, not an error.
        """
        if type(address) is not int or address < 0:
            raise R2Error("invalid_params", "address must be a non-negative int")
        cmd = f"pdfj @ {address}"
        # pdfj needs the analysis pass to know function boundaries, so run ``aa``
        # first like r2.functions/r2.disasm do.
        data = self.run(binary, ["aa", cmd], timeout=timeout)
        parsed = parse_r2_json(str(data.get("raw") or ""))
        arch, image_base = pe_preferred_base(binary)
        result: JsonObject = {
            "commands": ["aa", cmd],
            "module": binary.name,
            "address_va": address,
            "parsed": isinstance(parsed, dict),
        }
        if image_base is not None:
            result["image_base"] = image_base
        if arch is not None:
            result["architecture"] = arch.value
        if not isinstance(parsed, dict):
            # pdfj at a non-function address prints nothing; report an empty
            # function rather than raising, matching how r2.xrefs answers an
            # address that references nothing.
            result["ops"] = []
            result["count"] = 0
            result["invalid_count"] = 0
            return result
        func_va = parsed.get("addr")
        if isinstance(func_va, int):
            mapped = address_dict(
                func_va, module=binary.name, image_base=image_base, architecture=arch
            )
            if mapped is not None:
                result["address"] = mapped
        result["name"] = parsed.get("name")
        if isinstance(parsed.get("size"), int):
            result["size"] = parsed["size"]
        ops_in = parsed.get("ops")
        ops_in = ops_in if isinstance(ops_in, list) else []
        available = len(ops_in)
        ops_out: list[JsonObject] = []
        invalid = 0
        # Keep the fields an agent reads (address, raw opcode, the symbol-resolved
        # disasm text, the bytes, type, size) and drop r2's per-op internals
        # (esil, family, type_num, reloc, ...) so the function listing stays
        # legible and the envelope bounded.
        for op in ops_in[:_MAX_ITEMS]:
            if not isinstance(op, dict):
                continue
            va = _item_va(op, ("addr", "offset", "vaddr"))
            item: JsonObject = {
                "addr": va,
                "opcode": op.get("opcode"),
                "disasm": op.get("disasm"),
                "bytes": op.get("bytes"),
                "type": op.get("type"),
                "size": op.get("size"),
            }
            mapped = address_dict(
                va, module=binary.name, image_base=image_base, architecture=arch
            )
            if mapped is not None:
                item["address"] = mapped
            if _is_invalid_op(op):
                invalid += 1
            ops_out.append(item)
        result["ops"] = ops_out
        result["count"] = len(ops_out)
        result["invalid_count"] = invalid
        if available > _MAX_ITEMS:
            # A function longer than the cap is trimmed; say so, like the other
            # r2 readers, so "these are all the ops" is never a wrong read.
            result["ops_truncated"] = True
            result["ops_total"] = available
            result["ops_limit"] = _MAX_ITEMS
        return result

    def resolve(
        self,
        binary: Path,
        address: int,
        *,
        timeout: float = 30.0,
    ) -> JsonObject:
        """Map a raw address to its containing function and nearest named symbol.

        The reverse of every other r2 reader. ``r2.xrefs``, ``r2.relocations``,
        ``r2.search``, ``r2.read`` and the disassemblers all *emit* addresses;
        nothing turned one back into "what lives here". This does: given an
        address it reports the function it falls inside (with the offset from the
        function start) and the nearest flag at-or-before it (a symbol, an import
        thunk, an ``str.`` literal), so a hit from a search or an xref target that
        r2 never turned into a function still gets a name and a delta -- the
        equivalent of reading ``main + 16`` or ``str.foo + 4`` off a listing.

        Runs ``afij @ addr`` (the function whose bounds contain the address; an
        empty list, hence a null ``function``, when the address is not inside any
        analysed function) and ``fdj @ addr`` (the flag nearest at-or-before it).
        Both ``function`` and ``flag`` report ``delta`` = the queried address
        minus that entity's start, so 0 means the address sits exactly on it.
        """
        if type(address) is not int or address < 0:
            raise R2Error("invalid_params", "address must be a non-negative int")
        afij = f"afij @ {address}"
        fdj = f"fdj @ {address}"
        # afij needs the analysis pass to know function boundaries; fdj reads the
        # flag space aa populates. One ``aa`` covers both.
        data = self.run(binary, ["aa", afij, fdj], timeout=timeout)
        raw = str(data.get("raw") or "")
        # afij prints a JSON array, fdj a JSON object, back to back in one stream;
        # decode both in emission order (parse_r2_json would return only the
        # first, parse_r2_arrays would miss the object).
        values = _decode_r2_values(raw)
        afij_val = next((v for v in values if isinstance(v, list)), None)
        fdj_val = next((v for v in values if isinstance(v, dict)), None)
        arch, image_base = pe_preferred_base(binary)
        result: JsonObject = {
            "commands": ["aa", afij, fdj],
            "module": binary.name,
            "address_va": address,
            "parsed": bool(values),
        }
        if image_base is not None:
            result["image_base"] = image_base
        if arch is not None:
            result["architecture"] = arch.value
        mapped = address_dict(
            address, module=binary.name, image_base=image_base, architecture=arch
        )
        if mapped is not None:
            result["address"] = mapped
        result["function"] = _resolve_function(
            afij_val, address, module=binary.name, image_base=image_base, architecture=arch
        )
        result["flag"] = _resolve_flag(
            fdj_val, address, module=binary.name, image_base=image_base, architecture=arch
        )
        return result

    def callgraph(
        self,
        binary: Path,
        address: int,
        *,
        direction: str = "both",
        offset: int = 0,
        limit: int = 100,
        timeout: float = 30.0,
    ) -> JsonObject:
        """The direct callees and callers of the function at ``address``.

        Where ``r2.xrefs`` answers one address and ``r2.disasm_function`` reads a
        whole body op by op, this collapses a function to its call-graph
        neighbours: the functions it calls (callees) and the functions that call
        it (callers), each resolved to a name and a call-site address rather than
        left as raw pointers. It is the native analogue of ``apk.method_xrefs``
        -- the seam from ``r2.functions`` (pick a function) or ``r2.resolve`` (map
        a hit to its function) to "who reaches this, and what does it reach".

        Runs ``aa`` then ``aflj`` once and builds the graph from r2's own
        per-function ``callrefs`` (outbound) and ``codexrefs`` (inbound), so a
        single pass answers both directions and every edge endpoint is resolved
        to the function that contains it (an import thunk such as
        ``sym.imp.malloc`` included). ``address`` may sit anywhere inside a
        function, not only on its entry.
        """
        if type(address) is not int or address < 0:
            raise R2Error("invalid_params", "address must be a non-negative int")
        if direction not in ("callees", "callers", "both"):
            raise R2Error(
                "invalid_params",
                "direction must be callees, callers or both",
                direction=direction,
            )
        data = self.run(binary, ["aa", "aflj"], timeout=timeout)
        arrays = parse_r2_arrays(str(data.get("raw") or ""))
        funcs = arrays[0] if arrays else []
        arch, image_base = pe_preferred_base(binary)

        # Index every function by its start so a call target/source address can
        # be named. r2 5.x keys the start under ``offset``, 6.x under ``addr``;
        # read either. ``spans`` (sorted by start) lets a call site that lands in
        # the middle of a function -- a tail-called body, an offset the caller
        # asked about -- still resolve to the function that contains it.
        by_start: dict[int, JsonObject] = {}
        spans: list[tuple[int, int, str]] = []
        for func in funcs:
            if not isinstance(func, dict):
                continue
            start = _item_va(func, ("offset", "addr"))
            if start is None:
                continue
            size = func.get("size")
            size = size if isinstance(size, int) and size >= 0 else 0
            name = str(func.get("name") or "")
            by_start[start] = func
            spans.append((start, start + size, name))
        spans.sort()
        starts = [span[0] for span in spans]

        def _resolve(va: int | None) -> tuple[int | None, str, bool]:
            """(function start, name, resolved) for the function containing ``va``."""
            if va is None:
                return None, "", False
            func = by_start.get(va)
            if func is not None:
                return va, str(func.get("name") or ""), True
            index = bisect.bisect_right(starts, va) - 1
            if 0 <= index < len(spans):
                start, end, name = spans[index]
                # end == start guards a zero-size function: only an exact start
                # hit (handled above) counts, never a stray byte after it.
                if start <= va < end:
                    return start, name, True
            return va, "", False

        node_start, node_name, node_found = _resolve(address)
        node_func = by_start.get(node_start) if node_start is not None else None

        # (direction, other-start, callsite, type, name) -- a set so a function
        # called from two sites still yields two edges (distinct callsite) while
        # a duplicated ref row collapses.
        edges: set[tuple[str, int, int, str, str]] = set()
        scan_capped = False

        def _collect(rows: Any, edge_dir: str, endpoint_keys: tuple[str, ...]) -> None:
            nonlocal scan_capped
            if not isinstance(rows, list):
                return
            for row in rows:
                if scan_capped or len(edges) >= _MAX_CALLGRAPH_COLLECT:
                    scan_capped = True
                    return
                if not isinstance(row, dict):
                    continue
                endpoint = _item_va(row, endpoint_keys)
                callsite = _item_va(row, ("at",))
                rtype = str(row.get("type") or "")
                other_start, _name, _ok = _resolve(endpoint)
                # A callee edge names the target (``addr``) and its call site is
                # ``at`` (inside this function). A caller edge names the source
                # (``addr`` = the calling instruction); that instruction *is* the
                # call site, so the endpoint and the call site coincide.
                if edge_dir == "callee":
                    site = callsite if callsite is not None else -1
                else:
                    site = endpoint if endpoint is not None else -1
                edges.add(
                    (
                        edge_dir,
                        other_start if other_start is not None else -1,
                        site,
                        rtype,
                        _name,
                    )
                )

        if node_func is not None:
            if direction in ("callees", "both"):
                _collect(node_func.get("callrefs"), "callee", ("addr", "to", "ref"))
            if direction in ("callers", "both"):
                _collect(node_func.get("codexrefs"), "caller", ("addr", "from"))

        callees_total = sum(1 for edge in edges if edge[0] == "callee")
        callers_total = sum(1 for edge in edges if edge[0] == "caller")
        ordered = sorted(edges)
        start_at = max(0, int(offset))
        cap = min(max(1, int(limit)), _MAX_CALLGRAPH_PAGE)
        window = ordered[start_at : start_at + cap]

        result: JsonObject = {
            "commands": ["aa", "aflj"],
            "module": binary.name,
            "address_va": address,
            "direction": direction,
            "parsed": bool(funcs),
        }
        if image_base is not None:
            result["image_base"] = image_base
        if arch is not None:
            result["architecture"] = arch.value
        mapped = address_dict(
            address, module=binary.name, image_base=image_base, architecture=arch
        )
        if mapped is not None:
            result["address"] = mapped
        if node_start is not None and node_found:
            func_entry: JsonObject = {"name": node_name, "addr": node_start}
            node_size = node_func.get("size") if isinstance(node_func, dict) else None
            if isinstance(node_size, int):
                func_entry["size"] = node_size
            func_mapped = address_dict(
                node_start, module=binary.name, image_base=image_base, architecture=arch
            )
            if func_mapped is not None:
                func_entry["address"] = func_mapped
            result["function"] = func_entry
        else:
            # The address is not inside any analysed function; report an empty
            # graph rather than raising, matching r2.disasm_function/r2.xrefs.
            result["function"] = None

        result["edges"] = [
            self._callgraph_edge(
                edge, module=binary.name, image_base=image_base, architecture=arch
            )
            for edge in window
        ]
        result["count"] = len(window)
        result["total"] = len(ordered)
        result["callees_total"] = callees_total
        result["callers_total"] = callers_total
        result["offset"] = start_at
        result["has_more"] = start_at + len(window) < len(ordered)
        result["scan_capped"] = scan_capped
        return result

    @staticmethod
    def _callgraph_edge(
        edge: tuple[str, int, int, str, str],
        *,
        module: str,
        image_base: int | None,
        architecture: Any,
    ) -> JsonObject:
        edge_dir, other_start, site, rtype, name = edge
        item: JsonObject = {
            "direction": edge_dir,
            "name": name,
            "addr": other_start if other_start >= 0 else None,
            "call_site_va": site if site >= 0 else None,
            "type": rtype,
            # False when the endpoint fell outside every analysed function --
            # ``addr`` is then the raw target/source, not a function start, and
            # the name is empty (every aflj function carries a name).
            "resolved": bool(name),
        }
        if other_start >= 0:
            mapped = address_dict(
                other_start, module=module, image_base=image_base, architecture=architecture
            )
            if mapped is not None:
                item["address"] = mapped
        if site >= 0:
            site_mapped = address_dict(
                site, module=module, image_base=image_base, architecture=architecture
            )
            if site_mapped is not None:
                item["call_site"] = site_mapped
        return item

    def cfg(
        self,
        binary: Path,
        address: int,
        *,
        timeout: float = 30.0,
    ) -> JsonObject:
        """The control-flow graph of the function at ``address``.

        Where r2.disasm_function reads a function as a flat op list, this reads
        its shape: the basic blocks (nodes) and the branch edges between them, so
        loops, conditionals and fall-through are legible without walking every
        instruction. It is the native twin of static.cfg -- the seam from
        r2.functions or r2.disasm_function to "how does control move through this
        routine". ``address`` may sit anywhere inside the function, not only on
        its entry.

        Runs ``aa`` then ``afij`` (the function bounds) and ``afbj`` (its basic
        blocks) in one pass. Each block becomes a node; r2's per-block ``jump``
        (branch-taken / unconditional successor) and ``fail`` (branch-not-taken
        fall-through) become directed edges, and a jump table's ``switch_op``
        cases become switch edges. An address not inside any analysed function is
        a clean empty graph, not an error.
        """
        if type(address) is not int or address < 0:
            raise R2Error("invalid_params", "address must be a non-negative int")
        afij = f"afij @ {address}"
        afbj = f"afbj @ {address}"
        data = self.run(binary, ["aa", afij, afbj], timeout=timeout)
        arrays = parse_r2_arrays(str(data.get("raw") or ""))
        func_arr = arrays[0] if len(arrays) >= 1 else []
        blocks = arrays[1] if len(arrays) >= 2 else []
        arch, image_base = pe_preferred_base(binary)

        result: JsonObject = {
            "commands": ["aa", afij, afbj],
            "module": binary.name,
            "address_va": address,
            "parsed": bool(arrays),
        }
        if image_base is not None:
            result["image_base"] = image_base
        if arch is not None:
            result["architecture"] = arch.value
        mapped = address_dict(
            address, module=binary.name, image_base=image_base, architecture=arch
        )
        if mapped is not None:
            result["address"] = mapped

        func = func_arr[0] if isinstance(func_arr, list) and func_arr else None
        if isinstance(func, dict):
            func_start = _item_va(func, ("offset", "addr"))
            func_entry: JsonObject = {"name": str(func.get("name") or "")}
            if func_start is not None:
                func_entry["addr"] = func_start
                func_mapped = address_dict(
                    func_start, module=binary.name, image_base=image_base, architecture=arch
                )
                if func_mapped is not None:
                    func_entry["address"] = func_mapped
            if isinstance(func.get("size"), int):
                func_entry["size"] = func["size"]
            if isinstance(func.get("nbbs"), int):
                func_entry["nbbs"] = func["nbbs"]
            result["function"] = func_entry
        else:
            # afbj/afij at a non-function address print empty arrays; report an
            # empty graph rather than raising, matching r2.disasm_function.
            result["function"] = None

        nodes: list[JsonObject] = []
        # (src, dst, kind) -- a set so a block that lists the same successor twice
        # (a conditional whose arms coincide) collapses to one edge.
        edge_set: set[tuple[int, int, str]] = set()
        available = len(blocks) if isinstance(blocks, list) else 0
        for block in (blocks or [])[:_MAX_ITEMS]:
            if not isinstance(block, dict):
                continue
            start = _item_va(block, ("addr", "offset"))
            if start is None:
                continue
            size = block.get("size")
            size = size if isinstance(size, int) and size >= 0 else 0
            node: JsonObject = {"addr": start, "size": size, "end": start + size}
            if isinstance(block.get("ninstr"), int):
                node["ninstr"] = block["ninstr"]
            node_mapped = address_dict(
                start, module=binary.name, image_base=image_base, architecture=arch
            )
            if node_mapped is not None:
                node["address"] = node_mapped
            nodes.append(node)

            jump = _item_va(block, ("jump",))
            fail = _item_va(block, ("fail",))
            # jump is the branch-taken / unconditional successor; fail is the
            # fall-through when the branch is not taken. A block with both is a
            # conditional; a block with only jump flows unconditionally.
            if jump is not None:
                edge_set.add((start, jump, "jump"))
            if fail is not None:
                edge_set.add((start, fail, "fail"))
            for dst, kind in _switch_targets(block.get("switch_op")):
                edge_set.add((start, dst, kind))

        edges: list[JsonObject] = [
            self._cfg_edge(
                src, dst, kind, module=binary.name, image_base=image_base, architecture=arch
            )
            for src, dst, kind in sorted(edge_set)
        ]
        result["nodes"] = nodes
        result["edges"] = edges
        result["node_count"] = len(nodes)
        result["edge_count"] = len(edges)
        if available > _MAX_ITEMS:
            # A function with more blocks than the cap is trimmed; say so, like
            # the other r2 readers, so "this is the whole CFG" is never a wrong
            # read. Edges are built only from the included nodes.
            result["nodes_truncated"] = True
            result["nodes_total"] = available
            result["nodes_limit"] = _MAX_ITEMS
        return result

    @staticmethod
    def _cfg_edge(
        src: int,
        dst: int,
        kind: str,
        *,
        module: str,
        image_base: int | None,
        architecture: Any,
    ) -> JsonObject:
        item: JsonObject = {"src": src, "dst": dst, "kind": kind}
        src_mapped = address_dict(
            src, module=module, image_base=image_base, architecture=architecture
        )
        if src_mapped is not None:
            item["src_address"] = src_mapped
        dst_mapped = address_dict(
            dst, module=module, image_base=image_base, architecture=architecture
        )
        if dst_mapped is not None:
            item["dst_address"] = dst_mapped
        return item

    def libs(self, binary: Path, *, timeout: float = 30.0) -> JsonObject:
        """List the shared libraries the image links against.

        ``r2.imports`` names the individual symbols pulled from other libraries;
        this answers the coarser dependency question -- which shared objects the
        loader must resolve at all: the ``DT_NEEDED`` entries of an ELF, the
        linked dylibs of a Mach-O, the imported DLLs of a PE. It is the
        native/cross-format analogue of a PE's imported-module list and a fast
        triage read (a musl-only binary, an unexpected OpenSSL or curl
        dependency, a stray extra ``.so``) before ever walking the per-symbol
        imports. Runs ``ilj``. radare2 emits either bare library-name strings or
        small objects across versions and formats, so both are normalised to
        ``{"name": ...}`` items with a ``count``; a binary that links nothing
        (a fully static ELF) is a clean empty list, not an error.
        """
        data = self.run(binary, ["ilj"], timeout=timeout)
        parsed = parse_r2_json(str(data.get("raw") or ""))
        # ``ilj`` is a bare array on most builds, but some wrap it as
        # ``{"libs": [...]}``; accept either so the reader is version-proof.
        entries: list[Any] = []
        if isinstance(parsed, list):
            entries = parsed
        elif isinstance(parsed, dict):
            maybe = parsed.get("libs")
            if isinstance(maybe, list):
                entries = maybe
        items: list[JsonObject] = []
        for entry in entries:
            if len(items) >= _MAX_ITEMS:
                break
            if isinstance(entry, str):
                name = entry
            elif isinstance(entry, dict):
                name = str(entry.get("name") or entry.get("library") or entry.get("lib") or "")
            else:
                continue
            name = name.strip()
            if name:
                items.append({"name": name})
        result: JsonObject = {
            "commands": ["ilj"],
            "module": binary.name,
            "items": items,
            "count": len(items),
            "parsed": parsed is not None,
        }
        if len(entries) > _MAX_ITEMS:
            # Trimmed to the cap; disclosed like the other r2 readers so "these
            # are all the libraries" is never a wrong read on a crafted module.
            result["items_truncated"] = True
            result["items_total"] = len(entries)
            result["items_limit"] = _MAX_ITEMS
        return result

    def run(self, binary: Path, commands: list[str], *, timeout: float = 30.0) -> JsonObject:
        if not self.available or self.executable is None:
            raise R2Error("capability_unavailable", "radare2/rizin is not installed")
        if not binary.is_file():
            raise R2Error("not_found", "binary not found", path=str(binary))
        for cmd in commands:
            _require_allowed_command(cmd)
        script = "\n".join([*commands, "q"])
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        try:
            # r2 on PATH is often a launcher script, and subprocess.run kills
            # only that process then drains with no deadline. Measured: a stub
            # that started a child and held the pipes did not return 8s after a
            # 0.8s timeout, and the child was still running.
            completed = run_bounded(
                [str(self.executable), "-q0", "-c", script, str(binary)],
                timeout=timeout,
                creationflags=creationflags,
            )
        except TimedOut as exc:
            raise R2Error(
                "timeout",
                "r2 timed out",
                timeout=timeout,
                killed_pids=exc.killed,
            ) from exc
        except OSError as exc:
            # A configured executable that is present but cannot be launched --
            # not marked +x, or replaced between the is_file() check and the
            # spawn -- makes Popen raise OSError (PermissionError for a
            # non-executable file). Uncaught, that reaches the service envelope
            # as an internal_error with a logged incident, casting a backend
            # misconfiguration as a server defect. The sibling adapters (jadx,
            # apktool, jsre, windbg) all map this to backend_error; r2 did not.
            raise R2Error(
                "backend_error",
                f"failed to launch {self.executable}: {exc}",
            ) from exc
        produced = len(completed.stdout)
        out = completed.stdout[:_MAX_OUTPUT]
        err = completed.stderr[:_MAX_OUTPUT]
        if completed.returncode != 0:
            raise R2Error(
                "backend_error",
                "r2 exited non-zero",
                exit_code=completed.returncode,
                stderr=err.decode("utf-8", errors="replace")[:2000],
            )
        payload: JsonObject = {
            "raw": out.decode("utf-8", errors="replace"),
            "commands": commands,
        }
        if produced > _MAX_OUTPUT:
            # Cut silently, a listing that stopped at the buffer looks like a
            # listing that ended, and this is the analysis text a caller reads
            # to decide where a function finishes.
            payload["truncated"] = True
            payload["output_bytes"] = produced
            payload["returned_bytes"] = len(out)
        return enrich_r2_payload(payload, binary=binary)


def _discover() -> Path | None:
    for name in ("r2", "rizin", "radare2"):
        found = shutil.which(name)
        if found:
            return Path(found)
    return None
