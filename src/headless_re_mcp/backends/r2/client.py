from __future__ import annotations

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
    raise R2Error("invalid_params", "r2 command not whitelisted", command=command)


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
