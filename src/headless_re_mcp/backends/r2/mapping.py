from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from headless_re_mcp.core.models import Address, Architecture

JsonObject = dict[str, Any]
_MAX_ITEMS = 4096
# The whitelisted r2 commands whose output is a JSON array. When one of these
# produces *nothing*, that is an empty list, not a parse failure: r2's ``axj``
# prints nothing at all (not ``[]``) for an address with no references, so a
# zero-xref query used to come back ``parsed: False`` with no ``items`` or
# ``count`` -- indistinguishable from a broken decode, and missing the shape
# r2.xrefs documents. The other array commands emit ``[]`` when empty, so this
# only ever fires for that ``axj`` case, but naming them all keeps it honest.
_JSON_ARRAY_COMMANDS = ("aflj", "izj", "iij", "iEj", "axj", "pdj")
# How many candidate "["/"{" positions the JSON scan will try to decode.
# r2 -q0 prints its banners before the one JSON document, so the real root
# is always within the first handful of bracket positions; this only bounds
# the cost of raw output that is mostly brackets (see parse_r2_json).
_MAX_JSON_SCAN_ATTEMPTS = 256
# Enough for any PE header: the DOS stub and the optional header live in the
# first pages. The second read below covers the pathological ones.
_HEADER_WINDOW = 64 * 1024
_MAX_HEADER = 1024 * 1024


def pe_preferred_base(binary: Path) -> tuple[Architecture | None, int | None]:
    """Read PE preferred ImageBase without spawning r2.

    A prefix, not the file. Every r2 tool call enriches its payload through
    here, and slurping the target to read one header field cost, measured on a
    200 MB sample, 200 MB of RSS per call and 0.41s for six calls.
    """
    try:
        with binary.open("rb") as stream:
            data = stream.read(_HEADER_WINDOW)
            # Twice at most: the first re-read reveals the file header, which is
            # what says how long the optional header is.
            for _ in range(2):
                header_end = _needed_header_bytes(data)
                if header_end is None or header_end <= len(data) or header_end > _MAX_HEADER:
                    break
                stream.seek(0)
                data = stream.read(header_end)
    except OSError:
        return None, None
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None, None
    pe_offset = int.from_bytes(data[0x3C:0x40], "little")
    if pe_offset <= 0 or pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        return None, None
    optional_size = int.from_bytes(data[pe_offset + 20 : pe_offset + 22], "little")
    optional = data[pe_offset + 24 : pe_offset + 24 + optional_size]
    if len(optional) < 60:
        return None, None
    magic = int.from_bytes(optional[0:2], "little")
    if magic == 0x10B:
        architecture = Architecture.X86
        image_base = int.from_bytes(optional[28:32], "little")
    elif magic == 0x20B:
        architecture = Architecture.X64
        image_base = int.from_bytes(optional[24:32], "little")
    else:
        return None, None
    if image_base <= 0:
        return architecture, None
    return architecture, image_base


def _needed_header_bytes(head: bytes) -> int | None:
    """How far into the file the optional header runs, if this looks like a PE."""
    if len(head) < 0x40 or head[:2] != b"MZ":
        return None
    pe_offset = int.from_bytes(head[0x3C:0x40], "little")
    if pe_offset <= 0 or pe_offset + 24 > len(head):
        # Either not a PE, or the stub is longer than the window; ask for enough
        # to reach the file header and let the caller re-read.
        return pe_offset + 24 if 0 < pe_offset < _MAX_HEADER else None
    if head[pe_offset : pe_offset + 4] != b"PE\0\0":
        return None
    optional_size = int.from_bytes(head[pe_offset + 20 : pe_offset + 22], "little")
    return pe_offset + 24 + optional_size


def address_dict(
    va: int | None,
    *,
    module: str,
    image_base: int | None,
    architecture: Architecture | None,
) -> JsonObject | None:
    if type(va) is not int or va < 0:
        return None
    rva: int | None = None
    if image_base is not None and va >= image_base:
        rva = va - image_base
    try:
        if rva is not None:
            addr = Address(module=module, rva=rva, va=va, architecture=architecture)
        else:
            addr = Address(va=va, architecture=architecture)
    except ValueError:
        return None
    return addr.model_dump(mode="json", exclude_none=True)


def _reject_constant(value: str) -> Any:
    # Python's json accepts NaN/Infinity by default and hands back floats that
    # json.dumps(allow_nan=False) and every strict consumer downstream (the
    # web UI's JSON.parse, the agent store's canonical hashing) then refuse.
    # detection/die.py rejects these constants for the same reason.
    raise ValueError(f"non-standard JSON constant: {value}")


def parse_r2_json(raw: str) -> Any | None:
    """Extract the first JSON value from r2 -q0 output (may include banners).

    ``rfind("[")`` is wrong here: ``pdj`` / ``axj`` / ``izj`` put ``[`` inside
    opcodes (``mov eax, dword [rbp+0x10]``), C++ names, and strings. That
    slice is not the root array, so the ``{…}`` fallback loaded only the last
    object and ``enrich_r2_payload`` reported ``parsed: True`` with no items.

    The raw text is hostile-influenced: once the root document fails to parse
    (a 1 MB capture truncated mid-JSON is routine), the scan walks into
    bracket positions inside string values that came straight from the binary
    under analysis. A run of brackets there raised RecursionError out of the
    C decoder -- neither a JSONDecodeError nor a ValueError -- and, with that
    caught, would still make the scan quadratic; hence the attempt cap,
    matching detection/die.py's ``_MAX_JSON_OBJECT_SCANS``.
    """
    text = (raw or "").strip()
    if not text:
        return None
    decoder = json.JSONDecoder(parse_constant=_reject_constant)
    attempts = 0
    for index, char in enumerate(text):
        if char not in "[{":
            continue
        if attempts >= _MAX_JSON_SCAN_ATTEMPTS:
            break
        attempts += 1
        try:
            value, _end = decoder.raw_decode(text, index)
        except (ValueError, RecursionError):
            # JSONDecodeError is a ValueError, and so is the constant
            # rejection above; RecursionError is the deep-nesting case.
            continue
        return value
    return None


def _dedup_signature(entry: JsonObject) -> str:
    """A stable signature of an entry ignoring its ``ordinal``.

    r2 numbers each symbol-table row with an ``ordinal``; the same symbol listed
    under two ordinals is one symbol, so the ordinal is what we drop to tell the
    duplicates apart from genuinely distinct rows.
    """
    reduced = {key: value for key, value in entry.items() if key != "ordinal"}
    return json.dumps(reduced, sort_keys=True, default=str)


def _item_va(entry: JsonObject, keys: tuple[str, ...]) -> int | None:
    for key in keys:
        value = entry.get(key)
        if type(value) is int and value >= 0:
            return value
        if isinstance(value, str) and value:
            try:
                return int(value, 0)
            except ValueError:
                continue
    return None


def enrich_r2_payload(
    data: JsonObject,
    *,
    binary: Path,
    architecture: Architecture | None = None,
) -> JsonObject:
    """Parse *j payloads into items with unified Address fields."""
    module = binary.name
    pe_arch, image_base = pe_preferred_base(binary)
    arch = architecture or pe_arch
    raw = str(data.get("raw") or "")
    commands = list(data.get("commands") or [])
    parsed = parse_r2_json(raw)
    if (
        parsed is None
        and not raw.strip()
        and any(command.startswith(_JSON_ARRAY_COMMANDS) for command in commands)
    ):
        # Empty output from a JSON-array command (in practice axj with no
        # references) is an empty list, so items/count stay present and a
        # caller can tell "no references" from "the command failed".
        parsed = []
    out = dict(data)
    out["module"] = module
    if image_base is not None:
        out["image_base"] = image_base
    if arch is not None:
        out["architecture"] = arch.value

    # Preserve request address as Address when present.
    request_address = data.get("address")
    if type(request_address) is int:
        mapped = address_dict(
            request_address, module=module, image_base=image_base, architecture=arch
        )
        if mapped is not None:
            out["address"] = mapped
            out["address_va"] = request_address

    items: list[JsonObject] = []
    if isinstance(parsed, list):
        # r2 lists the same symbol under several ordinals when it merges the
        # dynamic and static symbol tables -- an ELF shared object's iEj shows
        # every export twice (identical but for `ordinal`), so `count` read
        # double and a reader saw each export listed once per table. Collapse
        # rows that are identical except for their ordinal before counting or
        # capping; only rows that actually carry an ordinal are considered, so
        # functions, xrefs and disassembly (which have none) are never touched.
        deduped: list[Any] = []
        seen: set[str] = set()
        dropped = 0
        for entry in parsed:
            if isinstance(entry, dict) and "ordinal" in entry:
                signature = _dedup_signature(entry)
                if signature in seen:
                    dropped += 1
                    continue
                seen.add(signature)
            deduped.append(entry)
        available = len(deduped)
        for entry in deduped[:_MAX_ITEMS]:
            if not isinstance(entry, dict):
                continue
            item = dict(entry)
            va = _item_va(
                entry,
                ("offset", "vaddr", "addr", "from", "to", "plt", "paddr"),
            )
            mapped = address_dict(va, module=module, image_base=image_base, architecture=arch)
            if mapped is not None:
                item["address"] = mapped
            # Named endpoints for xrefs
            for edge_key in ("from", "to"):
                edge_va = _item_va(entry, (edge_key,))
                edge_mapped = address_dict(
                    edge_va, module=module, image_base=image_base, architecture=arch
                )
                if edge_mapped is not None:
                    item[f"{edge_key}_address"] = edge_mapped
            items.append(item)
        out["items"] = items
        out["count"] = len(items)
        if dropped:
            # Said out loud like the truncation beside it: a caller comparing
            # `count` against another tool's export table should know r2's raw
            # listing was longer only because it repeated the same symbols.
            out["items_deduplicated"] = dropped
        if available > _MAX_ITEMS:
            # Said out loud, like the raw-output cut beside it. A list that
            # stopped at the cap looks exactly like a list that ended, and a
            # caller deciding "these are all the xrefs" is deciding wrongly.
            out["items_truncated"] = True
            out["items_total"] = available
            out["items_limit"] = _MAX_ITEMS
        out["parsed"] = True
    elif isinstance(parsed, dict):
        out["info"] = parsed
        out["parsed"] = True
    else:
        out["parsed"] = False
    out["commands"] = commands
    return out
