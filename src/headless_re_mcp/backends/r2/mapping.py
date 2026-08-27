from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from headless_re_mcp.core.models import Address, Architecture

JsonObject = dict[str, Any]
_MAX_ITEMS = 4096
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


def parse_r2_json(raw: str) -> Any | None:
    """Extract the first JSON value from r2 -q0 output (may include banners).

    ``rfind("[")`` is wrong here: ``pdj`` / ``axj`` / ``izj`` put ``[`` inside
    opcodes (``mov eax, dword [rbp+0x10]``), C++ names, and strings. That
    slice is not the root array, so the ``{…}`` fallback loaded only the last
    object and ``enrich_r2_payload`` reported ``parsed: True`` with no items.
    """
    text = (raw or "").strip()
    if not text:
        return None
    decoder = json.JSONDecoder()
    for index, char in enumerate(text):
        if char not in "[{":
            continue
        try:
            value, _end = decoder.raw_decode(text, index)
        except json.JSONDecodeError:
            continue
        return value
    return None


def _first_container_char(text: str) -> str | None:
    """The first ``[`` or ``{`` in the text, or None. Marks the payload shape.

    parse_r2_json scans for the first value it can decode. On a list command
    whose output was cut mid-array that value is element 0 (a ``{``), so the
    dict branch would fire and swallow the whole listing. Knowing the payload
    opened with ``[`` lets the caller route a half array to prefix recovery
    instead.
    """
    for char in text:
        if char in "[{":
            return char
    return None


def _recover_array_prefix(text: str) -> list[Any]:
    """Decode the complete leading elements of a top-level JSON array.

    r2 -q0 output is cut at the byte cap in R2Client.run, which can land in the
    middle of an aflj / izj / iij / iEj / axj array. json cannot load a half
    array at all, so the elements that did arrive whole were lost. Decode from
    just after the opening ``[`` one value at a time, stopping at the closing
    bracket, the first element that did not arrive complete, or the item cap --
    whichever comes first -- so a truncated listing still yields a bounded,
    valid prefix. Each ``[`` is tried in turn (a leading banner can carry its
    own bracket) and the first that yields rows wins.
    """
    decoder = json.JSONDecoder()
    length = len(text)
    search = 0
    while True:
        start = text.find("[", search)
        if start < 0:
            return []
        items: list[Any] = []
        index = start + 1
        while len(items) < _MAX_ITEMS:
            while index < length and text[index] in " \t\r\n,":
                index += 1
            if index >= length or text[index] == "]":
                break
            try:
                value, index = decoder.raw_decode(text, index)
            except json.JSONDecodeError:
                break
            items.append(value)
        if items:
            return items
        search = start + 1


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

    if isinstance(parsed, list):
        available = len(parsed)
        out["items"] = _map_items(
            parsed[:_MAX_ITEMS], module=module, image_base=image_base, arch=arch
        )
        out["count"] = len(out["items"])
        if available > _MAX_ITEMS:
            # Said out loud, like the raw-output cut beside it. A list that
            # stopped at the cap looks exactly like a list that ended, and a
            # caller deciding "these are all the xrefs" is deciding wrongly.
            out["items_truncated"] = True
            out["items_total"] = available
            out["items_limit"] = _MAX_ITEMS
        out["parsed"] = True
    elif _first_container_char(raw) == "[":
        # The payload opened as an array but did not load as one: R2Client.run
        # cut the output at the byte cap mid-list. json returns nothing for a
        # half array, and parse_r2_json's first decodable value is element 0 (a
        # dict), so the old dict branch reported parsed with a bogus info object
        # and no items -- the entire listing vanished on any binary whose aflj /
        # izj output ran past a megabyte. Recover the elements that arrived
        # whole as a bounded prefix. items_total is left off: the true count is
        # unknown because the tail never arrived (raw's own truncated flag says
        # the bytes were cut).
        out["items"] = _map_items(
            _recover_array_prefix(raw), module=module, image_base=image_base, arch=arch
        )
        out["count"] = len(out["items"])
        out["items_truncated"] = True
        out["items_limit"] = _MAX_ITEMS
        out["parsed"] = True
    elif isinstance(parsed, dict):
        out["info"] = parsed
        out["parsed"] = True
    else:
        out["parsed"] = False
    out["commands"] = commands
    return out


def _map_items(
    entries: list[Any],
    *,
    module: str,
    image_base: int | None,
    arch: Architecture | None,
) -> list[JsonObject]:
    """Attach unified Address fields to each object row, skipping non-objects."""
    items: list[JsonObject] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        item = dict(entry)
        va = _item_va(entry, ("offset", "vaddr", "addr", "from", "to", "plt", "paddr"))
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
    return items
