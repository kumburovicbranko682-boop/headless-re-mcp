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


def parse_r2_json_values(raw: str) -> list[Any]:
    """Every top-level JSON value in r2 -q0 output, in emission order.

    A script of several ``*j`` commands prints one value per command,
    newline-separated (no NUL markers arrive through ``-q0 -c``, measured on
    r2 5.5.0). ``parse_r2_json`` stops at the first value, which silently
    discards every command after the first; callers that batch commands need
    all of them, positionally. Skips over undecodable ``[``/``{`` exactly like
    the single-value parse, and jumps past each decoded value so a large
    array is scanned once.
    """
    text = (raw or "").strip()
    values: list[Any] = []
    decoder = json.JSONDecoder()
    index = 0
    while index < len(text):
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


def _salvage_cut_array(text: str, opening: int) -> list[Any]:
    """Complete values inside an array whose closing bracket was cut off."""
    decoder = json.JSONDecoder()
    values: list[Any] = []
    index = opening + 1
    length = len(text)
    while index < length:
        char = text[index]
        if char in ", \t\r\n":
            index += 1
            continue
        if char == "]":
            break
        try:
            value, end = decoder.raw_decode(text, index)
        except json.JSONDecodeError:
            # The cut tail begins here; everything before it was complete.
            break
        values.append(value)
        index = end
    return values


def reparse_cut_output(raw: str) -> tuple[Any | None, bool]:
    """(value, salvaged) for output the byte cap cut mid-stream.

    ``parse_r2_json`` takes the first *decodable* value, which is exactly
    wrong once the 1_000_000-byte cut falls inside the root array: the root
    never decodes, so the scan lands on the first fragment that does --
    measured through run() on an oversized ``aflj``, that was the nested
    ``callrefs`` array of the first function, presented as the function
    listing itself with ``parsed: True``. Call references masquerading as
    functions is fabricated analysis, not truncation.

    Cut output therefore trusts only the *first* structural character: if the
    value opening there decodes to completion the cut fell after it (use it as
    usual); if it is an unterminated array, salvage its complete top-level
    entries and say so; anything else parses as nothing rather than as
    whatever fragment happens to survive further in.
    """
    text = (raw or "").strip()
    first = next((index for index, char in enumerate(text) if char in "[{"), None)
    if first is None:
        return None, False
    decoder = json.JSONDecoder()
    try:
        value, _end = decoder.raw_decode(text, first)
    except json.JSONDecodeError:
        if text[first] == "[":
            entries = _salvage_cut_array(text, first)
            if entries:
                return entries, True
        return None, False
    return value, False


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


def _mapped_item(
    entry: JsonObject,
    *,
    module: str,
    image_base: int | None,
    arch: Architecture | None,
) -> JsonObject:
    """One r2 item with unified Address fields attached."""
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
        edge_mapped = address_dict(edge_va, module=module, image_base=image_base, architecture=arch)
        if edge_mapped is not None:
            item[f"{edge_key}_address"] = edge_mapped
    return item


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
    salvaged = False
    if data.get("truncated"):
        parsed, salvaged = reparse_cut_output(raw)
    else:
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

    items: list[JsonObject] = []
    if isinstance(parsed, list):
        available = len(parsed)
        for entry in parsed[:_MAX_ITEMS]:
            if not isinstance(entry, dict):
                continue
            items.append(_mapped_item(entry, module=module, image_base=image_base, arch=arch))
        out["items"] = items
        out["count"] = len(items)
        if available > _MAX_ITEMS:
            # Said out loud, like the raw-output cut beside it. A list that
            # stopped at the cap looks exactly like a list that ended, and a
            # caller deciding "these are all the xrefs" is deciding wrongly.
            out["items_truncated"] = True
            out["items_total"] = available
            out["items_limit"] = _MAX_ITEMS
        if salvaged:
            # items holds the complete entries recovered before the byte cut;
            # an unknown tail is gone. Distinct from items_truncated, which
            # counts a list that arrived whole and was capped here.
            out["items_salvaged"] = True
        out["parsed"] = True
    elif isinstance(parsed, dict):
        out["info"] = parsed
        out["parsed"] = True
    else:
        out["parsed"] = False
    out["commands"] = commands
    return out


def enrich_xrefs_payload(
    data: JsonObject,
    *,
    binary: Path,
    address: int,
    architecture: Architecture | None = None,
) -> JsonObject:
    """Merge the ``axtj``/``axfj`` pair into one direction-tagged items list.

    ``r2.xrefs`` promises references to and from one address. ``axj @ addr``
    never delivered that: ``axj`` lists the whole xref database and the ``@``
    seek does not filter it (measured on r2 5.5.0 -- a two-caller fixture
    answered with entry0/printf/section relocs for every address asked). The
    scoped commands are ``axtj`` (references to the seek; entries carry
    ``from``, the seek itself is the implied ``to``) and ``axfj`` (references
    from the instruction at the seek; entries carry ``from`` and ``to``), so
    the client now runs both and this merge tags each item with ``direction``:
    ``"to"`` when the reference points at ``address``, ``"from"`` when
    ``address`` makes it. The missing endpoint defaults to ``address`` so
    every item carries both ``from`` and ``to`` -- which the old global dump
    also never did (``axj`` names its target ``addr``, not ``to``).

    Positional, not shape-guessed: the first two top-level JSON arrays in
    ``raw`` are the axtj and axfj answers, in script order (r2 always prints
    an array, ``[]`` when empty, and ``aa`` is silent on stdout). Anything
    other than exactly two arrays means the output format drifted; that is
    reported as ``parsed: False`` with the raw text intact rather than
    guessed at.
    """
    module = binary.name
    pe_arch, image_base = pe_preferred_base(binary)
    arch = architecture or pe_arch
    out = dict(data)
    out["module"] = module
    if image_base is not None:
        out["image_base"] = image_base
    if arch is not None:
        out["architecture"] = arch.value
    mapped_request = address_dict(address, module=module, image_base=image_base, architecture=arch)
    if mapped_request is not None:
        out["address"] = mapped_request
        out["address_va"] = address

    # The payload arrives pre-enriched by run(), whose generic parse saw only
    # the first array; drop those keys so a drifted output cannot leave the
    # axtj half behind as authoritative-looking items.
    stale_keys = (
        "items",
        "count",
        "parsed",
        "items_truncated",
        "items_total",
        "items_limit",
        "items_salvaged",
    )
    for stale in stale_keys:
        out.pop(stale, None)

    values = parse_r2_json_values(str(data.get("raw") or ""))
    arrays = [value for value in values if isinstance(value, list)]
    if len(arrays) != 2:
        out["parsed"] = False
        out["commands"] = list(data.get("commands") or [])
        return out
    refs_to, refs_from = arrays
    tagged = [(entry, "to") for entry in refs_to] + [(entry, "from") for entry in refs_from]
    available = len(tagged)
    items: list[JsonObject] = []
    for entry, direction in tagged[:_MAX_ITEMS]:
        if not isinstance(entry, dict):
            continue
        normalized = dict(entry)
        normalized.setdefault("to" if direction == "to" else "from", address)
        normalized["direction"] = direction
        items.append(_mapped_item(normalized, module=module, image_base=image_base, arch=arch))
    out["items"] = items
    out["count"] = len(items)
    if available > _MAX_ITEMS:
        out["items_truncated"] = True
        out["items_total"] = available
        out["items_limit"] = _MAX_ITEMS
    out["parsed"] = True
    out["commands"] = list(data.get("commands") or [])
    return out
