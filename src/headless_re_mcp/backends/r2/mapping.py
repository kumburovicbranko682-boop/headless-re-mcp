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


def parse_r2_arrays(raw: str) -> list[list[Any]]:
    """Extract every top-level JSON array from r2 output, in emission order.

    A single r2 invocation that runs more than one ``*j`` command prints one
    array per command. ``parse_r2_json`` only returns the first, which is fine
    for the single-command tools but loses the second half of the two-command
    xref query (``axtj`` then ``axfj``). This walks the whole stream, decoding
    at each ``[`` and skipping the ``[`` that live inside opcodes/strings of an
    array already consumed (the decode jumps past them) and progress banners
    like ``[x] Analyze...`` (which fail to decode and are stepped over).
    """
    text = raw or ""
    decoder = json.JSONDecoder()
    arrays: list[list[Any]] = []
    index = 0
    length = len(text)
    while index < length:
        if text[index] != "[":
            index += 1
            continue
        try:
            value, end = decoder.raw_decode(text, index)
        except json.JSONDecodeError:
            index += 1
            continue
        if isinstance(value, list):
            arrays.append(value)
        index = end
    return arrays


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


# An xref row names the address it references under different keys across r2
# versions: modern builds emit ``to``, r2 5.x emits ``addr`` (with ``from`` the
# origin either way). Match any of them so the address filter is version-proof.
_XREF_ENDPOINT_KEYS: tuple[str, ...] = ("from", "to", "addr")


def _xref_touches(entry: JsonObject, va: int) -> bool:
    """True when this xref row has ``va`` as either its origin or its target."""
    return any(_item_va(entry, (key,)) == va for key in _XREF_ENDPOINT_KEYS)


def enrich_r2_payload(
    data: JsonObject,
    *,
    binary: Path,
    architecture: Architecture | None = None,
    xref_filter_va: int | None = None,
) -> JsonObject:
    """Parse *j payloads into items with unified Address fields.

    ``xref_filter_va`` narrows an ``axj`` dump (which radare2 emits whole,
    ignoring the ``@`` seek) to the rows that actually touch that address, so
    ``r2.xrefs`` answers "to and from address" instead of the entire program's
    reference table. Filtering happens before the item cap, so a target with
    many references is never truncated away by unrelated rows.
    """
    module = binary.name
    pe_arch, image_base = pe_preferred_base(binary)
    arch = architecture or pe_arch
    raw = str(data.get("raw") or "")
    commands = list(data.get("commands") or [])
    # r2 6.x renamed the aflj function-start key from ``offset`` to ``addr``.
    # The address mapping below already tolerates either, but callers and the
    # r2.functions contract still read the integer ``offset``; alias it back so
    # the documented field survives the version bump. Scoped to aflj so the
    # symbol tools (which promise "no integer address field") are untouched.
    is_functions = any(str(command).strip() == "aflj" for command in commands)
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
        if xref_filter_va is not None:
            parsed = [
                entry
                for entry in parsed
                if isinstance(entry, dict) and _xref_touches(entry, xref_filter_va)
            ]
        available = len(parsed)
        for entry in parsed[:_MAX_ITEMS]:
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
            if is_functions and "offset" not in item and va is not None:
                item["offset"] = va
            # Named xref endpoints, gated on the row being xref-shaped: it names
            # an origin under ``from``. Only then does ``addr`` mean "referenced
            # target" (r2 5.x) rather than, say, a function-start key -- so a
            # function row (aflj, which has ``addr`` but no ``from``) never grows
            # a spurious ``to``/``to_address``. The origin is ``from``; the
            # target is ``to`` on modern r2 but ``addr`` on r2 5.x. Without this
            # an r2 5.x xref row carried neither the documented ``to`` nor
            # ``to_address`` and a caller pivoting on the target read nothing.
            from_va = _item_va(entry, ("from",))
            if from_va is not None:
                from_mapped = address_dict(
                    from_va, module=module, image_base=image_base, architecture=arch
                )
                if from_mapped is not None:
                    item["from_address"] = from_mapped
                to_va = _item_va(entry, ("to", "addr"))
                if to_va is not None:
                    # Surface the documented integer ``to`` even when r2 named it ``addr``.
                    item.setdefault("to", to_va)
                    to_mapped = address_dict(
                        to_va, module=module, image_base=image_base, architecture=arch
                    )
                    if to_mapped is not None:
                        item["to_address"] = to_mapped
            items.append(item)
        out["items"] = items
        out["count"] = len(items)
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
