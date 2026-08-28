from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

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


# ELF e_machine values the two-arch Architecture enum can name. Any other
# machine (ARM, AArch64, RISC-V, ...) keeps the load base but gets no arch tag
# rather than a wrong one -- the address mapping still yields va and rva.
_ELF_MACHINE = {3: Architecture.X86, 62: Architecture.X64}
_PT_LOAD = 1


def elf_preferred_base(binary: Path) -> tuple[Architecture | None, int | None]:
    """Read an ELF's load base and architecture without spawning r2.

    The r2 tools run on whatever binary the session opened, and on Linux that is
    usually an ELF, not a PE. ``pe_preferred_base`` returns nothing for one, so
    every ELF address used to come back va-only -- no rva, no module -- yet rva
    is the coordinate a caller correlating r2 output against a loader map needs.
    The load base is the lowest ``p_vaddr`` among the ``PT_LOAD`` program
    headers, exactly what r2 reports as ``baddr``. A position-independent ELF
    (``ET_DYN``) whose first load segment sits at vaddr 0 has no fixed base, so
    this returns ``None`` for the base there -- honest va-only -- rather than
    inventing ``rva == va``. ``e_machine`` maps to the arch enum where it can;
    an unrepresentable machine keeps the base and drops the arch. Malformed
    headers degrade to ``(arch-if-known, None)`` the way the PE reader does,
    because this runs for every r2 payload and must never raise.
    """
    try:
        with binary.open("rb") as stream:
            head = stream.read(64)
            if len(head) < 64 or head[:4] != b"\x7fELF":
                return None, None
            is64 = head[4] == 2
            byteorder: Literal["little", "big"] = "big" if head[5] == 2 else "little"
            machine = int.from_bytes(head[0x12:0x14], byteorder)
            architecture = _ELF_MACHINE.get(machine)
            if is64:
                e_phoff = int.from_bytes(head[0x20:0x28], byteorder)
                e_phentsize = int.from_bytes(head[0x36:0x38], byteorder)
                e_phnum = int.from_bytes(head[0x38:0x3A], byteorder)
                vaddr_off, vaddr_len = 16, 8
            else:
                e_phoff = int.from_bytes(head[0x1C:0x20], byteorder)
                e_phentsize = int.from_bytes(head[0x2A:0x2C], byteorder)
                e_phnum = int.from_bytes(head[0x2C:0x2E], byteorder)
                vaddr_off, vaddr_len = 8, 4
            min_phent = vaddr_off + vaddr_len
            table_bytes = e_phentsize * e_phnum
            # e_phnum can be PN_XNUM (0xffff, real count in the section header):
            # a table that large is either that sentinel or a corrupt field, so
            # bound it like the PE reader bounds its header and give up honestly.
            if e_phoff <= 0 or e_phentsize < min_phent or table_bytes == 0:
                return architecture, None
            if table_bytes > _MAX_HEADER:
                return architecture, None
            stream.seek(e_phoff)
            table = stream.read(table_bytes)
    except OSError:
        return None, None
    base: int | None = None
    for index in range(e_phnum):
        entry = table[index * e_phentsize : (index + 1) * e_phentsize]
        if len(entry) < min_phent:
            break
        if int.from_bytes(entry[0:4], byteorder) != _PT_LOAD:
            continue
        vaddr = int.from_bytes(entry[vaddr_off : vaddr_off + vaddr_len], byteorder)
        if base is None or vaddr < base:
            base = vaddr
    if base is None or base <= 0:
        return architecture, None
    return architecture, base


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

    ``rfind("[")`` is wrong here: ``pdj`` / ``axtj`` / ``izj`` put ``[`` inside
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
    detected_arch, image_base = pe_preferred_base(binary)
    if detected_arch is None and image_base is None:
        # Not a PE. The r2 tools run on whatever the session opened, and on Linux
        # that is usually an ELF; fall back to its load base so ELF addresses
        # carry rva/module too, not only va. Both being None means the PE reader
        # made no claim at all (magic mismatch), so trying ELF cannot override a
        # real PE finding -- a PE with a zero ImageBase keeps its arch and skips
        # this branch.
        detected_arch, image_base = elf_preferred_base(binary)
    arch = architecture or detected_arch
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

    items: list[JsonObject] = []
    if isinstance(parsed, list):
        available = len(parsed)
        for entry in parsed[:_MAX_ITEMS]:
            if not isinstance(entry, dict):
                continue
            item = dict(entry)
            # r2 renamed raw keys between 5.x and 6.x: aflj's function entry
            # moved from `offset` to `addr`, and iij's import library from `lib`
            # to `libname`. The mapped `address` below reads either spelling, but
            # the raw keys the r2.* tool docstrings promise -- `offset` for
            # functions, `lib` for imports -- must stay stable across r2 versions
            # or a caller reading them breaks on a newer r2. Same value, same
            # meaning; restore the documented spelling when only the newer one is
            # present so the contract does not depend on the installed r2.
            if "offset" not in item and "addr" in item:
                item["offset"] = item["addr"]
            if "lib" not in item and "libname" in item:
                item["lib"] = item["libname"]
            # The reverse drift: r2 5.x spells "this import has no PLT stub"
            # as plt: 0 on an ELF's GOT-only imports, where 6.x omits the key.
            # The zero page is never a real stub, yet 0 fell through to the
            # address mapping below and grew a fabricated address at va 0 that
            # an agent could try to dereference. Erase the sentinel so a
            # stub-less import row is name-only on every r2, as the r2.imports
            # docstring states.
            if type(item.get("plt")) is int and item["plt"] == 0:
                del item["plt"]
            va = _item_va(
                item,
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
