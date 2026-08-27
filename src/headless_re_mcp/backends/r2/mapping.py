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


_ELF_MAGIC = b"\x7fELF"
_PT_LOAD = 1
# e_machine values the x86/x64-only Architecture enum can express. An ARM /
# AArch64 ELF -- the common Android .so -- still gets a base for rva binding,
# just no architecture, because the enum has no arm member (see elf_preferred_base).
_EM_386 = 3
_EM_X86_64 = 62
# A malformed or hostile header could claim a huge program-header table; cap the
# scan the same way the PE path bounds its re-read at _MAX_HEADER.
_ELF_MAX_PHNUM = 256


def _elf_int(data: bytes, offset: int, size: int, *, little: bool) -> int:
    """Read a little/big-endian ELF integer, 0 when the slice runs past the end."""
    return int.from_bytes(data[offset : offset + size], "little" if little else "big")


def _elf_architecture(machine: int) -> Architecture | None:
    if machine == _EM_386:
        return Architecture.X86
    if machine == _EM_X86_64:
        return Architecture.X64
    return None


def elf_preferred_base(binary: Path) -> tuple[Architecture | None, int | None]:
    """Read an ELF's architecture and preferred load base without spawning r2.

    The ELF counterpart of ``pe_preferred_base``. Android native libraries and
    Linux executables are ELF, and r2 reports their addresses at the base it
    maps them to -- the p_vaddr of the lowest PT_LOAD segment, which is 0 for
    the position-independent ``.so`` that dominates Android. Reading it lets
    ``enrich_r2_payload`` bind a module-relative rva and (for x86/x64) tag the
    architecture, exactly as it does for a PE, instead of leaving every ELF
    result a bare ``va`` with no module and no arch. Unlike PE, a base of 0 is
    the norm here rather than a sentinel: it means rva == va, so it is returned
    rather than discarded. The Architecture enum has no ARM member, so an
    arm/arm64 module keeps its base but reports no architecture.
    """
    try:
        with binary.open("rb") as stream:
            head = stream.read(_HEADER_WINDOW)
            if len(head) < 0x14 or head[:4] != _ELF_MAGIC:
                return None, None
            ei_class = head[4]
            # ELFDATA2MSB (2) is big-endian; treat everything else as little.
            little = head[5] != 2
            machine = _elf_int(head, 0x12, 2, little=little)
            architecture = _elf_architecture(machine)
            if ei_class == 2:  # ELFCLASS64
                phoff = _elf_int(head, 0x20, 8, little=little)
                phentsize = _elf_int(head, 0x36, 2, little=little)
                phnum = _elf_int(head, 0x38, 2, little=little)
                vaddr_off, vaddr_size = 0x10, 8
            elif ei_class == 1:  # ELFCLASS32
                phoff = _elf_int(head, 0x1C, 4, little=little)
                phentsize = _elf_int(head, 0x2A, 2, little=little)
                phnum = _elf_int(head, 0x2C, 2, little=little)
                vaddr_off, vaddr_size = 0x08, 4
            else:
                return architecture, None
            if phoff <= 0 or phentsize < vaddr_off + vaddr_size:
                return architecture, None
            phnum = min(phnum, _ELF_MAX_PHNUM)
            span = phoff + phnum * phentsize
            if span > _MAX_HEADER:
                return architecture, None
            if span > len(head):
                stream.seek(0)
                head = stream.read(span)
    except OSError:
        return None, None
    base: int | None = None
    for index in range(phnum):
        entry = phoff + index * phentsize
        if entry + vaddr_off + vaddr_size > len(head):
            break
        if _elf_int(head, entry, 4, little=little) != _PT_LOAD:
            continue
        p_vaddr = _elf_int(head, entry + vaddr_off, vaddr_size, little=little)
        base = p_vaddr if base is None else min(base, p_vaddr)
    return architecture, base


def preferred_base(binary: Path) -> tuple[Architecture | None, int | None]:
    """Architecture and preferred load base for a PE or ELF, or (None, None).

    ``enrich_r2_payload`` calls this to bind r2's virtual addresses to a
    module-relative rva. It dispatches on the file's magic so an ELF (an Android
    ``.so`` or a Linux binary) is enriched the same way a PE is, instead of only
    PE. A PE that parsed at all -- even one whose ImageBase came back a sentinel
    0 -- is never re-read as an ELF; the ELF path runs only when the PE reader
    found nothing.
    """
    architecture, image_base = pe_preferred_base(binary)
    if architecture is not None or image_base is not None:
        return architecture, image_base
    return elf_preferred_base(binary)


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
    detected_arch, image_base = preferred_base(binary)
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
