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


def elf_architecture(binary: Path) -> Architecture | None:
    """Read the CPU architecture from an ELF header, without spawning r2.

    The sibling :func:`pe_preferred_base` only knows PE, so an ELF -- the whole
    point of the portable Linux backend -- came back through ``enrich_r2_payload``
    with no ``architecture`` at all, even though r2 disassembled it fine and the
    machine is a fixed field in the first 20 bytes of the file. A caller reading
    x86 from x64 disassembly is reading it wrong, and the field was simply absent
    for every non-PE target.

    A prefix read, not the file, exactly like ``pe_preferred_base``: the ELF
    header's ``e_machine`` lives at offset 18. Only the two machines the
    :class:`Architecture` model can name are mapped (``EM_386`` -> x86,
    ``EM_X86_64`` -> x64); any other machine (ARM, AArch64, MIPS, RISC-V) or a
    non-ELF file yields ``None`` so the caller omits the field as it does today
    rather than guessing.
    """
    try:
        with binary.open("rb") as stream:
            head = stream.read(20)
    except OSError:
        return None
    if len(head) < 20 or head[:4] != b"\x7fELF":
        return None
    # e_ident[EI_DATA] at offset 5: 1 = little-endian, 2 = big-endian. e_machine
    # is a 2-byte field, so it has to be read in the file's own byte order.
    ei_data = head[5]
    if ei_data == 1:
        e_machine = int.from_bytes(head[18:20], "little")
    elif ei_data == 2:
        e_machine = int.from_bytes(head[18:20], "big")
    else:
        return None
    if e_machine == 3:  # EM_386
        return Architecture.X86
    if e_machine == 62:  # EM_X86_64
        return Architecture.X64
    return None


def macho_architecture(binary: Path) -> Architecture | None:
    """Read the CPU architecture from a thin Mach-O header, without spawning r2.

    r2 opens Mach-O as readily as ELF, yet :func:`enrich_r2_payload` knew only
    PE and ELF, so a Mach-O target -- an Intel-Mac sample an analyst is
    disassembling -- came back with no ``architecture`` even though r2
    disassembled it. Like the PE and ELF readers this is a prefix read: the
    Mach-O magic in the first four bytes fixes the file's word size and byte
    order, and ``cputype`` is the four bytes right after it.

    Only the two CPUs the :class:`Architecture` model can name are mapped
    (``CPU_TYPE_X86`` -> x86, ``CPU_TYPE_X86_64`` -> x64). ARM/ARM64, any other
    CPU, a fat/universal archive (whose slices share no single architecture,
    so r2 picks one and naming it here would be a guess), and a non-Mach-O file
    all yield ``None`` so the field is omitted rather than invented -- the same
    behaviour those inputs get today.
    """
    try:
        with binary.open("rb") as stream:
            head = stream.read(8)
    except OSError:
        return None
    if len(head) < 8:
        return None
    magic = head[:4]
    # Thin Mach-O only: MH_MAGIC/MH_MAGIC_64 (little-endian on disk as
    # CE/CF FA ED FE) and their byte-swapped big-endian forms. cputype follows
    # the magic and is read in the byte order the magic just established.
    if magic in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        cputype = int.from_bytes(head[4:8], "little")
    elif magic in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf"):
        cputype = int.from_bytes(head[4:8], "big")
    else:
        # 0xCAFEBABE / 0xBEBAFEED (and the 64-bit fat variants) are universal
        # archives with several slices; anything else is not Mach-O.
        return None
    if cputype == 0x00000007:  # CPU_TYPE_X86 (i386)
        return Architecture.X86
    if cputype == 0x01000007:  # CPU_TYPE_X86_64 (CPU_TYPE_X86 | CPU_ARCH_ABI64)
        return Architecture.X64
    return None


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
    # PE first (it also yields the image base for RVA), then the ELF and Mach-O
    # headers so a non-PE target still names its architecture instead of dropping
    # the field. Each reader returns None unless the magic matches, so the order
    # only decides who answers, never a misread.
    arch = architecture or pe_arch or elf_architecture(binary) or macho_architecture(binary)
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
