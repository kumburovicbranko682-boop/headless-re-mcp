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

# ELF e_machine -> Architecture, mirroring session.detect_elf_architecture. Kept
# local so this backend module stays decoupled from the session layer; both are
# small, commented tables keyed by the same well-known constants.
_ELF_MACHINE_TO_ARCH = {
    0x03: Architecture.X86,
    0x3E: Architecture.X64,
    0x28: Architecture.ARM,
    0xB7: Architecture.ARM64,
}

# Mach-O cpu_type -> Architecture and the four thin magics -> (is64, endianness),
# mirroring session.detect_macho_architecture; kept local so this backend module
# stays decoupled from the session layer, as with the ELF table above.
_MACHO_CPUTYPE_TO_ARCH = {
    0x00000007: Architecture.X86,
    0x01000007: Architecture.X64,
    0x0000000C: Architecture.ARM,
    0x0100000C: Architecture.ARM64,
}
_MACHO_MAGICS: dict[bytes, tuple[bool, Literal["big", "little"]]] = {
    b"\xcf\xfa\xed\xfe": (True, "little"),
    b"\xce\xfa\xed\xfe": (False, "little"),
    b"\xfe\xed\xfa\xcf": (True, "big"),
    b"\xfe\xed\xfa\xce": (False, "big"),
}
_MACHO_LC_SEGMENT = 0x01
_MACHO_LC_SEGMENT_64 = 0x19
# Fat/universal magics -> 64-bit table entries, mirroring session._FAT_MAGICS.
# Only consulted when a caller explicitly selects a slice: the 0xCAFEBABE
# collision with Java class files is harmless here because a Java file has no
# slice whose cputype maps onto the requested Architecture, so the scan below
# simply finds nothing and the addresses stay va-only.
_FAT_MAGICS: dict[bytes, bool] = {
    b"\xca\xfe\xba\xbe": False,
    b"\xca\xfe\xba\xbf": True,
}
_FAT_MAX_ARCHS = 32


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


def elf_preferred_base(binary: Path) -> tuple[Architecture | None, int | None]:
    """Read an ELF's load base and architecture without spawning r2.

    The ELF counterpart of ``pe_preferred_base``: the load base is the lowest
    ``p_vaddr`` among the ``PT_LOAD`` segments, which matches radare2's own
    ``$B`` for both ET_EXEC (e.g. 0x400000) and PIE ET_DYN (0), so ``va - base``
    yields an rva consistent with the addresses r2 reports. Returns
    ``(architecture, base)`` -- either may be None: a machine the enum cannot
    name still yields its base, and a header too short or corrupt to trust
    yields no base (addresses stay va-only) rather than a wrong one.
    """
    try:
        with binary.open("rb") as stream:
            ident = stream.read(64)
            if len(ident) < 64 or ident[:4] != b"\x7fELF":
                return None, None
            is64 = ident[4] == 2
            endian: Literal["big", "little"] = "big" if ident[5] == 2 else "little"
            machine = int.from_bytes(ident[18:20], endian)
            arch = _ELF_MACHINE_TO_ARCH.get(machine)
            if is64:
                e_phoff = int.from_bytes(ident[0x20:0x28], endian)
                e_phentsize = int.from_bytes(ident[0x36:0x38], endian)
                e_phnum = int.from_bytes(ident[0x38:0x3A], endian)
                vaddr_off, vaddr_size = 16, 8
            else:
                e_phoff = int.from_bytes(ident[0x1C:0x20], endian)
                e_phentsize = int.from_bytes(ident[0x2A:0x2C], endian)
                e_phnum = int.from_bytes(ident[0x2C:0x2E], endian)
                vaddr_off, vaddr_size = 8, 4
            min_entry = vaddr_off + vaddr_size
            if e_phoff <= 0 or e_phentsize < min_entry or not 0 < e_phnum <= 4096:
                return arch, None
            table_size = e_phentsize * e_phnum
            if table_size > _MAX_HEADER:
                return arch, None
            stream.seek(e_phoff)
            table = stream.read(table_size)
    except OSError:
        return None, None
    if len(table) < table_size:
        return arch, None
    base: int | None = None
    for index in range(e_phnum):
        off = index * e_phentsize
        p_type = int.from_bytes(table[off : off + 4], endian)
        if p_type != 1:  # PT_LOAD
            continue
        vaddr = int.from_bytes(table[off + vaddr_off : off + vaddr_off + vaddr_size], endian)
        base = vaddr if base is None else min(base, vaddr)
    return arch, base


def macho_preferred_base(
    binary: Path, *, select: Architecture | None = None
) -> tuple[Architecture | None, int | None]:
    """Read a Mach-O's load base and architecture without spawning r2.

    The Mach-O counterpart of ``pe_preferred_base``/``elf_preferred_base``: the
    load base is the vmaddr of the segment that maps the mach header (fileoff 0,
    non-empty, and not ``__PAGEZERO``), which matches radare2's ``$B`` -- verified
    0x100000000 for a standard 64-bit executable, and 0 for a PIE image -- so
    ``va - base`` yields an rva consistent with the addresses r2 reports.
    ``__PAGEZERO`` sits at vmaddr 0 and would otherwise drag the base to 0, so it
    is skipped.

    A fat/universal (0xCAFEBABE) binary has no single base until an architecture
    is picked, and which slice r2 picks by default depends on the host, so with
    no ``select`` a fat file yields ``(None, None)`` and addresses stay va-only.
    When the caller *has* directed r2 at a slice (``-a``/``-b``), passing that
    slice's ``Architecture`` as ``select`` resolves the fat table, parses the
    matching slice's own thin header, and returns its base -- verified to equal
    the ``baddr`` r2 reports for the same selection. ``select`` is ignored for a
    thin file, which has only its own architecture. Either half of the returned
    pair may be None.
    """
    try:
        with binary.open("rb") as stream:
            magic = stream.read(4)
            if magic in _MACHO_MAGICS:
                return _thin_macho_base(stream, 0)
            fat_is64 = _FAT_MAGICS.get(magic)
            if fat_is64 is None or select is None:
                return None, None
            span = _fat_slice_span(stream, fat_is64, select)
            if span is None:
                return None, None
            return _thin_macho_base(stream, span[0])
    except OSError:
        return None, None


def macho_slice_span(binary: Path, select: Architecture) -> tuple[int, int] | None:
    """(file offset, byte size) of the ``select`` slice inside a fat Mach-O.

    None when the file is not fat/universal, its table is malformed, or no
    slice's cputype maps to ``select``. This is the carve primitive for an
    engine with no native slice flag (Ghidra's headless importer offers no
    load spec for a fat file at all): the ``size`` bytes at ``offset`` are a
    complete thin Mach-O of that architecture, importable on its own.
    """
    try:
        with binary.open("rb") as stream:
            fat_is64 = _FAT_MAGICS.get(stream.read(4))
            if fat_is64 is None:
                return None
            return _fat_slice_span(stream, fat_is64, select)
    except OSError:
        return None


def _fat_slice_span(
    stream: Any, fat_is64: bool, select: Architecture
) -> tuple[int, int] | None:
    """(offset, size) of the fat table entry whose cputype maps to ``select``.

    The stream is positioned just past the magic. fat_arch entries are
    big-endian: cputype, cpusubtype, then offset and size (32-bit, or 64-bit
    under FAT_MAGIC_64), then align.
    """
    nfat = int.from_bytes(stream.read(4), "big")
    if not 1 <= nfat <= _FAT_MAX_ARCHS:
        return None
    entry_size = 32 if fat_is64 else 20
    table = stream.read(entry_size * nfat)
    if len(table) < entry_size * nfat:
        return None
    word = 8 if fat_is64 else 4
    for index in range(nfat):
        entry = table[index * entry_size :]
        cputype = int.from_bytes(entry[0:4], "big")
        if _MACHO_CPUTYPE_TO_ARCH.get(cputype) is not select:
            continue
        offset = int.from_bytes(entry[8 : 8 + word], "big")
        size = int.from_bytes(entry[8 + word : 8 + 2 * word], "big")
        return offset, size
    return None


def _thin_macho_base(stream: Any, header_offset: int) -> tuple[Architecture | None, int | None]:
    """(architecture, base) of the thin Mach-O whose header starts at ``header_offset``.

    Works for a whole thin file (offset 0) and for a slice inside a fat file:
    segment ``vmaddr`` is an absolute virtual address either way, and ``fileoff``
    is relative to the slice's own start, so the fileoff==0 header-segment test
    holds unchanged.
    """
    stream.seek(header_offset)
    head = stream.read(32)
    order = _MACHO_MAGICS.get(head[:4])
    if order is None or len(head) < 24:
        return None, None
    is64, endian = order
    arch = _MACHO_CPUTYPE_TO_ARCH.get(int.from_bytes(head[4:8], endian))
    ncmds = int.from_bytes(head[16:20], endian)
    sizeofcmds = int.from_bytes(head[20:24], endian)
    if ncmds <= 0 or not 0 < sizeofcmds <= _MAX_HEADER:
        return arch, None
    stream.seek(header_offset + (32 if is64 else 28))
    commands = stream.read(sizeofcmds)
    if len(commands) < sizeofcmds:
        return arch, None
    seg_cmd = _MACHO_LC_SEGMENT_64 if is64 else _MACHO_LC_SEGMENT
    vaddr_size = 8 if is64 else 4
    vmaddr_off = 24  # cmd(4) + cmdsize(4) + segname(16)
    fileoff_off = vmaddr_off + 2 * vaddr_size  # past vmaddr + vmsize
    header_base: int | None = None
    min_base: int | None = None
    offset = 0
    for _ in range(ncmds):
        if offset + 8 > len(commands):
            break
        cmd = int.from_bytes(commands[offset : offset + 4], endian)
        cmdsize = int.from_bytes(commands[offset + 4 : offset + 8], endian)
        if cmdsize <= 0 or offset + cmdsize > len(commands):
            break
        if cmd == seg_cmd and cmdsize >= fileoff_off + 2 * vaddr_size:
            segname = commands[offset + 8 : offset + 24].split(b"\x00", 1)[0]
            vmaddr = int.from_bytes(
                commands[offset + vmaddr_off : offset + vmaddr_off + vaddr_size], endian
            )
            fileoff = int.from_bytes(
                commands[offset + fileoff_off : offset + fileoff_off + vaddr_size], endian
            )
            filesize = int.from_bytes(
                commands[
                    offset + fileoff_off + vaddr_size : offset + fileoff_off + 2 * vaddr_size
                ],
                endian,
            )
            if segname != b"__PAGEZERO" and filesize > 0:
                min_base = vmaddr if min_base is None else min(min_base, vmaddr)
                if fileoff == 0:
                    header_base = vmaddr if header_base is None else min(header_base, vmaddr)
        offset += cmdsize
    return arch, header_base if header_base is not None else min_base


def preferred_base(
    binary: Path, *, select: Architecture | None = None
) -> tuple[Architecture | None, int | None]:
    """Best-effort (architecture, load base) for a local binary.

    Tries each supported container in turn: a PE parse that named neither an
    arch nor a base is not a PE, so fall through to ELF, then to Mach-O. The
    first container that recognises the header wins -- a recognised binary whose
    base is merely unresolvable (e.g. an arch the enum cannot name) stops the
    chain rather than being reparsed as another format. Both halves may be None
    for an unknown container.

    ``select`` names the slice of a fat Mach-O the caller directed the engine
    at (see ``macho_preferred_base``); it is meaningless for the single-arch
    containers and ignored by them.
    """
    arch, base = pe_preferred_base(binary)
    if arch is not None or base is not None:
        return arch, base
    arch, base = elf_preferred_base(binary)
    if arch is not None or base is not None:
        return arch, base
    return macho_preferred_base(binary, select=select)


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
    slice_arch: Architecture | None = None,
) -> JsonObject:
    """Parse *j payloads into items with unified Address fields.

    ``slice_arch`` names the fat Mach-O slice the r2 invocation was directed at
    (``-a``/``-b``); it selects that slice's base and architecture so the
    payload's coordinates describe the slice r2 actually analysed. Leave it
    None for everything else -- single-arch binaries ignore it and an
    unselected fat stays va-only.
    """
    module = binary.name
    # PE, then ELF, then Mach-O: a non-PE binary still gains rva/module/arch
    # instead of staying va-only, and the first container to recognise the
    # header wins (see preferred_base).
    detected_arch, image_base = preferred_base(binary, select=slice_arch)
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
                ("offset", "vaddr", "addr", "from", "to", "ref", "at", "plt", "paddr"),
            )
            mapped = address_dict(va, module=module, image_base=image_base, architecture=arch)
            if mapped is not None:
                item["address"] = mapped
            # Named endpoints for xrefs. axj/axtj phrase edges as from/to; axffj
            # (references *from* a function) phrases them as at (the referencing
            # site) and ref (the target), so both vocabularies are mapped.
            for edge_key in ("from", "to", "at", "ref"):
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
