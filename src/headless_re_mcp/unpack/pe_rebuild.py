"""PE dump remapping and IAT rebuild (Python post-process; Scylla-inspired).

Rebuilds are explicit and report every change / unfixed item. This never claims
universal unpack success.
"""

from __future__ import annotations

import struct
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from headless_re_mcp.core.limits import PE_REBUILD_MEMORY_FACTOR

JsonObject = dict[str, Any]

_IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
_IMAGE_SCN_MEM_READ = 0x40000000
_IMAGE_SCN_MEM_WRITE = 0x80000000
_DIR_EXPORT = 0
_DIR_IMPORT = 1
_DIR_RESOURCE = 2
_DIR_EXCEPTION = 3
_DIR_SECURITY = 4
_DIR_BASERELOC = 5
_DIR_DEBUG = 6
_DIR_ARCHITECTURE = 7
_DIR_GLOBALPTR = 8
_DIR_TLS = 9
_DIR_LOAD_CONFIG = 10
_DIR_BOUND_IMPORT = 11
_DIR_IAT = 12
_DIR_DELAY_IMPORT = 13
_DIR_COM = 14


class PeRebuildError(ValueError):
    """Raised when a dump cannot be safely remapped or imports rebuilt."""


@dataclass
class RebuildReport:
    changes: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    unfixed: list[str] = field(default_factory=list)

    def to_dict(self) -> JsonObject:
        return {
            "changes": list(self.changes),
            "warnings": list(self.warnings),
            "unfixed": list(self.unfixed),
            "claims_universal_unpack": False,
        }


def _read_uint(data: bytes | bytearray, offset: int, size: int, fmt: str) -> int:
    # struct.unpack_from raises struct.error on a short/negative read, and that
    # is not a ValueError -- so it slipped past every PeRebuildError/ValueError
    # handler at the call sites and surfaced as an internal_error whose message
    # leaked the raw buffer size. The dump's own SizeOfOptionalHeader can be
    # small enough that the fixed-offset optional-header reads run off a
    # truncated image, so bound the read here and raise the module's own error,
    # the way detection/pe._slice does for the read-only parser.
    if offset < 0 or offset + size > len(data):
        raise PeRebuildError("PE structure is truncated")
    return int(struct.unpack_from(fmt, data, offset)[0])


def _u16(data: bytes | bytearray, offset: int) -> int:
    return _read_uint(data, offset, 2, "<H")


def _u32(data: bytes | bytearray, offset: int) -> int:
    return _read_uint(data, offset, 4, "<I")


def _u64(data: bytes | bytearray, offset: int) -> int:
    return _read_uint(data, offset, 8, "<Q")


# The PE specification bounds FileAlignment to a power of two between 512 and
# 64 KiB, and SectionAlignment to a power of two no smaller than it. These are
# read out of the dump, which the target wrote, and they multiply every length
# computed below: a FileAlignment of 0x40000000 rounded the headers and each
# section up to a gigabyte apiece, and the rebuild had not returned after 20
# seconds.
MAX_FILE_ALIGNMENT = 0x10000
MAX_SECTION_ALIGNMENT = 0x1000000
# The Windows loader will not map more than 96 sections. A hostile
# NumberOfSections of 0xFFFF still fits a u16 and was being used to size the
# rewritten headers and to iterate allocations. Each section is copied out of
# the dump, so the count is an allocation multiplier the same way FileAlignment
# is: a 1 MB dump claiming 400 sections rebuilt to 419 MB and peaked at 842 MB
# of heap, while the memory gate -- which only sees the dump -- estimated 4 MB
# and let it through.
MAX_SECTION_COUNT = 96
MAX_SECTIONS = MAX_SECTION_COUNT


def _usable_alignment(value: Any, *, floor: int, ceiling: int, what: str) -> int:
    """An alignment the rebuild can multiply by, or a refusal naming the field."""
    if not isinstance(value, int) or isinstance(value, bool):
        raise PeRebuildError(f"{what} is not a number")
    alignment = value
    if alignment > ceiling:
        raise PeRebuildError(
            f"{what} {alignment:#x} exceeds the {ceiling:#x} the format allows; "
            "the dump's headers are not usable for a rebuild"
        )
    if alignment > 0 and alignment & (alignment - 1):
        raise PeRebuildError(f"{what} {alignment:#x} is not a power of two")
    return max(alignment, floor)


def _align(value: int, alignment: int) -> int:
    if alignment <= 0:
        raise PeRebuildError("alignment must be positive")
    return (value + alignment - 1) // alignment * alignment


def _rva_to_file_offset(
    headers: JsonObject, rva: int, *, length: int, image: bytes | bytearray
) -> int:
    """File offset of an RVA range that already exists in the image."""
    if type(rva) is not int or rva < 0 or type(length) is not int or length <= 0:
        raise PeRebuildError("IAT range is not a usable file offset")
    for section in headers["sections"]:
        va = int(section["virtual_address"])
        raw_size = int(section["raw_size"])
        raw_offset = int(section["raw_offset"])
        if raw_size <= 0:
            continue
        if va <= rva and rva + length <= va + raw_size:
            offset = raw_offset + (rva - va)
            if offset >= 0 and offset + length <= len(image):
                return offset
    raise PeRebuildError(
        f"IAT RVA {rva:#x} size {length:#x} is not a writable file range in the dump"
    )


def parse_runtime_headers(image: bytes | bytearray) -> JsonObject:
    """Parse DOS/NT/section headers from a runtime module image or file."""
    if len(image) < 0x40 or image[:2] != b"MZ":
        raise PeRebuildError("image does not contain a valid DOS header")
    pe_offset = _u32(image, 0x3C)
    if pe_offset < 0x40 or pe_offset + 24 > len(image):
        raise PeRebuildError("PE header offset is outside the image")
    if image[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise PeRebuildError("image does not contain a valid PE signature")

    file_header = pe_offset + 4
    machine = _u16(image, file_header)
    section_count = _u16(image, file_header + 2)
    if section_count > MAX_SECTION_COUNT:
        raise PeRebuildError(
            f"NumberOfSections {section_count} exceeds the {MAX_SECTION_COUNT} "
            "the rebuild will accept; the dump's headers are not usable for a rebuild"
        )
    optional_size = _u16(image, file_header + 16)
    characteristics = _u16(image, file_header + 18)
    optional = file_header + 20
    if optional + optional_size > len(image):
        raise PeRebuildError("optional header is truncated")
    magic = _u16(image, optional)
    pe32_plus = magic == 0x20B
    if magic not in {0x10B, 0x20B}:
        raise PeRebuildError(f"unsupported optional magic: {magic:#x}")

    entry_point_rva = _u32(image, optional + 16)
    image_base = (
        _u64(image, optional + 24) if pe32_plus else _u32(image, optional + 28)
    )
    section_alignment = _u32(image, optional + 32)
    file_alignment = _u32(image, optional + 36)
    image_size = _u32(image, optional + 56)
    size_of_headers = _u32(image, optional + 60)
    subsystem = _u16(image, optional + 68)
    dll_characteristics = _u16(image, optional + 70)
    dir_count_off = optional + (108 if pe32_plus else 92)
    dir_off = optional + (112 if pe32_plus else 96)
    dir_count = min(_u32(image, dir_count_off), 16)
    directories = []
    for index in range(dir_count):
        base = dir_off + index * 8
        directories.append(
            {
                "index": index,
                "rva": _u32(image, base),
                "size": _u32(image, base + 4),
            }
        )

    sections_offset = optional + optional_size
    sections: list[JsonObject] = []
    for index in range(section_count):
        off = sections_offset + index * 40
        if off + 40 > len(image):
            raise PeRebuildError("section table is truncated")
        name = bytes(image[off : off + 8]).split(b"\0", 1)[0].decode("latin-1", "replace")
        sections.append(
            {
                "index": index,
                "name": name,
                "virtual_size": _u32(image, off + 8),
                "virtual_address": _u32(image, off + 12),
                "raw_size": _u32(image, off + 16),
                "raw_offset": _u32(image, off + 20),
                "characteristics": _u32(image, off + 36),
            }
        )

    header_end = min(len(image), max(size_of_headers, sections_offset + section_count * 40))
    return {
        "pe_offset": pe_offset,
        "machine": machine,
        "architecture": "x64" if pe32_plus else "x86",
        "characteristics": characteristics,
        "subsystem": subsystem,
        "dll_characteristics": dll_characteristics,
        "image_base": image_base,
        "image_size": image_size,
        "entry_point_rva": entry_point_rva,
        "section_alignment": section_alignment,
        "file_alignment": file_alignment,
        "size_of_headers": size_of_headers,
        "section_count": section_count,
        "directories": directories,
        "sections": sections,
        "header_bytes": header_end,
        "pointer_size": 8 if pe32_plus else 4,
    }


def remap_dump_to_file(
    dump: bytes,
    *,
    entry_point_rva: int | None = None,
) -> tuple[bytes, RebuildReport]:
    """Map a runtime SizeOfImage dump back to a PE file layout."""
    report = RebuildReport()
    headers = parse_runtime_headers(dump)
    pe_offset = int(headers["pe_offset"])
    file_alignment = _usable_alignment(
        headers["file_alignment"], floor=0x200, ceiling=MAX_FILE_ALIGNMENT, what="FileAlignment"
    )
    section_alignment = _usable_alignment(
        headers["section_alignment"],
        floor=0x1000,
        ceiling=MAX_SECTION_ALIGNMENT,
        what="SectionAlignment",
    )
    pe32_plus = headers["architecture"] == "x64"
    sections = list(headers["sections"])
    if not sections:
        raise PeRebuildError("dump has no sections to remap")
    if len(sections) > MAX_SECTION_COUNT:
        raise PeRebuildError(
            f"NumberOfSections {len(sections)} exceeds the {MAX_SECTION_COUNT} "
            "the loader accepts; the dump's headers are not usable for a rebuild"
        )

    size_of_headers = _align(
        pe_offset + 24 + _u16(dump, pe_offset + 20) + (len(sections) + 1) * 40,
        file_alignment,
    )
    # FileAlignment padding is already capped at 64 KiB. This gate is for the
    # section table copying the dump over and over: overlapping sections each
    # claim the whole image, so the count is the multiplier. Measuring the
    # padded size would also refuse a legal 64 KiB FileAlignment on a small
    # dump, which the format still allows.
    planned = pe_offset + 24 + _u16(dump, pe_offset + 20) + (len(sections) + 1) * 40
    for section in sections:
        mapped = max(int(section["virtual_size"]), int(section["raw_size"]))
        if mapped > len(dump):
            mapped = len(dump)
        planned += mapped
    limit = len(dump) * PE_REBUILD_MEMORY_FACTOR
    if planned > limit:
        raise PeRebuildError(
            f"rebuild would produce {planned} bytes from a {len(dump)}-byte dump "
            f"(more than {PE_REBUILD_MEMORY_FACTOR}x); the section table is not "
            "usable for a rebuild"
        )
    out = bytearray(dump[: min(len(dump), size_of_headers)].ljust(size_of_headers, b"\0"))
    # Ensure DOS/PE headers present even if SizeOfHeaders was truncated in dump.
    if len(dump) >= pe_offset + 4:
        out[:pe_offset] = dump[:pe_offset]
        out[pe_offset : pe_offset + 4] = dump[pe_offset : pe_offset + 4]

    file_cursor = size_of_headers
    new_sections: list[tuple[int, bytes]] = []
    for section in sections:
        va = int(section["virtual_address"])
        vsize = int(section["virtual_size"])
        mapped = max(vsize, int(section["raw_size"]))
        if mapped > len(dump):
            # The dump is the whole mapped image, so no single section inside it
            # can be larger. A header claiming otherwise is the target's own
            # number, and it was being used as an allocation size: a section
            # declaring 0x7fffffff turned a 15 KB dump into a 2 GB file.
            report.warnings.append(
                f"section {section['name']}: declares {mapped:#x} bytes, larger than the "
                f"{len(dump):#x} byte dump; truncated to the dump"
            )
            report.unfixed.append(f"section {section['name']}: declared size not trusted")
            mapped = len(dump)
        if va >= len(dump):
            report.warnings.append(
                f"section {section['name']}: virtual_address {va:#x} beyond dump"
            )
            payload = b"\0" * mapped
            report.unfixed.append(f"section {section['name']}: missing runtime bytes")
        else:
            end = min(len(dump), va + mapped)
            payload = bytes(dump[va:end]).ljust(mapped, b"\0")
        raw_size = _align(len(payload), file_alignment) if mapped else 0
        raw_offset = file_cursor if raw_size else 0
        padded = payload.ljust(raw_size, b"\0") if raw_size else b""
        new_sections.append((raw_offset, padded))
        file_cursor = raw_offset + raw_size
        report.changes.append(
            f"section {section['name']}: raw_offset={raw_offset:#x} raw_size={raw_size:#x}"
        )

    for _, padded in new_sections:
        out.extend(padded)

    # Rewrite section table + SizeOfHeaders / SizeOfImage / optional EP.
    optional_size = _u16(out, pe_offset + 20)
    sections_offset = pe_offset + 24 + optional_size
    for index, section in enumerate(sections):
        off = sections_offset + index * 40
        raw_offset, padded = new_sections[index]
        struct.pack_into("<I", out, off + 8, int(section["virtual_size"]))
        struct.pack_into("<I", out, off + 12, int(section["virtual_address"]))
        struct.pack_into("<I", out, off + 16, len(padded))
        struct.pack_into("<I", out, off + 20, raw_offset)

    opt = pe_offset + 24
    struct.pack_into("<I", out, opt + 60, size_of_headers)
    last_va = max(int(s["virtual_address"]) + max(int(s["virtual_size"]), 1) for s in sections)
    size_of_image = _align(last_va, section_alignment)
    struct.pack_into("<I", out, opt + 56, size_of_image)
    report.changes.append(f"SizeOfHeaders={size_of_headers:#x}")
    report.changes.append(f"SizeOfImage={size_of_image:#x}")

    if entry_point_rva is not None:
        if type(entry_point_rva) is not int or entry_point_rva < 0:
            raise PeRebuildError("entry_point_rva must be a non-negative integer")
        struct.pack_into("<I", out, opt + 16, entry_point_rva)
        report.changes.append(f"AddressOfEntryPoint={entry_point_rva:#x}")

    # Clear volatile directories that are usually stale after dump.
    dir_count_off = opt + (108 if pe32_plus else 92)
    dir_off = opt + (112 if pe32_plus else 96)
    dir_count = min(_u32(out, dir_count_off), 16)
    for index in (_DIR_BOUND_IMPORT, _DIR_SECURITY, _DIR_BASERELOC):
        if index < dir_count:
            base = dir_off + index * 8
            if _u32(out, base) or _u32(out, base + 4):
                struct.pack_into("<II", out, base, 0, 0)
                report.changes.append(f"cleared data directory[{index}]")

    report.unfixed.append("checksum not recalculated")
    report.unfixed.append("TLS / exception / delay-import directories not rebuilt")
    report.warnings.append("import directory may still be invalid until unpack.iat.rebuild")
    return bytes(out), report


def _encode_name(name: str) -> bytes:
    raw = name.encode("ascii", "strict") + b"\0"
    if len(raw) % 2:
        raw += b"\0"
    return raw


def rebuild_imports(
    pe_bytes: bytes,
    entries: list[JsonObject],
    *,
    iat_rva: int | None = None,
) -> tuple[bytes, RebuildReport]:
    """Append a rebuilt import directory and point the PE import directory at it."""
    report = RebuildReport()
    headers = parse_runtime_headers(pe_bytes)
    pe32_plus = headers["architecture"] == "x64"
    pointer_size = 8 if pe32_plus else 4
    ordinal_flag = 1 << (pointer_size * 8 - 1)

    by_module: dict[str, list[JsonObject]] = {}
    unresolved = 0
    for item in entries:
        if not isinstance(item, dict):
            continue
        kind = str(item.get("kind", ""))
        if kind == "null":
            continue
        if kind != "api":
            unresolved += 1
            report.unfixed.append(
                f"thunk {item.get('thunk_va', item.get('thunk_rva', '?'))}: {kind}"
            )
            continue
        module = str(item.get("module", "")).strip()
        name = str(item.get("name", "")).strip()
        ordinal = item.get("ordinal")
        if not module:
            unresolved += 1
            report.unfixed.append("api entry missing module name")
            continue
        if name.startswith("ordinal_") and (not isinstance(ordinal, int) or ordinal <= 0):
            try:
                ordinal = int(name.split("_", 1)[1])
            except (IndexError, ValueError):
                ordinal = 0
        by_module.setdefault(module.lower(), []).append(
            {
                "module": module,
                "name": name,
                "ordinal": int(ordinal) if isinstance(ordinal, int) else 0,
                "by_ordinal": bool(
                    isinstance(ordinal, int)
                    and ordinal > 0
                    and (not name or name.startswith("ordinal_"))
                ),
            }
        )

    if not by_module:
        raise PeRebuildError("no resolved API entries available for import rebuild")

    # Preserve original module casing from first sighting.
    modules: list[tuple[str, list[JsonObject]]] = []
    seen: set[str] = set()
    for item in entries:
        if not isinstance(item, dict) or str(item.get("kind")) != "api":
            continue
        key = str(item.get("module", "")).strip().lower()
        if key and key not in seen and key in by_module:
            seen.add(key)
            modules.append((str(item.get("module")), by_module[key]))

    pe_offset = int(headers["pe_offset"])
    # The same headers, read from the same untrusted image, and used the same
    # way: this one pads the appended import section. Measured before the
    # check, a FileAlignment of 0x40000000 turned a 14 KB image into a 2 GB
    # output and peaked at 5 GB of heap getting there.
    file_alignment = _usable_alignment(
        headers["file_alignment"], floor=0x200, ceiling=MAX_FILE_ALIGNMENT, what="FileAlignment"
    )
    section_alignment = _usable_alignment(
        headers["section_alignment"],
        floor=0x1000,
        ceiling=MAX_SECTION_ALIGNMENT,
        what="SectionAlignment",
    )
    out = bytearray(pe_bytes)

    # New section placed after current image virtual size.
    image_size = int(headers["image_size"])
    new_va = _align(image_size, section_alignment)
    section_name = b".himps\0\0"

    # Build import blobs: descriptors + ILT + IAT + names.
    # Layout inside new section:
    #   [descriptors][ILTs][IATs][hint/name + dll names]
    descriptor_count = len(modules) + 1  # null terminator
    descriptor_size = descriptor_count * 20

    # First pass: measure name payload and thunk counts.
    thunk_slots = 0
    name_blob = bytearray()
    name_offsets: dict[str, int] = {}
    dll_offsets: dict[str, int] = {}
    for module_name, apis in modules:
        key = module_name.lower()
        if key not in dll_offsets:
            dll_offsets[key] = len(name_blob)
            name_blob.extend(module_name.encode("ascii", "replace") + b"\0")
        for api in apis:
            thunk_slots += 1
            if api["by_ordinal"]:
                continue
            api_key = f"{key}!{api['name']}"
            if api_key in name_offsets:
                continue
            name_offsets[api_key] = len(name_blob)
            name_blob.extend(struct.pack("<H", 0))  # hint
            name_blob.extend(_encode_name(str(api["name"])))
        thunk_slots += 1  # null terminator per DLL

    ilt_size = thunk_slots * pointer_size
    iat_size = ilt_size
    placed_iat_rva = iat_rva
    in_place_iat = placed_iat_rva is not None
    iat_file_off = (
        _rva_to_file_offset(headers, placed_iat_rva, length=iat_size, image=out)
        if placed_iat_rva is not None
        else 0
    )
    # Pad name blob
    while len(name_blob) % 2:
        name_blob.append(0)
    iat_in_section = 0 if in_place_iat else iat_size
    names_off = descriptor_size + ilt_size + iat_in_section
    names_rva_base = new_va + names_off

    section_payload = bytearray(names_off + len(name_blob))

    ilt_cursor = descriptor_size
    iat_cursor = descriptor_size + ilt_size
    in_place_cursor = 0
    desc_cursor = 0
    first_iat_rva = (
        placed_iat_rva if placed_iat_rva is not None else new_va + iat_cursor
    )

    for module_name, apis in modules:
        key = module_name.lower()
        ilt_rva = new_va + ilt_cursor
        iat_rva_local = (
            placed_iat_rva + in_place_cursor
            if placed_iat_rva is not None
            else new_va + iat_cursor
        )
        name_rva = names_rva_base + dll_offsets[key]
        struct.pack_into(
            "<IIIII",
            section_payload,
            desc_cursor,
            ilt_rva,  # OriginalFirstThunk
            0,  # TimeDateStamp
            0,  # ForwarderChain
            name_rva,  # Name
            iat_rva_local,  # FirstThunk
        )
        desc_cursor += 20
        for api in apis:
            if api["by_ordinal"]:
                value = ordinal_flag | (int(api["ordinal"]) & 0xFFFF)
            else:
                api_key = f"{key}!{api['name']}"
                value = names_rva_base + name_offsets[api_key]
            if pe32_plus:
                struct.pack_into("<Q", section_payload, ilt_cursor, value)
                if in_place_iat:
                    struct.pack_into("<Q", out, iat_file_off + in_place_cursor, value)
                else:
                    struct.pack_into("<Q", section_payload, iat_cursor, value)
            else:
                struct.pack_into("<I", section_payload, ilt_cursor, value & 0xFFFFFFFF)
                if in_place_iat:
                    struct.pack_into(
                        "<I", out, iat_file_off + in_place_cursor, value & 0xFFFFFFFF
                    )
                else:
                    struct.pack_into("<I", section_payload, iat_cursor, value & 0xFFFFFFFF)
            ilt_cursor += pointer_size
            if in_place_iat:
                in_place_cursor += pointer_size
            else:
                iat_cursor += pointer_size
        # null terminator
        ilt_cursor += pointer_size
        if in_place_iat:
            in_place_cursor += pointer_size
        else:
            iat_cursor += pointer_size

    # null descriptor already zeroed. Names must sit at names_off so the
    # published Name / thunk RVAs resolve; iat_size is the on-disk IAT span and
    # is zero in-section when the IAT is patched in place.
    section_payload[names_off:] = name_blob

    raw_size = _align(len(section_payload), file_alignment)
    padded = bytes(section_payload).ljust(raw_size, b"\0")
    raw_offset = _align(len(out), file_alignment)
    if raw_offset > len(out):
        out.extend(b"\0" * (raw_offset - len(out)))
    out.extend(padded)

    # Grow section table: rewrite NumberOfSections and append entry.
    section_count = _u16(out, pe_offset + 6)
    optional_size = _u16(out, pe_offset + 20)
    sections_offset = pe_offset + 24 + optional_size
    new_section_off = sections_offset + section_count * 40
    # If headers have no room, fail closed rather than corrupting.
    size_of_headers = _u32(out, pe_offset + 24 + 60)
    if new_section_off + 40 > size_of_headers:
        raise PeRebuildError(
            "SizeOfHeaders has no room for an additional section table entry; "
            "remap dump with larger headers first"
        )

    struct.pack_into("<H", out, pe_offset + 6, section_count + 1)
    out[new_section_off : new_section_off + 8] = section_name
    struct.pack_into("<I", out, new_section_off + 8, len(section_payload))  # VirtualSize
    struct.pack_into("<I", out, new_section_off + 12, new_va)
    struct.pack_into("<I", out, new_section_off + 16, raw_size)
    struct.pack_into("<I", out, new_section_off + 20, raw_offset)
    struct.pack_into("<I", out, new_section_off + 36,
                     _IMAGE_SCN_CNT_INITIALIZED_DATA | _IMAGE_SCN_MEM_READ | _IMAGE_SCN_MEM_WRITE)

    new_image_size = _align(new_va + len(section_payload), section_alignment)
    struct.pack_into("<I", out, pe_offset + 24 + 56, new_image_size)

    # Point import + IAT directories at new section.
    pe32_plus_flag = headers["architecture"] == "x64"
    dir_off = pe_offset + 24 + (112 if pe32_plus_flag else 96)
    dir_count = len(headers["directories"])
    if dir_count < 13:
        raise PeRebuildError(
            f"NumberOfRvaAndSizes is {dir_count}; import rebuild needs at least 13"
        )
    struct.pack_into("<II", out, dir_off + _DIR_IMPORT * 8, new_va, descriptor_size)
    struct.pack_into(
        "<II",
        out,
        dir_off + _DIR_IAT * 8,
        first_iat_rva,
        iat_size,
    )
    # Clear bound import.
    struct.pack_into("<II", out, dir_off + _DIR_BOUND_IMPORT * 8, 0, 0)

    report.changes.append(f"added section .himps at RVA {new_va:#x}")
    report.changes.append(f"import directory -> RVA {new_va:#x} size {descriptor_size:#x}")
    report.changes.append(f"IAT directory -> RVA {first_iat_rva:#x} size {iat_size:#x}")
    report.changes.append(f"modules={len(modules)} unresolved_thunks={unresolved}")
    if in_place_iat:
        report.changes.append(
            f"patched IAT in-place at RVA {first_iat_rva:#x} size {iat_size:#x}"
        )
    else:
        report.unfixed.append("original IAT bytes at runtime VA are not patched in-place")
    report.unfixed.append("forwarded exports are not expanded")
    report.unfixed.append("PE checksum not recalculated")
    return bytes(out), report


def write_rebuilt_pe(path: Path, data: bytes) -> str:
    """Atomically write rebuilt PE bytes and return SHA-256 hex."""
    import hashlib

    path = path.expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    for stale in path.parent.glob(f"{path.name}*.partial"):
        with suppress(OSError):
            stale.unlink()
    partial = path.with_suffix(path.suffix + ".partial")
    try:
        partial.write_bytes(data)
        partial.replace(path)
    except BaseException:
        with suppress(OSError):
            partial.unlink(missing_ok=True)
        raise
    finally:
        with suppress(OSError):
            if partial.exists() and path.exists():
                partial.unlink()
    return hashlib.sha256(data).hexdigest()
