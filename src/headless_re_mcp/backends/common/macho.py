"""Pure-stdlib structural reader for a Mach-O binary (macOS / iOS executable).

With PE covered by a whole tool line and ELF by elf.summary/elf.symbols, Mach-O
was the one first-class native format that still required an external backend to
open. A macOS dylib, an iOS app's main binary or a Mach-O malware sample is an
exact, well-documented structure -- a header plus a flat list of load commands --
so summarize_macho reads it with the stdlib alone: the CPU/filetype/flags from
the header; the segments (name, addresses, sizes, protection) from
LC_SEGMENT(_64); the linked dylibs, install name and run-time search paths from
the dylib/rpath commands; the UUID, the entry point offset, the target platform
and minimum OS from the version commands; and the triage booleans an analyst
wants first -- pie, signed (LC_CODE_SIGNATURE), encrypted (LC_ENCRYPTION_INFO
cryptid, the iOS store-encryption flag) and stripped (LC_SYMTAB).
list_macho_symbols walks the LC_SYMTAB nlist array -- the import/export surface
-- naming each symbol, saying whether it is imported (an undefined external,
resolved to the dylib its library ordinal names) or exported (a defined
external), and skipping debug stabs. read_macho_signature decodes the
LC_CODE_SIGNATURE SuperBlob -- the CodeDirectory's signing identifier, team ID,
flags (adhoc / hardened runtime / linker-signed) and cdhash, plus the
entitlements plist -- the ``codesign -dvv`` view, offline.

Universal ("fat") binaries are handled too: each architecture slice is listed
with its CPU/offset/size and summarized in place, bounded by a slice cap. Both
Mach-O classes (32- and 64-bit) and both byte orders parse. The header walk is
exact; the load commands are followed defensively -- a command that leaves the
file or lies about its size contributes a warning, not an exception -- and every
name, list and count is bounded. The 0xcafebabe magic is shared with Java class
files, so an implausible fat-arch count is refused with a message saying so.
"""

from __future__ import annotations

import hashlib
import plistlib
import struct
from typing import Any

JsonObject = dict[str, Any]

_MAX_NAME = 256
_MAX_CMDS = 2048
_MAX_SEGMENTS = 128
_MAX_DYLIBS = 512
_MAX_RPATHS = 64
_MAX_SLICES = 16
_MAX_WARNINGS = 32

# Raw first-four-bytes forms of the thin magics (the value is stored in the
# target's byte order, so the file starts with one of these exact sequences).
_THIN_MAGICS = {
    b"\xcf\xfa\xed\xfe": (64, "<", "little"),
    b"\xce\xfa\xed\xfe": (32, "<", "little"),
    b"\xfe\xed\xfa\xcf": (64, ">", "big"),
    b"\xfe\xed\xfa\xce": (32, ">", "big"),
}
_FAT_MAGIC_32 = b"\xca\xfe\xba\xbe"
_FAT_MAGIC_64 = b"\xca\xfe\xba\xbf"

_CPU = {
    7: "x86",
    0x01000007: "x86-64",
    12: "ARM",
    0x0100000C: "AArch64",
    0x0200000C: "arm64_32",
    18: "PowerPC",
    0x01000012: "PowerPC64",
}

_FILETYPE = {
    1: "object",
    2: "executable",
    3: "fixed VM library",
    4: "core dump",
    5: "preloaded executable",
    6: "dylib",
    7: "dynamic linker",
    8: "bundle",
    9: "dylib stub",
    10: "dsym companion",
    11: "kext bundle",
}

_PLATFORM = {
    1: "macOS",
    2: "iOS",
    3: "tvOS",
    4: "watchOS",
    5: "bridgeOS",
    6: "Mac Catalyst",
    7: "iOS Simulator",
    8: "tvOS Simulator",
    9: "watchOS Simulator",
    10: "DriverKit",
    11: "visionOS",
    12: "visionOS Simulator",
}

# Load commands this reader acts on.
_LC_SEGMENT = 0x1
_LC_SYMTAB = 0x2
_LC_LOAD_DYLIB = 0xC
_LC_ID_DYLIB = 0xD
_LC_SEGMENT_64 = 0x19
_LC_UUID = 0x1B
_LC_CODE_SIGNATURE = 0x1D
_LC_LAZY_LOAD_DYLIB = 0x20
_LC_ENCRYPTION_INFO = 0x21
_LC_VERSION_MIN_MACOSX = 0x24
_LC_VERSION_MIN_IPHONEOS = 0x25
_LC_ENCRYPTION_INFO_64 = 0x2C
_LC_VERSION_MIN_TVOS = 0x2F
_LC_VERSION_MIN_WATCHOS = 0x30
_LC_BUILD_VERSION = 0x32
_LC_LOAD_WEAK_DYLIB = 0x80000018
_LC_RPATH = 0x8000001C
_LC_REEXPORT_DYLIB = 0x8000001F
_LC_LOAD_UPWARD_DYLIB = 0x80000023
_LC_MAIN = 0x80000028

_DYLIB_COMMANDS = frozenset(
    (
        _LC_LOAD_DYLIB,
        _LC_LOAD_WEAK_DYLIB,
        _LC_REEXPORT_DYLIB,
        _LC_LAZY_LOAD_DYLIB,
        _LC_LOAD_UPWARD_DYLIB,
    )
)
_VERSION_MIN_COMMANDS = {
    _LC_VERSION_MIN_MACOSX: "macOS",
    _LC_VERSION_MIN_IPHONEOS: "iOS",
    _LC_VERSION_MIN_TVOS: "tvOS",
    _LC_VERSION_MIN_WATCHOS: "watchOS",
}

_MH_PIE = 0x200000

_MAX_SYMBOL_PAGE = 1000

# nlist n_type field: a stab mask, an external bit, a private-external bit and a
# 3-bit type nested in the low nibble.
_N_STAB = 0xE0
_N_PEXT = 0x10
_N_TYPE = 0x0E
_N_EXT = 0x01
_N_UNDF = 0x0
_N_ABS = 0x2
_N_SECT = 0xE
_N_PBUD = 0xC
_N_INDR = 0xA
_NTYPE_NAME = {
    _N_UNDF: "undefined",
    _N_ABS: "absolute",
    _N_SECT: "section",
    _N_PBUD: "prebound",
    _N_INDR: "indirect",
}

# Special two-level-namespace library ordinals stored in the high byte of n_desc
# for an undefined external symbol; anything else is a 1-based index into the
# ordered dylib dependency list.
_SPECIAL_ORDINALS = {0x0: "self", 0xFE: "dynamic_lookup", 0xFF: "executable"}

# Code-signature blob magics and superblob slot indices (cs_blobs.h). All the
# fields inside the signature region are big-endian regardless of the image.
_CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
_CSMAGIC_CODEDIRECTORY = 0xFADE0C02
_CSMAGIC_REQUIREMENTS = 0xFADE0C01
_CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xFADE7171
_CSMAGIC_EMBEDDED_DER_ENTITLEMENTS = 0xFADE7172
_CSMAGIC_BLOBWRAPPER = 0xFADE0B01

_CSSLOT_CODEDIRECTORY = 0
_CSSLOT_REQUIREMENTS = 2
_CSSLOT_ENTITLEMENTS = 5
_CSSLOT_DER_ENTITLEMENTS = 7
_CSSLOT_ALTERNATE_CD_FIRST = 0x1000
_CSSLOT_ALTERNATE_CD_LAST = 0x1005
_CSSLOT_CMS_SIGNATURE = 0x10000
_CSSLOT_NAME = {
    0: "code_directory",
    1: "info",
    2: "requirements",
    3: "resource_dir",
    4: "application",
    5: "entitlements",
    6: "rep_specific",
    7: "der_entitlements",
    0x10000: "cms_signature",
}

_CD_FLAG_BITS = (
    (0x2, "ADHOC"),
    (0x100, "HARD"),
    (0x200, "KILL"),
    (0x800, "RESTRICT"),
    (0x1000, "ENFORCEMENT"),
    (0x2000, "LIBRARY_VALIDATION"),
    (0x10000, "RUNTIME"),
    (0x20000, "LINKER_SIGNED"),
)
_CS_ADHOC = 0x2
_CS_RUNTIME = 0x10000
_CS_LINKER_SIGNED = 0x20000

_CD_HASH_TYPE = {1: "sha1", 2: "sha256", 3: "sha256_truncated", 4: "sha384"}
_CDHASH_LEN = 20  # Apple truncates every cdhash to 20 bytes.

_MAX_SIG_SLOTS = 64
_MAX_ENTITLEMENT_KEYS = 128
_MAX_ENTITLEMENT_DEPTH = 4


class MachoParseError(ValueError):
    """Bytes that are not a Mach-O binary.

    A ValueError subclass so a caller that funnels ValueError into an
    ``invalid_request`` envelope keeps working, while one that wants the more
    precise ``invalid_params`` can catch this type by name. Raised only for the
    header (thin or fat); a bad load command is a warning, not a failure.
    """


def _version_triple(value: int) -> str:
    return f"{(value >> 16) & 0xFFFF}.{(value >> 8) & 0xFF}.{value & 0xFF}"


def _prot_letters(prot: int) -> str:
    return ("r" if prot & 1 else "-") + ("w" if prot & 2 else "-") + ("x" if prot & 4 else "-")


def _lc_string(data: bytes, cmd_start: int, cmd_end: int, str_offset: int) -> str:
    """An lc_str: NUL-terminated text at cmd_start+str_offset, inside the command."""
    begin = cmd_start + str_offset
    limit = min(cmd_end, len(data))
    if str_offset < 8 or begin >= limit:
        return ""
    end = data.find(b"\x00", begin, limit)
    raw = data[begin : end if end != -1 else limit]
    return raw.decode("utf-8", errors="replace")[:_MAX_NAME]


def _summarize_thin(data: bytes) -> JsonObject:
    """Summary of one thin Mach-O image (a whole file or one fat slice)."""
    magic = data[:4]
    if magic not in _THIN_MAGICS:
        raise MachoParseError("not a Mach-O image: unknown magic")
    bits, endian, endian_name = _THIN_MAGICS[magic]
    hdr_size = 32 if bits == 64 else 28
    if len(data) < hdr_size:
        raise MachoParseError("truncated Mach-O header")
    cputype, _cpusubtype, filetype, ncmds, sizeofcmds, flags = struct.unpack_from(
        endian + "iiIIII", data, 4
    )

    warnings: list[str] = []

    def warn(message: str) -> None:
        if len(warnings) < _MAX_WARNINGS:
            warnings.append(message)

    segments: list[JsonObject] = []
    dylibs: list[str] = []
    rpaths: list[str] = []
    id_dylib: str | None = None
    uuid: str | None = None
    entry_offset: int | None = None
    platform: JsonObject | None = None
    symbol_count: int | None = None
    signed = False
    encrypted = False

    if ncmds > _MAX_CMDS:
        warn(f"load command count {ncmds} exceeds cap; walk truncated")
    offset = hdr_size
    command_span = hdr_size + sizeofcmds
    for index in range(min(ncmds, _MAX_CMDS)):
        if offset + 8 > len(data):
            warn(f"load command {index} is past end of file")
            break
        cmd, cmdsize = struct.unpack_from(endian + "II", data, offset)
        if cmdsize < 8:
            warn(f"load command {index} has impossible size {cmdsize}")
            break
        cmd_end = offset + cmdsize
        if cmd_end > len(data):
            warn(f"load command {index} extends past end of file")
            break

        # cmd_end <= len(data) holds here, so "the command's fixed part fits"
        # reduces to a size check against cmdsize alone.
        if cmd in (_LC_SEGMENT, _LC_SEGMENT_64):
            is64 = cmd == _LC_SEGMENT_64
            fmt = endian + ("16sQQQQiiII" if is64 else "16sIIIIiiII")
            if cmdsize >= 8 + struct.calcsize(fmt):
                fields = struct.unpack_from(fmt, data, offset + 8)
                segname = fields[0].rstrip(b"\x00").decode("utf-8", errors="replace")
                vmaddr, vmsize, fileoff, filesize = fields[1], fields[2], fields[3], fields[4]
                initprot, nsects = fields[6], fields[7]
                if len(segments) < _MAX_SEGMENTS:
                    segments.append(
                        {
                            "name": segname[:_MAX_NAME],
                            "vmaddr": f"0x{vmaddr:x}",
                            "vmsize": vmsize,
                            "fileoff": fileoff,
                            "filesize": filesize,
                            "prot": _prot_letters(initprot),
                            "sections": nsects,
                        }
                    )
            else:
                warn(f"segment command {index} is truncated")
        elif cmd in _DYLIB_COMMANDS or cmd == _LC_ID_DYLIB:
            if cmdsize >= 12:
                (str_offset,) = struct.unpack_from(endian + "I", data, offset + 8)
                name = _lc_string(data, offset, cmd_end, str_offset)
                if cmd == _LC_ID_DYLIB:
                    id_dylib = name
                elif len(dylibs) < _MAX_DYLIBS:
                    dylibs.append(name)
        elif cmd == _LC_RPATH:
            if cmdsize >= 12:
                (str_offset,) = struct.unpack_from(endian + "I", data, offset + 8)
                if len(rpaths) < _MAX_RPATHS:
                    rpaths.append(_lc_string(data, offset, cmd_end, str_offset))
        elif cmd == _LC_UUID:
            if cmdsize >= 24:
                uuid = data[offset + 8 : offset + 24].hex()
        elif cmd == _LC_MAIN:
            if cmdsize >= 24:
                (entryoff,) = struct.unpack_from(endian + "Q", data, offset + 8)
                entry_offset = entryoff
        elif cmd == _LC_SYMTAB:
            if cmdsize >= 24:
                _symoff, nsyms, _stroff, _strsize = struct.unpack_from(
                    endian + "IIII", data, offset + 8
                )
                symbol_count = nsyms
        elif cmd == _LC_CODE_SIGNATURE:
            signed = True
        elif cmd in (_LC_ENCRYPTION_INFO, _LC_ENCRYPTION_INFO_64):
            if cmdsize >= 20:
                _cryptoff, _cryptsize, cryptid = struct.unpack_from(
                    endian + "III", data, offset + 8
                )
                encrypted = cryptid != 0
        elif cmd == _LC_BUILD_VERSION:
            if cmdsize >= 24:
                platform_id, minos, sdk, _ntools = struct.unpack_from(
                    endian + "IIII", data, offset + 8
                )
                platform = {
                    "name": _PLATFORM.get(platform_id, f"0x{platform_id:x}"),
                    "min_os": _version_triple(minos),
                    "sdk": _version_triple(sdk),
                }
        elif cmd in _VERSION_MIN_COMMANDS:
            if cmdsize >= 16:
                version, sdk = struct.unpack_from(endian + "II", data, offset + 8)
                platform = {
                    "name": _VERSION_MIN_COMMANDS[cmd],
                    "min_os": _version_triple(version),
                    "sdk": _version_triple(sdk),
                }
        offset = cmd_end
    if offset > command_span and command_span >= hdr_size:
        warn("load commands overran the header's sizeofcmds")

    return {
        "format": "Mach-O",
        "fat": False,
        "bits": bits,
        "endianness": endian_name,
        "cpu": _CPU.get(cputype, f"0x{cputype:x}"),
        "cpu_raw": cputype,
        "filetype": _FILETYPE.get(filetype, f"0x{filetype:x}"),
        "filetype_raw": filetype,
        "flags": f"0x{flags:x}",
        "pie": bool(flags & _MH_PIE),
        "ncmds": ncmds,
        "segments": segments,
        "dylibs": dylibs,
        "id_dylib": id_dylib,
        "rpaths": rpaths,
        "uuid": uuid,
        "entry_offset": entry_offset,
        "platform": platform,
        "symbol_count": symbol_count,
        "stripped": not symbol_count,
        "signed": signed,
        "encrypted": encrypted,
        "warnings": warnings,
    }


def _summarize_fat(data: bytes) -> JsonObject:
    """Summary of a universal binary: each architecture slice, parsed in place."""
    is64 = data[:4] == _FAT_MAGIC_64
    (nfat_arch,) = struct.unpack_from(">I", data, 4)
    if nfat_arch == 0:
        raise MachoParseError("fat binary with no architecture slices")
    if nfat_arch > _MAX_SLICES:
        raise MachoParseError(
            f"implausible fat arch count {nfat_arch}"
            " (a Java class file shares the 0xcafebabe magic)"
        )

    warnings: list[str] = []
    arch_fmt = ">iiQQII" if is64 else ">iiIII"
    arch_size = struct.calcsize(arch_fmt)
    slices: list[JsonObject] = []
    for index in range(nfat_arch):
        base = 8 + index * arch_size
        if base + arch_size > len(data):
            if len(warnings) < _MAX_WARNINGS:
                warnings.append(f"fat arch record {index} is past end of file")
            break
        fields = struct.unpack_from(arch_fmt, data, base)
        cputype, offset, size = fields[0], fields[2], fields[3]
        entry: JsonObject = {
            "cpu": _CPU.get(cputype, f"0x{cputype:x}"),
            "cpu_raw": cputype,
            "offset": offset,
            "size": size,
        }
        if offset < 0 or size < 0 or offset + size > len(data):
            entry["error"] = "slice extends past end of file"
        else:
            try:
                entry["summary"] = _summarize_thin(data[offset : offset + size])
            except MachoParseError as exc:
                entry["error"] = str(exc)
        slices.append(entry)

    return {
        "format": "Mach-O",
        "fat": True,
        "slice_count": len(slices),
        "slices": slices,
        "warnings": warnings,
    }


def summarize_macho(data: bytes) -> JsonObject:
    """Structural summary of a Mach-O binary, thin or universal.

    Raises MachoParseError when the bytes are not a Mach-O (unknown magic, a
    header that does not fit, or a 0xcafebabe file whose arch count says Java
    class rather than fat binary). A thin image answers with the header fields,
    segments, linked dylibs, rpaths, uuid, entry point, target platform and the
    pie/signed/encrypted/stripped booleans; a fat binary answers with one such
    summary per architecture slice. Bad load commands or slice records yield
    warnings and are skipped, never an exception.
    """
    if len(data) < 8:
        raise MachoParseError("not a Mach-O file: too short for any header")
    magic = data[:4]
    if magic in _THIN_MAGICS:
        return _summarize_thin(data)
    if magic in (_FAT_MAGIC_32, _FAT_MAGIC_64):
        return _summarize_fat(data)
    raise MachoParseError("not a Mach-O file: unknown magic")


def _symbol_name(strtab: bytes, strx: int) -> str:
    """A NUL-terminated symbol name at ``strx`` in a string table, bounded/safe."""
    if strx <= 0 or strx >= len(strtab):
        return ""
    end = strtab.find(b"\x00", strx)
    raw = strtab[strx : end if end != -1 else len(strtab)]
    return raw.decode("utf-8", errors="replace")[:_MAX_NAME]


def _find_symtab_and_dylibs(data: bytes, endian: str, hdr_size: int, ncmds: int) -> JsonObject:
    """Walk the load commands once for LC_SYMTAB and the ordered dylib names.

    Returns the four LC_SYMTAB fields (or None when absent) and the dependency
    list in link order, so an undefined symbol's library ordinal can be named.
    Bounds are followed defensively; a bad command stops the walk with a warning.
    """
    warnings: list[str] = []
    symtab: tuple[int, int, int, int] | None = None
    dylibs: list[str] = []
    offset = hdr_size
    for index in range(min(ncmds, _MAX_CMDS)):
        if offset + 8 > len(data):
            warnings.append(f"load command {index} is past end of file")
            break
        cmd, cmdsize = struct.unpack_from(endian + "II", data, offset)
        if cmdsize < 8 or offset + cmdsize > len(data):
            warnings.append(f"load command {index} has a bad size")
            break
        cmd_end = offset + cmdsize
        if cmd == _LC_SYMTAB and cmdsize >= 24:
            symoff, nsyms, stroff, strsize = struct.unpack_from(endian + "IIII", data, offset + 8)
            symtab = (symoff, nsyms, stroff, strsize)
        elif cmd in _DYLIB_COMMANDS and cmdsize >= 12:
            (str_offset,) = struct.unpack_from(endian + "I", data, offset + 8)
            if len(dylibs) < _MAX_DYLIBS:
                dylibs.append(_lc_string(data, offset, cmd_end, str_offset))
        offset = cmd_end
    return {"symtab": symtab, "dylibs": dylibs, "warnings": warnings}


def _list_thin_symbols(data: bytes, *, offset: int, limit: int, extra: JsonObject) -> JsonObject:
    """One page of a thin image's LC_SYMTAB symbols, classified import/export."""
    magic = data[:4]
    if magic not in _THIN_MAGICS:
        raise MachoParseError("not a Mach-O image: unknown magic")
    bits, endian, endian_name = _THIN_MAGICS[magic]
    hdr_size = 32 if bits == 64 else 28
    if len(data) < hdr_size:
        raise MachoParseError("truncated Mach-O header")
    cputype, _cpusubtype, _filetype, ncmds, _sizeofcmds, _flags = struct.unpack_from(
        endian + "iiIIII", data, 4
    )

    found = _find_symtab_and_dylibs(data, endian, hdr_size, ncmds)
    warnings: list[str] = list(found["warnings"])[:_MAX_WARNINGS]

    def warn(message: str) -> None:
        if len(warnings) < _MAX_WARNINGS:
            warnings.append(message)

    dylibs: list[str] = found["dylibs"]
    start = max(0, int(offset))
    window = max(1, min(int(limit), _MAX_SYMBOL_PAGE))

    total = 0
    symbols: list[JsonObject] = []
    symtab = found["symtab"]
    if symtab is None:
        warn("no LC_SYMTAB: statically stripped, or a symbol-less image")
    else:
        symoff, nsyms, stroff, strsize = symtab
        total = nsyms
        strtab = b""
        if 0 <= stroff <= stroff + strsize <= len(data):
            strtab = data[stroff : stroff + strsize]
        else:
            warn("string table is past end of file; names unavailable")
        nl_size = 16 if bits == 64 else 12
        # n_desc is read unsigned in both classes: it is a bitfield container,
        # and the library ordinal lives in its high byte.
        nl_fmt = endian + ("IBBHQ" if bits == 64 else "IBBHI")
        for index in range(start, min(total, start + window)):
            eoff = symoff + index * nl_size
            if eoff < 0 or eoff + nl_size > len(data):
                warn(f"symbol {index} is past end of file")
                break
            n_strx, n_type, _n_sect, n_desc, n_value = struct.unpack_from(nl_fmt, data, eoff)
            name = _symbol_name(strtab, n_strx)
            is_stab = bool(n_type & _N_STAB)
            external = bool(n_type & _N_EXT) and not is_stab
            ntype = n_type & _N_TYPE
            defined = ntype in (_N_SECT, _N_ABS, _N_INDR)
            imported = external and ntype == _N_UNDF and bool(name)
            exported = external and defined and bool(name)
            entry: JsonObject = {
                "name": name,
                "type": "debug" if is_stab else _NTYPE_NAME.get(ntype, f"0x{ntype:x}"),
                "external": external,
                "value": f"0x{n_value:x}",
                "imported": imported,
                "exported": exported,
            }
            if imported:
                ordinal = (n_desc >> 8) & 0xFF
                entry["library_ordinal"] = ordinal
                if ordinal in _SPECIAL_ORDINALS:
                    entry["library"] = _SPECIAL_ORDINALS[ordinal]
                elif 1 <= ordinal <= len(dylibs):
                    entry["library"] = dylibs[ordinal - 1]
            symbols.append(entry)

    result: JsonObject = {
        "format": "Mach-O",
        "bits": bits,
        "endianness": endian_name,
        "cpu": _CPU.get(cputype, f"0x{cputype:x}"),
        "symbols": symbols,
        "symbols_listed": len(symbols),
        "symbols_total": total,
        "imported_listed": sum(1 for s in symbols if s["imported"]),
        "exported_listed": sum(1 for s in symbols if s["exported"]),
        "offset": start,
        "limit": window,
        "has_more": start + len(symbols) < total,
        "warnings": warnings,
    }
    result.update(extra)
    return result


def _list_fat_symbols(data: bytes, offset: int, limit: int) -> JsonObject:
    """Symbols of a fat binary's first architecture slice, arch noted for context."""
    is64 = data[:4] == _FAT_MAGIC_64
    (nfat_arch,) = struct.unpack_from(">I", data, 4)
    if nfat_arch == 0:
        raise MachoParseError("fat binary with no architecture slices")
    if nfat_arch > _MAX_SLICES:
        raise MachoParseError(
            f"implausible fat arch count {nfat_arch}"
            " (a Java class file shares the 0xcafebabe magic)"
        )
    arch_fmt = ">iiQQII" if is64 else ">iiIII"
    arch_size = struct.calcsize(arch_fmt)
    available: list[str] = []
    slices: list[tuple[int, int]] = []
    for index in range(nfat_arch):
        base = 8 + index * arch_size
        if base + arch_size > len(data):
            break
        fields = struct.unpack_from(arch_fmt, data, base)
        cputype, sliceoff, size = fields[0], fields[2], fields[3]
        available.append(_CPU.get(cputype, f"0x{cputype:x}"))
        slices.append((sliceoff, size))
    if not slices:
        raise MachoParseError("fat binary with no readable architecture slices")

    sliceoff, size = slices[0]
    if sliceoff < 0 or size < 0 or sliceoff + size > len(data):
        raise MachoParseError("first fat slice extends past end of file")
    extra: JsonObject = {"fat": True, "arch": available[0], "available_arches": available}
    result = _list_thin_symbols(
        data[sliceoff : sliceoff + size], offset=offset, limit=limit, extra=extra
    )
    if len(available) > 1:
        note = f"fat binary; listed the {available[0]} slice of {available}"
        if len(result["warnings"]) < _MAX_WARNINGS:
            result["warnings"] = [note, *result["warnings"]]
    return result


def _plist_safe(value: object, depth: int = 0) -> object:
    """A plist value reduced to JSON-safe types, bounded in breadth and depth."""
    if depth >= _MAX_ENTITLEMENT_DEPTH:
        return str(value)
    if isinstance(value, bool | int | float | str):
        return value
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, list):
        return [_plist_safe(item, depth + 1) for item in value[:_MAX_ENTITLEMENT_KEYS]]
    if isinstance(value, dict):
        return {
            str(key): _plist_safe(item, depth + 1)
            for key, item in list(value.items())[:_MAX_ENTITLEMENT_KEYS]
        }
    return str(value)


def _read_code_directory(cd: bytes, warn: Any) -> JsonObject | None:
    """The CodeDirectory blob decoded: identity, team, hash setup, flags, cdhash."""
    if len(cd) < 44:
        warn("code directory blob is truncated")
        return None
    (
        magic,
        length,
        version,
        flags,
        _hash_offset,
        ident_offset,
        n_special_slots,
        n_code_slots,
        code_limit,
        hash_size,
        hash_type,
        platform,
        page_size_log2,
        _spare2,
    ) = struct.unpack_from(">IIIIIIIIIBBBBI", cd, 0)
    if magic != _CSMAGIC_CODEDIRECTORY:
        warn(f"code directory has wrong magic 0x{magic:x}")
        return None
    length = min(length, len(cd))

    identifier = ""
    if 0 < ident_offset < length:
        end = cd.find(b"\x00", ident_offset, length)
        raw = cd[ident_offset : end if end != -1 else length]
        identifier = raw.decode("utf-8", errors="replace")[:_MAX_NAME]

    team: str | None = None
    if version >= 0x20200 and len(cd) >= 52:
        (team_offset,) = struct.unpack_from(">I", cd, 48)
        if 0 < team_offset < length:
            end = cd.find(b"\x00", team_offset, length)
            raw = cd[team_offset : end if end != -1 else length]
            team = raw.decode("utf-8", errors="replace")[:_MAX_NAME]

    # The cdhash names the signature itself: the digest (by the CD's own hash
    # type) of the CodeDirectory blob, truncated to 20 bytes. It is what
    # notarization tickets, kernel logs and threat-intel lookups key on.
    hasher = {1: "sha1", 2: "sha256", 3: "sha256", 4: "sha384"}.get(hash_type)
    cdhash: str | None = None
    if hasher is not None:
        cdhash = hashlib.new(hasher, cd[:length]).digest()[:_CDHASH_LEN].hex()

    return {
        "version": f"0x{version:x}",
        "identifier": identifier,
        "team_id": team,
        "flags": [name for bit, name in _CD_FLAG_BITS if flags & bit],
        "flags_raw": f"0x{flags:x}",
        "hash_type": _CD_HASH_TYPE.get(hash_type, f"0x{hash_type:x}"),
        "hash_size": hash_size,
        "code_limit": code_limit,
        "page_size": (1 << page_size_log2) if page_size_log2 else 0,
        "code_slots": n_code_slots,
        "special_slots": n_special_slots,
        "platform": platform,
        "cdhash": cdhash,
        "flags_value": flags,
    }


def _read_signature_blob(blob: bytes, warn: Any) -> JsonObject:
    """The embedded-signature SuperBlob decoded into its analyst-facing parts."""
    out: JsonObject = {
        "code_directory": None,
        "entitlements": None,
        "has_der_entitlements": False,
        "has_requirements": False,
        "cms_signature_size": 0,
        "slots": [],
    }
    if len(blob) < 12:
        warn("code signature region is too small for a superblob")
        return out
    magic, _length, count = struct.unpack_from(">III", blob, 0)
    if magic != _CSMAGIC_EMBEDDED_SIGNATURE:
        warn(f"code signature region has wrong magic 0x{magic:x}")
        return out
    if count > _MAX_SIG_SLOTS:
        warn(f"superblob slot count {count} exceeds cap; walk truncated")

    slots: list[JsonObject] = []
    for index in range(min(count, _MAX_SIG_SLOTS)):
        base = 12 + index * 8
        if base + 8 > len(blob):
            warn(f"superblob index entry {index} is past the region end")
            break
        slot_type, slot_offset = struct.unpack_from(">II", blob, base)
        if _CSSLOT_ALTERNATE_CD_FIRST <= slot_type <= _CSSLOT_ALTERNATE_CD_LAST:
            slot_name = "alternate_code_directory"
        else:
            slot_name = _CSSLOT_NAME.get(slot_type, f"0x{slot_type:x}")
        slots.append({"slot": slot_name, "slot_raw": slot_type, "offset": slot_offset})
        if slot_offset + 8 > len(blob):
            warn(f"superblob slot {slot_name} points past the region end")
            continue
        sub = blob[slot_offset:]
        sub_magic, sub_length = struct.unpack_from(">II", sub, 0)
        sub_length = min(sub_length, len(sub))

        if slot_type == _CSSLOT_CODEDIRECTORY or (
            out["code_directory"] is None
            and _CSSLOT_ALTERNATE_CD_FIRST <= slot_type <= _CSSLOT_ALTERNATE_CD_LAST
        ):
            # The primary CodeDirectory wins; an alternate only fills a gap.
            out["code_directory"] = _read_code_directory(sub[:sub_length], warn)
        elif slot_type == _CSSLOT_REQUIREMENTS:
            out["has_requirements"] = sub_magic == _CSMAGIC_REQUIREMENTS and sub_length > 8
        elif slot_type == _CSSLOT_ENTITLEMENTS:
            if sub_magic == _CSMAGIC_EMBEDDED_ENTITLEMENTS and sub_length > 8:
                try:
                    parsed = plistlib.loads(sub[8:sub_length])
                except Exception:
                    warn("entitlements plist did not parse")
                else:
                    if isinstance(parsed, dict):
                        out["entitlements"] = _plist_safe(parsed)
                    else:
                        warn("entitlements plist is not a dictionary")
        elif slot_type == _CSSLOT_DER_ENTITLEMENTS:
            out["has_der_entitlements"] = (
                sub_magic == _CSMAGIC_EMBEDDED_DER_ENTITLEMENTS and sub_length > 8
            )
        elif slot_type == _CSSLOT_CMS_SIGNATURE and sub_magic == _CSMAGIC_BLOBWRAPPER:
            out["cms_signature_size"] = max(0, sub_length - 8)
    out["slots"] = slots
    return out


def _read_thin_signature(data: bytes, extra: JsonObject) -> JsonObject:
    """The code signature of one thin image, or an unsigned verdict."""
    magic = data[:4]
    if magic not in _THIN_MAGICS:
        raise MachoParseError("not a Mach-O image: unknown magic")
    bits, endian, endian_name = _THIN_MAGICS[magic]
    hdr_size = 32 if bits == 64 else 28
    if len(data) < hdr_size:
        raise MachoParseError("truncated Mach-O header")
    cputype, _cpusubtype, _filetype, ncmds, _sizeofcmds, _flags = struct.unpack_from(
        endian + "iiIIII", data, 4
    )

    warnings: list[str] = []

    def warn(message: str) -> None:
        if len(warnings) < _MAX_WARNINGS:
            warnings.append(message)

    dataoff = 0
    datasize = 0
    offset = hdr_size
    for index in range(min(ncmds, _MAX_CMDS)):
        if offset + 8 > len(data):
            warn(f"load command {index} is past end of file")
            break
        cmd, cmdsize = struct.unpack_from(endian + "II", data, offset)
        if cmdsize < 8 or offset + cmdsize > len(data):
            warn(f"load command {index} has a bad size")
            break
        if cmd == _LC_CODE_SIGNATURE and cmdsize >= 16:
            dataoff, datasize = struct.unpack_from(endian + "II", data, offset + 8)
        offset += cmdsize

    result: JsonObject = {
        "format": "Mach-O",
        "bits": bits,
        "endianness": endian_name,
        "cpu": _CPU.get(cputype, f"0x{cputype:x}"),
        "signed": False,
        "code_directory": None,
        "adhoc": None,
        "hardened_runtime": None,
        "linker_signed": None,
        "entitlements": None,
        "has_der_entitlements": False,
        "has_requirements": False,
        "cms_signature_size": 0,
        "slots": [],
        "warnings": warnings,
    }
    result.update(extra)

    if not datasize:
        warn("no LC_CODE_SIGNATURE: the image is unsigned")
        return result
    if dataoff < 0 or dataoff + datasize > len(data):
        warn("code signature region is past end of file")
        return result

    result["signed"] = True
    parsed = _read_signature_blob(data[dataoff : dataoff + datasize], warn)
    result.update(parsed)
    directory = result["code_directory"]
    if directory is not None:
        flags_value = int(directory.pop("flags_value"))
        result["adhoc"] = bool(flags_value & _CS_ADHOC)
        result["hardened_runtime"] = bool(flags_value & _CS_RUNTIME)
        result["linker_signed"] = bool(flags_value & _CS_LINKER_SIGNED)
    return result


def read_macho_signature(data: bytes) -> JsonObject:
    """The embedded code signature, decoded: who signed it and under what rules.

    LC_CODE_SIGNATURE points at a SuperBlob whose CodeDirectory is the identity
    an analyst wants first: the signing identifier, the Apple Developer team ID
    (the practical "who"), the hash type and page setup, the flags word decoded
    (ADHOC, HARD, KILL, RESTRICT, ENFORCEMENT, LIBRARY_VALIDATION, RUNTIME --
    the hardened runtime -- and LINKER_SIGNED), and the cdhash -- the truncated
    digest of the CodeDirectory itself, the value notarization and threat-intel
    lookups key on. The entitlements plist is parsed (stdlib plistlib) into a
    bounded JSON-safe dict -- get-task-allow, sandbox exceptions and friends --
    and the verdicts are stated directly: adhoc, hardened_runtime,
    linker_signed, plus cms_signature_size (0 for an ad-hoc signature, the CMS
    blob size when a certificate chain is attached).

    Raises MachoParseError only when the bytes are not a Mach-O at all. An
    unsigned image answers signed=false with a warning; a fat binary is read on
    its first architecture slice (arch and the full slice list reported); a
    corrupt superblob or slot warns and degrades instead of raising.
    """
    if len(data) < 8:
        raise MachoParseError("not a Mach-O file: too short for any header")
    magic = data[:4]
    if magic in _THIN_MAGICS:
        return _read_thin_signature(data, {"fat": False})
    if magic not in (_FAT_MAGIC_32, _FAT_MAGIC_64):
        raise MachoParseError("not a Mach-O file: unknown magic")

    is64 = magic == _FAT_MAGIC_64
    (nfat_arch,) = struct.unpack_from(">I", data, 4)
    if nfat_arch == 0:
        raise MachoParseError("fat binary with no architecture slices")
    if nfat_arch > _MAX_SLICES:
        raise MachoParseError(
            f"implausible fat arch count {nfat_arch}"
            " (a Java class file shares the 0xcafebabe magic)"
        )
    arch_fmt = ">iiQQII" if is64 else ">iiIII"
    arch_size = struct.calcsize(arch_fmt)
    available: list[str] = []
    slices: list[tuple[int, int]] = []
    for index in range(nfat_arch):
        base = 8 + index * arch_size
        if base + arch_size > len(data):
            break
        fields = struct.unpack_from(arch_fmt, data, base)
        cputype, sliceoff, size = fields[0], fields[2], fields[3]
        available.append(_CPU.get(cputype, f"0x{cputype:x}"))
        slices.append((sliceoff, size))
    if not slices:
        raise MachoParseError("fat binary with no readable architecture slices")
    sliceoff, size = slices[0]
    if sliceoff < 0 or size < 0 or sliceoff + size > len(data):
        raise MachoParseError("first fat slice extends past end of file")
    extra: JsonObject = {"fat": True, "arch": available[0], "available_arches": available}
    result = _read_thin_signature(data[sliceoff : sliceoff + size], extra)
    if len(available) > 1:
        note = f"fat binary; read the {available[0]} slice of {available}"
        if len(result["warnings"]) < _MAX_WARNINGS:
            result["warnings"] = [note, *result["warnings"]]
    return result


def list_macho_symbols(data: bytes, *, offset: int = 0, limit: int = 200) -> JsonObject:
    """One page of a Mach-O's LC_SYMTAB symbols: imports and exports.

    The symbol table names what the binary imports from other dylibs (undefined
    external entries, each carrying the library ordinal of the dylib that
    provides it) and what it exports for others to link (defined external
    entries); debug stabs are classified as such but neither imported nor
    exported. Raises MachoParseError only when the bytes are not a Mach-O at
    all; a thin image with no LC_SYMTAB is an empty listing with a warning, and
    a fat binary is read on its first architecture slice (the arch and the full
    slice list are reported).
    """
    if len(data) < 8:
        raise MachoParseError("not a Mach-O file: too short for any header")
    magic = data[:4]
    if magic in _THIN_MAGICS:
        return _list_thin_symbols(data, offset=offset, limit=limit, extra={"fat": False})
    if magic in (_FAT_MAGIC_32, _FAT_MAGIC_64):
        return _list_fat_symbols(data, offset, limit)
    raise MachoParseError("not a Mach-O file: unknown magic")
