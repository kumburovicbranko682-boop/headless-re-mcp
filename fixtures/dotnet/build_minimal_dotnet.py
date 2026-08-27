"""Generate ``minimal_assembly.exe``: a tiny but real ECMA-335 .NET assembly.

The .NET reverse-engineering line has two halves. Deobfuscation and
verification shell out to de4dot (GPL, user-configured), so their gate must
skip when it is absent. The other half -- ``dotnet.inspect`` /
``dotnet.enumerate`` / ``dotnet.il`` / ``dotnet.xrefs`` -- is a pure-Python
ECMA-335 metadata reader that needs no external tool at all. To exercise it
end to end we need a genuine managed assembly, so this script hand-writes the
smallest one that carries real metadata: a #~ tables stream with Module,
TypeDef, Field, MethodDef, MemberRef and Assembly rows, a #Strings heap, and
two method bodies with actual CIL. No compiler is required; the output is
deterministic and committed as ``minimal_assembly.exe`` next to this file.

Run ``python fixtures/dotnet/build_minimal_dotnet.py`` to regenerate it.
"""

from __future__ import annotations

import struct
from pathlib import Path

_SECTION_RVA = 0x2000
_FILE_BASE = 0x200
_SECTION_ALIGN = 0x2000
_FILE_ALIGN = 0x200

# Public identifiers the metadata carries, so tests can assert on real names.
MODULE_NAME = "MyModule.dll"
ASSEMBLY_NAME = "MyAssembly"
TYPE_NAME = "Sample"
FIELD_NAME = "Secret"
METHOD_ADD = "Add"
METHOD_RUN = "Run"
MEMBERREF_NAME = "WriteLine"
METADATA_VERSION = "v4.0.30319"
ENTRY_POINT_TOKEN = 0x06000002  # Run
CALL_TARGET_TOKEN = 0x0A000001  # MemberRef row 1


def _u8(v: int) -> bytes:
    return struct.pack("<B", v)


def _u16(v: int) -> bytes:
    return struct.pack("<H", v)


def _u32(v: int) -> bytes:
    return struct.pack("<I", v)


def _u64(v: int) -> bytes:
    return struct.pack("<Q", v)


def _pad4(b: bytes) -> bytes:
    return b + b"\x00" * ((-len(b)) % 4)


def build() -> bytes:
    """Return the bytes of the minimal .NET assembly."""
    # ---- #Strings heap (index 0 is the empty string) ----
    strings = bytearray(b"\x00")
    index: dict[str, int] = {}

    def add_string(text: str) -> int:
        at = len(strings)
        strings.extend(text.encode("utf-8") + b"\x00")
        index[text] = at
        return at

    i_module = add_string(MODULE_NAME)
    i_type_module = add_string("<Module>")
    i_type_sample = add_string(TYPE_NAME)
    i_add = add_string(METHOD_ADD)
    i_run = add_string(METHOD_RUN)
    i_asm = add_string(ASSEMBLY_NAME)
    i_field = add_string(FIELD_NAME)
    i_memberref = add_string(MEMBERREF_NAME)
    i_ns = 0
    strings_heap = _pad4(bytes(strings))

    # ---- method bodies (tiny format: (code_size << 2) | 0x02) ----
    il_add = bytes([0x1B, 0x2A])  # ldc.i4.5 ; ret
    body_add = _u8((len(il_add) << 2) | 0x02) + il_add
    il_run = bytes([0x28]) + _u32(CALL_TARGET_TOKEN) + bytes([0x2A])  # call ; ret
    body_run = _u8((len(il_run) << 2) | 0x02) + il_run

    # ---- section layout: CLR header, method bodies (4-aligned), metadata ----
    cursor = 72  # after the 72-byte COR20 header
    cursor = (cursor + 3) & ~3
    rva_add = _SECTION_RVA + cursor
    cursor += len(body_add)
    cursor = (cursor + 3) & ~3
    rva_run = _SECTION_RVA + cursor
    cursor += len(body_run)
    cursor = (cursor + 3) & ~3
    rva_meta = _SECTION_RVA + cursor

    # ---- #~ tables stream (HeapSizes=0 => 2-byte heap indices) ----
    valid = (
        (1 << 0x00)  # Module
        | (1 << 0x02)  # TypeDef
        | (1 << 0x04)  # Field
        | (1 << 0x06)  # MethodDef
        | (1 << 0x0A)  # MemberRef
        | (1 << 0x20)  # Assembly
    )
    row_counts = {0x00: 1, 0x02: 2, 0x04: 1, 0x06: 2, 0x0A: 1, 0x20: 1}

    tables = bytearray()
    tables += _u32(0)  # Reserved
    tables += _u8(2) + _u8(0)  # schema major/minor
    tables += _u8(0)  # HeapSizes
    tables += _u8(1)  # Reserved
    tables += _u64(valid)
    tables += _u64(0)  # Sorted
    for bit in range(64):
        if valid & (1 << bit):
            tables += _u32(row_counts[bit])
    # Module: Generation Name Mvid EncId EncBaseId
    tables += _u16(0) + _u16(i_module) + _u16(0) + _u16(0) + _u16(0)
    # TypeDef x2: Flags Name Namespace Extends FieldList MethodList
    tables += _u32(0) + _u16(i_type_module) + _u16(i_ns) + _u16(0) + _u16(1) + _u16(1)
    tables += _u32(0x00100001) + _u16(i_type_sample) + _u16(i_ns) + _u16(0) + _u16(1) + _u16(1)
    # Field: Flags Name Signature
    tables += _u16(0x0016) + _u16(i_field) + _u16(0)
    # MethodDef x2: RVA ImplFlags Flags Name Signature ParamList
    tables += _u32(rva_add) + _u16(0) + _u16(0x0016) + _u16(i_add) + _u16(0) + _u16(1)
    tables += _u32(rva_run) + _u16(0) + _u16(0x0016) + _u16(i_run) + _u16(0) + _u16(1)
    # MemberRef: Class Name Signature
    tables += _u16(0) + _u16(i_memberref) + _u16(0)
    # Assembly: HashAlgId Maj Min Build Rev Flags PublicKey Name Culture
    tables += (
        _u32(0x8004)
        + _u16(1) + _u16(0) + _u16(0) + _u16(0)
        + _u32(0)
        + _u16(0) + _u16(i_asm) + _u16(0)
    )
    tables_stream = _pad4(bytes(tables))

    # ---- metadata root (BSJB) ----
    version = _pad4(METADATA_VERSION.encode("ascii") + b"\x00")
    stream_defs = [
        ("#~", tables_stream),
        ("#Strings", strings_heap),
        ("#GUID", b""),
        ("#Blob", _pad4(b"\x00")),
    ]

    def meta_header(offsets: list[int]) -> bytes:
        header = bytearray()
        header += b"BSJB"
        header += _u16(1) + _u16(1)
        header += _u32(0)
        header += _u32(len(version))
        header += version
        header += _u16(0)  # flags
        header += _u16(len(stream_defs))  # stream count
        for (name, data), off in zip(stream_defs, offsets, strict=True):
            header += _u32(off) + _u32(len(data))
            header += _pad4(name.encode("ascii") + b"\x00")
        return bytes(header)

    header_len = len(meta_header([0] * len(stream_defs)))
    offsets: list[int] = []
    running = header_len
    for _name, data in stream_defs:
        offsets.append(running)
        running += len(data)
    metadata = bytearray(meta_header(offsets))
    for (_name, data), off in zip(stream_defs, offsets, strict=True):
        assert off == len(metadata)
        metadata += data
    meta_size = len(metadata)

    # ---- COR20 CLR header (72 bytes) ----
    clr = bytearray()
    clr += _u32(72)  # cb
    clr += _u16(2) + _u16(5)  # runtime major/minor
    clr += _u32(rva_meta) + _u32(meta_size)  # MetaData directory
    clr += _u32(0x00000001)  # Flags: COMIMAGE_FLAGS_ILONLY
    clr += _u32(ENTRY_POINT_TOKEN)
    # Resources, StrongNameSignature, CodeManagerTable, VTableFixups,
    # ExportAddressTableJumps, ManagedNativeHeader -- all (rva, size) = (0, 0).
    for _ in range(6):
        clr += _u32(0) + _u32(0)
    assert len(clr) == 72, len(clr)

    # ---- assemble the section body ----
    section = bytearray(clr)
    section += b"\x00" * ((rva_add - _SECTION_RVA) - len(section))
    section += body_add
    section += b"\x00" * ((rva_run - _SECTION_RVA) - len(section))
    section += body_run
    section += b"\x00" * ((rva_meta - _SECTION_RVA) - len(section))
    section += metadata

    raw_size = (len(section) + _FILE_ALIGN - 1) & ~(_FILE_ALIGN - 1)
    section += b"\x00" * (raw_size - len(section))
    image_size = (_SECTION_RVA + raw_size + _SECTION_ALIGN - 1) & ~(_SECTION_ALIGN - 1)

    # ---- PE headers (PE32, x86) ----
    dos = bytearray(b"\x00" * 0x80)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = _u32(0x80)

    coff = bytearray()
    coff += b"PE\x00\x00"
    coff += _u16(0x014C)  # machine i386
    coff += _u16(1)  # sections
    coff += _u32(0)  # timestamp
    coff += _u32(0) + _u32(0)  # symbol table
    coff += _u16(0xE0)  # optional header size
    coff += _u16(0x2102)  # EXECUTABLE_IMAGE | 32BIT_MACHINE | DLL

    opt = bytearray()
    opt += _u16(0x10B)  # PE32
    opt += _u8(8) + _u8(0)  # linker version
    opt += _u32(0) + _u32(0) + _u32(0)  # code/data sizes
    opt += _u32(rva_add)  # AddressOfEntryPoint
    opt += _u32(_SECTION_RVA)  # BaseOfCode
    opt += _u32(_SECTION_RVA)  # BaseOfData
    opt += _u32(0x00400000)  # ImageBase
    opt += _u32(_SECTION_ALIGN) + _u32(_FILE_ALIGN)
    opt += _u16(4) + _u16(0) + _u16(0) + _u16(0) + _u16(4) + _u16(0)
    opt += _u32(0)  # win32 version
    opt += _u32(image_size)
    opt += _u32(_FILE_BASE)  # SizeOfHeaders
    opt += _u32(0)  # checksum
    opt += _u16(3) + _u16(0)  # subsystem / dll characteristics
    opt += _u32(0x100000) + _u32(0x1000) + _u32(0x100000) + _u32(0x1000)
    opt += _u32(0)  # loader flags
    opt += _u32(16)  # number of data directories
    directories = [(0, 0)] * 16
    directories[14] = (_SECTION_RVA, 72)  # COM descriptor -> COR20 header
    for rva, size in directories:
        opt += _u32(rva) + _u32(size)
    assert len(opt) == 0xE0, len(opt)

    section_header = bytearray()
    section_header += b".text\x00\x00\x00"
    section_header += _u32(raw_size)  # VirtualSize
    section_header += _u32(_SECTION_RVA)  # VirtualAddress
    section_header += _u32(raw_size)  # SizeOfRawData
    section_header += _u32(_FILE_BASE)  # PointerToRawData
    section_header += _u32(0) + _u32(0) + _u16(0) + _u16(0)
    section_header += _u32(0x60000020)  # CODE | EXECUTE | READ

    headers = bytearray()
    headers += dos + coff + opt + section_header
    headers += b"\x00" * (_FILE_BASE - len(headers))
    return bytes(headers) + bytes(section)


def main() -> None:
    out = Path(__file__).resolve().parent / "minimal_assembly.exe"
    out.write_bytes(build())
    print(f"wrote {out} ({out.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
