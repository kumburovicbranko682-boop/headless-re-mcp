"""Generate ``minimal_assembly.exe``: a tiny but real ECMA-335 .NET assembly.

The .NET reverse-engineering line has two halves. Deobfuscation and
verification shell out to de4dot (GPL, user-configured), so their gate must
skip when it is absent. The other half -- ``dotnet.inspect`` /
``dotnet.enumerate`` / ``dotnet.il`` / ``dotnet.xrefs`` -- is a pure-Python
ECMA-335 metadata reader that needs no external tool at all. To exercise it
end to end we need a genuine managed assembly, so this script hand-writes the
smallest one that carries real metadata: a #~ tables stream with Module,
TypeRef, TypeDef, Field, MethodDef, MemberRef, CustomAttribute, ModuleRef,
Assembly and AssemblyRef rows, a #Strings heap, a #Blob heap carrying a real
custom-attribute value (the TargetFrameworkAttribute every compiler stamps on
an assembly), the assembly's strong-name public key and genuine member
signatures (monodis asserts on malformed ones, so real blobs are what let it
fully disassemble the fixture and mark the .entrypoint the entrypoint gate
cross-checks), and three method bodies with actual CIL -- including a
<Module>::.cctor module initializer (the managed code-before-main the
monodis gate cross-checks). It also carries a
CodeView RSDS debug directory (a per-build PDB GUID, age and path) so the
managed build-fingerprint fact -- the symbol-server key, the analogue of an
ELF build-id -- has a positive case a strict PE decoder (llvm-readobj /
objdump) confirms. No compiler is required; the output is deterministic and
committed as ``minimal_assembly.exe`` next to this file.

Run ``python fixtures/dotnet/build_minimal_dotnet.py`` to regenerate it.
"""

from __future__ import annotations

import struct
import uuid
from pathlib import Path

_SECTION_RVA = 0x2000
_FILE_BASE = 0x200
_SECTION_ALIGN = 0x2000
_FILE_ALIGN = 0x200
_IMAGE_DEBUG_DIRECTORY_SIZE = 28
_IMAGE_DEBUG_TYPE_CODEVIEW = 2

# The CodeView PDB reference the linker stamps into the debug directory: a
# per-build GUID, an age counter and the PDB path. The GUID+age is the
# symbol-server key for the build (the managed analogue of an ELF build-id),
# and the path is the sort of build-machine directory that leaks in the wild.
# Fixed here so the reader and the llvm-readobj/objdump gate assert exact bytes.
PDB_GUID = uuid.UUID("a1b2c3d4-e5f6-4788-99aa-bbccddeeff00")
PDB_AGE = 1
PDB_PATH = r"C:\build\headless\MyAssembly.pdb"

# Public identifiers the metadata carries, so tests can assert on real names.
MODULE_NAME = "MyModule.dll"
ASSEMBLY_NAME = "MyAssembly"
TYPE_NAME = "Sample"
FIELD_NAME = "Secret"
METHOD_ADD = "Add"
METHOD_RUN = "Run"
MEMBERREF_NAME = "WriteLine"
# WriteLine's declaring type, resolved through a TypeRef into mscorlib the way
# every real call into the runtime library is. Giving the MemberRef a genuine
# parent (and every member a genuine signature blob below) is what lets monodis
# fully disassemble the fixture -- it asserts on malformed signatures -- so the
# entrypoint gate can cross-check the .entrypoint directive in its output.
CONSOLE_TYPE_NAME = "Console"
CONSOLE_NAMESPACE = "System"
# The unmanaged DLL a P/Invoke targets: the ModuleRef table (0x1A) names it.
# Its row sits between MemberRef (0x0A) and Assembly (0x20) in the walk, so it
# is another table the AssemblyRef/resource reads must step over correctly.
MODULE_REF_NAME = "kernel32.dll"
RESOURCE_NAME = "config.json"
RESOURCE_FLAGS = 0x0001  # Public
# The AssemblyRef every real compiler emits: the runtime library the assembly
# links against. Its row sits between Assembly (0x20) and ManifestResource
# (0x28) in the table walk, so mis-sizing it (an easy bug: the AssemblyRef row
# is NOT the Assembly row's shape) would corrupt every table read behind it --
# with this row present, the resource enumeration doubles as a regression test.
ASSEMBLY_REF_NAME = "mscorlib"
ASSEMBLY_REF_VERSION = (4, 0, 0, 0)
# The TargetFrameworkAttribute value the CustomAttribute row (0x0C) carries:
# a TypeRef (0x01) names System.Runtime.Versioning.TargetFrameworkAttribute in
# mscorlib, a second MemberRef row is its .ctor(string), and the attribute's
# value blob in #Blob serializes this framework string -- exactly how csc
# stamps a real build's target platform onto the manifest assembly.
TARGET_FRAMEWORK = ".NETFramework,Version=v4.8"
TFA_TYPE_NAME = "TargetFrameworkAttribute"
TFA_NAMESPACE = "System.Runtime.Versioning"
# The strong-name identity: the Assembly row's PublicKey blob. This is the
# 16-byte "ECMA" standard public key every framework assembly (mscorlib,
# System, ...) is signed with; its public-key token -- the low 8 bytes of the
# key's SHA-1 reversed, which the CLR, ildasm and sn all derive -- is the
# published constant b77a5c561934e089, so the reader's token has an external
# ground truth no code of ours computed.
PUBLIC_KEY = bytes.fromhex("00000000000000000400000000000000")
PUBLIC_KEY_TOKEN = "b77a5c561934e089"
METADATA_VERSION = "v4.0.30319"
# MethodDef row 1 is <Module>::.cctor -- the module initializer the runtime
# executes at load, before the entry point (the managed code-before-main,
# where obfuscators put their stubs); Add and Run follow as rows 2 and 3.
MODULE_CCTOR_TOKEN = 0x06000001
ENTRY_POINT_TOKEN = 0x06000003  # Run
CALL_TARGET_TOKEN = 0x0A000001  # MemberRef row 1
# Every compiler stamps a Module Version ID -- a GUID regenerated on each build
# -- into the #GUID heap, and the Module row's Mvid points at it. A real
# assembly is never missing one, so the fixture carries a fixed, recognizable
# value the inspect gate can assert against.
MODULE_MVID = "8b8a2c3d-4e5f-6071-8293-a4b5c6d7e8f9"


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
    i_mod_ref = add_string(MODULE_REF_NAME)
    i_resource = add_string(RESOURCE_NAME)
    i_asm_ref = add_string(ASSEMBLY_REF_NAME)
    i_tfa = add_string(TFA_TYPE_NAME)
    i_tfa_ns = add_string(TFA_NAMESPACE)
    i_ctor = add_string(".ctor")
    i_cctor = add_string(".cctor")
    i_console = add_string(CONSOLE_TYPE_NAME)
    i_console_ns = add_string(CONSOLE_NAMESPACE)
    i_ns = 0
    strings_heap = _pad4(bytes(strings))

    # ---- #Blob heap (index 0 is the empty blob; entries carry a packed len) ----
    blob = bytearray(b"\x00")

    def add_blob(content: bytes) -> int:
        at = len(blob)
        assert len(content) < 0x80, "single-byte packed length only"
        blob.append(len(content))
        blob.extend(content)
        return at

    # .ctor(string) signature: HASTHIS, 1 parameter, returns void, param string.
    b_ctor_sig = add_blob(bytes([0x20, 0x01, 0x01, 0x0E]))
    # Real member signatures (II.23.2), which monodis decodes -- and asserts
    # on -- when disassembling: a static int32 Add(), a static void Run(), an
    # int32 field, and Console.WriteLine()'s static void ().
    b_add_sig = add_blob(bytes([0x00, 0x00, 0x08]))  # DEFAULT, 0 params, ret I4
    b_void_sig = add_blob(bytes([0x00, 0x00, 0x01]))  # DEFAULT, 0 params, ret VOID
    b_field_sig = add_blob(bytes([0x06, 0x08]))  # FIELD, I4
    # Custom-attribute value (II.23.3): prolog 0x0001, one SerString fixed
    # argument (packed length + UTF-8), zero named arguments.
    tfa_utf8 = TARGET_FRAMEWORK.encode("utf-8")
    b_ca_value = add_blob(bytes([0x01, 0x00, len(tfa_utf8)]) + tfa_utf8 + b"\x00\x00")
    # The Assembly row's strong-name public key.
    b_pubkey = add_blob(PUBLIC_KEY)
    blob_heap = _pad4(bytes(blob))

    # ---- method bodies (tiny format: (code_size << 2) | 0x02) ----
    il_cctor = bytes([0x2A])  # ret -- the smallest real module initializer
    body_cctor = _u8((len(il_cctor) << 2) | 0x02) + il_cctor
    il_add = bytes([0x1B, 0x2A])  # ldc.i4.5 ; ret
    body_add = _u8((len(il_add) << 2) | 0x02) + il_add
    il_run = bytes([0x28]) + _u32(CALL_TARGET_TOKEN) + bytes([0x2A])  # call ; ret
    body_run = _u8((len(il_run) << 2) | 0x02) + il_run

    # ---- CodeView RSDS debug record (ties the assembly to its PDB) ----
    # An IMAGE_DEBUG_DIRECTORY (28 bytes) of type 2 (CodeView) pointing at an
    # RSDS blob: the per-build PDB GUID, an age, and the PDB path the linker
    # baked in -- the managed build fingerprint (symbol-server key) and the
    # kind of build-machine path that regularly leaks. bytes_le layout so the
    # GUID round-trips through Python's uuid the way the runtime lays it out.
    rsds = (
        b"RSDS"
        + PDB_GUID.bytes_le
        + _u32(PDB_AGE)
        + PDB_PATH.encode("utf-8")
        + b"\x00"
    )

    # ---- section layout: CLR header, method bodies (4-aligned), metadata ----
    cursor = 72  # after the 72-byte COR20 header
    cursor = (cursor + 3) & ~3
    rva_cctor = _SECTION_RVA + cursor
    cursor += len(body_cctor)
    cursor = (cursor + 3) & ~3
    rva_add = _SECTION_RVA + cursor
    cursor += len(body_add)
    cursor = (cursor + 3) & ~3
    rva_run = _SECTION_RVA + cursor
    cursor += len(body_run)
    cursor = (cursor + 3) & ~3
    rva_debug_dir = _SECTION_RVA + cursor
    cursor += _IMAGE_DEBUG_DIRECTORY_SIZE
    cursor = (cursor + 3) & ~3
    rva_rsds = _SECTION_RVA + cursor
    cursor += len(rsds)
    cursor = (cursor + 3) & ~3
    rva_meta = _SECTION_RVA + cursor

    # ---- #~ tables stream (HeapSizes=0 => 2-byte heap indices) ----
    valid = (
        (1 << 0x00)  # Module
        | (1 << 0x01)  # TypeRef
        | (1 << 0x02)  # TypeDef
        | (1 << 0x04)  # Field
        | (1 << 0x06)  # MethodDef
        | (1 << 0x0A)  # MemberRef
        | (1 << 0x0C)  # CustomAttribute
        | (1 << 0x1A)  # ModuleRef
        | (1 << 0x20)  # Assembly
        | (1 << 0x23)  # AssemblyRef
        | (1 << 0x28)  # ManifestResource
    )
    row_counts = {
        0x00: 1, 0x01: 2, 0x02: 2, 0x04: 1, 0x06: 3, 0x0A: 2, 0x0C: 1,
        0x1A: 1, 0x20: 1, 0x23: 1, 0x28: 1,
    }

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
    # Module: Generation Name Mvid EncId EncBaseId (Mvid -> #GUID row 1)
    tables += _u16(0) + _u16(i_module) + _u16(1) + _u16(0) + _u16(0)
    # TypeRef x2: ResolutionScope Name Namespace -- TargetFrameworkAttribute
    # and System.Console, both resolved from the mscorlib AssemblyRef
    # (ResolutionScope tag 2, row 1), the way every runtime-library type is.
    tables += _u16((1 << 2) | 2) + _u16(i_tfa) + _u16(i_tfa_ns)
    tables += _u16((1 << 2) | 2) + _u16(i_console) + _u16(i_console_ns)
    # TypeDef x2: Flags Name Namespace Extends FieldList MethodList. <Module>
    # (row 1) owns MethodDef row 1 (its .cctor); Sample's methods start at 2.
    tables += _u32(0) + _u16(i_type_module) + _u16(i_ns) + _u16(0) + _u16(1) + _u16(1)
    tables += _u32(0x00100001) + _u16(i_type_sample) + _u16(i_ns) + _u16(0) + _u16(1) + _u16(2)
    # Field: Flags Name Signature
    tables += _u16(0x0016) + _u16(i_field) + _u16(b_field_sig)
    # MethodDef x3: RVA ImplFlags Flags Name Signature ParamList. Row 1 is the
    # module initializer <Module>::.cctor -- flags Private | Static |
    # SpecialName | RTSpecialName (0x1811), the shape ECMA II.10.5.3 requires.
    tables += _u32(rva_cctor) + _u16(0) + _u16(0x1811) + _u16(i_cctor) + _u16(b_void_sig) + _u16(1)
    tables += _u32(rva_add) + _u16(0) + _u16(0x0016) + _u16(i_add) + _u16(b_add_sig) + _u16(1)
    tables += _u32(rva_run) + _u16(0) + _u16(0x0016) + _u16(i_run) + _u16(b_void_sig) + _u16(1)
    # MemberRef x2: Class Name Signature. Row 1 is the WriteLine call target,
    # its Class the System.Console TypeRef (MemberRefParent tag 1, row 2);
    # row 2 is TargetFrameworkAttribute::.ctor(string), its Class the TypeRef
    # above (MemberRefParent tag 1, row 1).
    tables += _u16((2 << 3) | 1) + _u16(i_memberref) + _u16(b_void_sig)
    tables += _u16((1 << 3) | 1) + _u16(i_ctor) + _u16(b_ctor_sig)
    # CustomAttribute: Parent Type Value -- the TargetFramework stamp on the
    # manifest assembly: Parent is Assembly row 1 (HasCustomAttribute tag 14),
    # Type the .ctor MemberRef row 2 (CustomAttributeType tag 3), Value the
    # serialized framework string in #Blob.
    tables += _u16((1 << 5) | 14) + _u16((2 << 3) | 3) + _u16(b_ca_value)
    # ModuleRef: Name -- the unmanaged DLL a P/Invoke binds to.
    tables += _u16(i_mod_ref)
    # Assembly: HashAlgId Maj Min Build Rev Flags PublicKey Name Culture.
    # Flags bit 0 (afPublicKey) marks the PublicKey field as a full public key,
    # which points at the ECMA strong-name key in #Blob.
    tables += (
        _u32(0x8004)
        + _u16(1) + _u16(0) + _u16(0) + _u16(0)
        + _u32(0x0001)
        + _u16(b_pubkey) + _u16(i_asm) + _u16(0)
    )
    # AssemblyRef: Maj Min Build Rev Flags PublicKeyOrToken Name Culture Hash
    # -- no leading HashAlgId, and a trailing HashValue blob, unlike Assembly.
    ref_major, ref_minor, ref_build, ref_rev = ASSEMBLY_REF_VERSION
    tables += (
        _u16(ref_major) + _u16(ref_minor) + _u16(ref_build) + _u16(ref_rev)
        + _u32(0)
        + _u16(0) + _u16(i_asm_ref) + _u16(0) + _u16(0)
    )
    # ManifestResource: Offset Flags Name Implementation (null => embedded here)
    tables += _u32(0) + _u32(RESOURCE_FLAGS) + _u16(i_resource) + _u16(0)
    tables_stream = _pad4(bytes(tables))

    # ---- metadata root (BSJB) ----
    version = _pad4(METADATA_VERSION.encode("ascii") + b"\x00")
    stream_defs = [
        ("#~", tables_stream),
        ("#Strings", strings_heap),
        ("#GUID", uuid.UUID(MODULE_MVID).bytes_le),
        ("#Blob", blob_heap),
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

    # ---- IMAGE_DEBUG_DIRECTORY entry (28 bytes) ----
    # Characteristics, TimeDateStamp, Major/Minor, Type=2 (CodeView),
    # SizeOfData, AddressOfRawData (RVA) and PointerToRawData (file offset)
    # both pointing at the RSDS blob laid down just after it.
    ptr_rsds = _FILE_BASE + (rva_rsds - _SECTION_RVA)
    debug_dir = (
        _u32(0) + _u32(0) + _u16(0) + _u16(0)
        + _u32(_IMAGE_DEBUG_TYPE_CODEVIEW)
        + _u32(len(rsds)) + _u32(rva_rsds) + _u32(ptr_rsds)
    )
    assert len(debug_dir) == _IMAGE_DEBUG_DIRECTORY_SIZE, len(debug_dir)

    # ---- assemble the section body ----
    section = bytearray(clr)
    section += b"\x00" * ((rva_cctor - _SECTION_RVA) - len(section))
    section += body_cctor
    section += b"\x00" * ((rva_add - _SECTION_RVA) - len(section))
    section += body_add
    section += b"\x00" * ((rva_run - _SECTION_RVA) - len(section))
    section += body_run
    section += b"\x00" * ((rva_debug_dir - _SECTION_RVA) - len(section))
    section += debug_dir
    section += b"\x00" * ((rva_rsds - _SECTION_RVA) - len(section))
    section += rsds
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
    directories[6] = (rva_debug_dir, _IMAGE_DEBUG_DIRECTORY_SIZE)  # debug directory
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
