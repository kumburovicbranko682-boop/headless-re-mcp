"""The pure-Python .NET metadata line, proven without any external tool.

test_dotnet_m6_gate.py exercises the real happy path (types/methods/IL/xrefs),
but every one of its cases skips unless a GPL ``HEADLESS_RE_DE4DOT`` build and
its bundled sample assembly are present -- even though dotnet.enumerate /
dotnet.il / dotnet.xrefs never touch de4dot. On any runner without it the
in-process ECMA-335 decoder therefore went unproven against a populated
assembly (the unit suite only builds an *empty*-tables shell).

This gate synthesises a tiny but real .NET assembly in-process -- one TypeDef,
one MethodDef with a real IL body, one MemberRef -- and drives it end-to-end
through AnalysisService. It needs no compiler and no external tool, so the
cross-platform decode path finally has happy-path coverage that actually runs.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_TYPE_NAME = "Widget"
_NAMESPACE = "HeadlessRe.Fixture"
_FIELD_NAME = "Value"
_METHOD_NAME = "Compute"
_MEMBER_NAME = "WriteLine"
_RESOURCE_NAME = "config.json"
_MODULE_NAME = "HeadlessReFixture.dll"
_ASSEMBLY_NAME = "HeadlessReFixture"
_METHOD_TOKEN = 0x06000001
_CALL_TOKEN = 0x0A000001


@dataclass(frozen=True)
class _Assembly:
    path: Path
    method_token: int
    call_token: int


def _u16(value: int) -> bytes:
    return struct.pack("<H", value)


def _u32(value: int) -> bytes:
    return struct.pack("<I", value)


def _build_dotnet_assembly(path: Path, *, include_assembly: bool = False) -> _Assembly:
    """Emit a minimal, verifiable PE/CLR assembly with populated tables.

    Layout mirrors the empty-table scaffold in the dotnet unit tests, extended
    with a real ``#~`` tables stream (Module/TypeDef/Field/MethodDef/MemberRef/
    ManifestResource), the string/guid/blob heaps those rows reference, and a
    tiny-format IL body the MethodDef RVA points at. heap_sizes is 0 so every
    heap index is 2 bytes, which keeps the ECMA-335 row sizes the reader
    computes matching ours. One row per table covers all five enumeration kinds
    (types/methods/fields/resources/strings) plus IL and MemberRef xrefs.

    When ``include_assembly`` is set, an Assembly row (table 0x20, which sits
    between MemberRef 0x0A and ManifestResource 0x28 in bit order) is added so
    the ``assembly_name`` recovery -- which has to size and skip every
    intervening table to reach the Assembly row's Name column -- is proven end
    to end through the service, not only in the clr_inspect unit test.
    """
    strings = bytearray(b"\x00")

    def add_str(text: str) -> int:
        index = len(strings)
        strings.extend(text.encode("utf-8") + b"\x00")
        return index

    idx_module = add_str(_MODULE_NAME)
    idx_ns = add_str(_NAMESPACE)
    idx_type = add_str(_TYPE_NAME)
    idx_field = add_str(_FIELD_NAME)
    idx_method = add_str(_METHOD_NAME)
    idx_member = add_str(_MEMBER_NAME)
    idx_resource = add_str(_RESOURCE_NAME)
    idx_assembly = add_str(_ASSEMBLY_NAME) if include_assembly else 0

    guid_heap = b"\x11" * 16
    blob_heap = b"\x00"
    us_heap = b"\x00"

    method_rva = 0x1050
    # Module(0) TypeDef(2) Field(4) MethodDef(6) MemberRef(10) [Assembly(32)] ManifestResource(40)
    valid = (1 << 0x00) | (1 << 0x02) | (1 << 0x04) | (1 << 0x06) | (1 << 0x0A) | (1 << 0x28)
    if include_assembly:
        valid |= 1 << 0x20
    row_count = 7 if include_assembly else 6
    tables = bytearray()
    tables += _u32(0)                    # reserved
    tables += bytes([2, 0])              # schema major/minor
    tables += bytes([0])                 # heap sizes (all 2-byte indexes)
    tables += bytes([1])                 # reserved
    tables += struct.pack("<Q", valid)
    tables += struct.pack("<Q", 0)       # sorted
    tables += _u32(1) * row_count         # row counts, ascending bit order
    # Module: generation, name, mvid, encid, encbaseid
    tables += _u16(0) + _u16(idx_module) + _u16(1) + _u16(0) + _u16(0)
    # TypeDef: flags, name, namespace, extends, fieldlist, methodlist
    tables += _u32(0x00100001) + _u16(idx_type) + _u16(idx_ns) + _u16(0) + _u16(1) + _u16(1)
    # Field: flags, name, signature
    tables += _u16(0x0006) + _u16(idx_field) + _u16(0)
    # MethodDef: rva, implflags, flags, name, signature, paramlist
    tables += _u32(method_rva) + _u16(0) + _u16(0x0016) + _u16(idx_method) + _u16(0) + _u16(1)
    # MemberRef: class (TypeDef rid 1 -> (1<<3)|0), name, signature
    tables += _u16(8) + _u16(idx_member) + _u16(0)
    if include_assembly:
        # Assembly (0x20, before ManifestResource in bit order): hashalg, major,
        # minor, build, rev, flags, publickey(blob), name, culture.
        tables += (
            _u32(0x8004)
            + _u16(1)
            + _u16(0)
            + _u16(0)
            + _u16(0)
            + _u32(0)
            + _u16(0)
            + _u16(idx_assembly)
            + _u16(0)
        )
    # ManifestResource: offset, flags, name, implementation (in this file -> 0)
    tables += _u32(0) + _u32(0x0001) + _u16(idx_resource) + _u16(0)

    streams = [
        ("#~", bytes(tables)),
        ("#Strings", bytes(strings)),
        ("#US", us_heap),
        ("#GUID", guid_heap),
        ("#Blob", blob_heap),
    ]

    def name_padded(name: str) -> bytes:
        raw = name.encode("ascii") + b"\x00"
        return raw + b"\x00" * ((4 - (len(raw) % 4)) % 4)

    version = b"v4.0.30319\0"
    version_padded = version + b"\0" * ((4 - (len(version) % 4)) % 4)
    root = bytearray()
    root += b"BSJB"
    root += _u16(1) + _u16(1)
    root += _u32(0)
    root += _u32(len(version))
    root += version_padded
    root += _u16(0)                # flags
    root += _u16(len(streams))     # stream count

    header_len = len(root)
    for name, _payload in streams:
        header_len += 8 + len(name_padded(name))
    cursor = header_len
    offsets: dict[str, int] = {}
    for name, payload in streams:
        offsets[name] = cursor
        cursor += len(payload)
    for name, payload in streams:
        root += _u32(offsets[name]) + _u32(len(payload)) + name_padded(name)
    for _name, payload in streams:
        root += payload
    meta_blob = bytes(root)

    image = bytearray(0x1200)
    pe_offset = 0x80
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    file_header = pe_offset + 4
    struct.pack_into("<HHIIIHH", image, file_header, 0x8664, 1, 0, 0, 0, 0xF0, 0x2022)
    optional = file_header + 20
    struct.pack_into("<HBB", image, optional, 0x20B, 14, 0)
    struct.pack_into("<I", image, optional + 16, 0x1000)
    struct.pack_into("<Q", image, optional + 24, 0x140000000)
    struct.pack_into("<II", image, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", image, optional + 56, 0x2000, 0x200)
    struct.pack_into("<HH", image, optional + 68, 3, 0x8160)
    struct.pack_into("<I", image, optional + 108, 16)
    dir_base = optional + 112
    struct.pack_into("<II", image, dir_base + 14 * 8, 0x1100, 72)  # COM descriptor -> COR20
    section = optional + 0xF0
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x1000, 0x1000, 0x1000, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)

    cor_off = 0x300  # RVA 0x1100
    struct.pack_into("<I", image, cor_off, 72)
    struct.pack_into("<HH", image, cor_off + 4, 2, 5)
    struct.pack_into("<II", image, cor_off + 8, 0x1200, len(meta_blob))
    struct.pack_into("<I", image, cor_off + 16, 0x1)          # ILONLY
    struct.pack_into("<I", image, cor_off + 20, _METHOD_TOKEN)

    # ldc.i4.s 42; pop; call 0x0A000001; ret -- the ldc.i4.s exercises a short
    # inline operand, the exact shape the old decoder mis-aligned on.
    il = bytes([0x1F, 0x2A, 0x26, 0x28, 0x01, 0x00, 0x00, 0x0A, 0x2A])
    body = bytes([(len(il) << 2) | 0x02]) + il         # tiny method header
    image[0x250 : 0x250 + len(body)] = body            # RVA 0x1050 -> file 0x250
    image[0x400 : 0x400 + len(meta_blob)] = meta_blob  # RVA 0x1200 -> file 0x400

    path.write_bytes(image)
    return _Assembly(path=path, method_token=_METHOD_TOKEN, call_token=_CALL_TOKEN)


def _make_service(artifact_root: Path) -> AnalysisService:
    return AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=artifact_root,
        )
    )


@pytest.mark.integration
def test_dotnet_metadata_enumerate_il_xrefs_without_de4dot(tmp_path: Path) -> None:
    assembly = _build_dotnet_assembly(tmp_path / _MODULE_NAME)
    service = _make_service(tmp_path / "artifacts")
    created = service.create_session(str(assembly.path))
    assert created.ok and created.data is not None, created.error
    session_id = str(created.data["session"]["id"])
    try:
        inspected = service.dotnet_inspect(session_id, require_verified=True)
        assert inspected.ok and inspected.data is not None, inspected.error
        assert inspected.data["is_dotnet"] is True
        assert inspected.data["verified_clr"] is True
        assert inspected.data["kind"] == "pure_managed"
        assert inspected.data["module_name"] == _MODULE_NAME
        stats = inspected.data["metadata_stats"]
        assert stats["type_count"] == 1
        assert stats["method_count"] == 1

        types = service.dotnet_enumerate(session_id, "types", limit=16)
        assert types.ok and types.data is not None, types.error
        assert types.data["capability"] == "dotnet_metadata"
        assert types.data["not_ida_idalib"] is True
        assert types.data["total"] == 1
        type_item = types.data["items"][0]
        assert type_item["name"] == _TYPE_NAME
        assert type_item["namespace"] == _NAMESPACE
        assert type_item["token"] == 0x02000001

        methods = service.dotnet_enumerate(session_id, "methods", limit=16)
        assert methods.ok and methods.data is not None, methods.error
        assert methods.data["total"] == 1
        method_item = methods.data["items"][0]
        assert method_item["name"] == _METHOD_NAME
        assert method_item["token"] == assembly.method_token
        assert int(method_item["rva"]) > 0

        fields = service.dotnet_enumerate(session_id, "fields", limit=16)
        assert fields.ok and fields.data is not None, fields.error
        assert fields.data["total"] == 1
        assert fields.data["items"][0]["name"] == _FIELD_NAME
        assert fields.data["items"][0]["token"] == 0x04000001

        resources = service.dotnet_enumerate(session_id, "resources", limit=16)
        assert resources.ok and resources.data is not None, resources.error
        assert resources.data["total"] == 1
        assert resources.data["items"][0]["name"] == _RESOURCE_NAME
        assert resources.data["items"][0]["token"] == 0x28000001

        heap = service.dotnet_enumerate(session_id, "strings", limit=64)
        assert heap.ok and heap.data is not None, heap.error
        heap_values = {item["value"] for item in heap.data["items"]}
        assert {_MODULE_NAME, _TYPE_NAME, _METHOD_NAME, _MEMBER_NAME} <= heap_values

        il = service.dotnet_il(session_id, assembly.method_token)
        assert il.ok and il.data is not None, il.error
        assert il.data["backend"] == "dotnet_metadata"
        instructions = il.data["instructions"]
        mnemonics = [insn["mnemonic"] for insn in instructions]
        assert mnemonics == ["ldc.i4.s", "pop", "call", "ret"]
        # The short operand must decode to its value, not be swallowed as the
        # next opcode -- and the method must not be reported as partial.
        assert instructions[0]["operand"] == 42
        assert il.data["partial"] is False
        assert assembly.call_token in il.data["call_tokens"]

        xrefs = service.dotnet_xrefs(session_id, limit=16)
        assert xrefs.ok and xrefs.data is not None, xrefs.error
        assert xrefs.data["kind"] == "xrefs"
        assert xrefs.data["total"] == 1
        assert xrefs.data["items"][0]["name"] == _MEMBER_NAME
    finally:
        service.close_session(session_id)


@pytest.mark.integration
def test_dotnet_inspect_recovers_assembly_name_end_to_end(tmp_path: Path) -> None:
    """dotnet.inspect must surface assembly_name for an assembly with that table.

    The clr_inspect unit test proves ``_parse_metadata_root`` reads the Assembly
    row, but only by calling the parser directly. Here the Assembly table travels
    through the whole service path (create_session -> dotnet_inspect), so the
    row-sizing that has to skip Module/TypeDef/Field/MethodDef/MemberRef to reach
    it is exercised as an agent would hit it -- and the earlier enumerations must
    still decode, proving the extra table did not shift any offsets.
    """
    assembly = _build_dotnet_assembly(tmp_path / _MODULE_NAME, include_assembly=True)
    service = _make_service(tmp_path / "artifacts")
    created = service.create_session(str(assembly.path))
    assert created.ok and created.data is not None, created.error
    session_id = str(created.data["session"]["id"])
    try:
        inspected = service.dotnet_inspect(session_id, require_verified=True)
        assert inspected.ok and inspected.data is not None, inspected.error
        assert inspected.data["verified_clr"] is True
        assert inspected.data["module_name"] == _MODULE_NAME
        assert inspected.data["assembly_name"] == _ASSEMBLY_NAME

        # The Assembly row is inserted mid-stream; the type/method/resource reads
        # that come after it must still land on the right rows.
        types = service.dotnet_enumerate(session_id, "types", limit=16)
        assert types.ok and types.data is not None, types.error
        assert types.data["items"][0]["name"] == _TYPE_NAME
        methods = service.dotnet_enumerate(session_id, "methods", limit=16)
        assert methods.ok and methods.data is not None, methods.error
        assert methods.data["items"][0]["name"] == _METHOD_NAME
        resources = service.dotnet_enumerate(session_id, "resources", limit=16)
        assert resources.ok and resources.data is not None, resources.error
        assert resources.data["items"][0]["name"] == _RESOURCE_NAME
    finally:
        service.close_session(session_id)


@pytest.mark.integration
def test_dotnet_il_out_of_range_token_fails_closed(tmp_path: Path) -> None:
    """An IL request for a rid past the table must be a clean not_found."""
    assembly = _build_dotnet_assembly(tmp_path / _MODULE_NAME)
    service = _make_service(tmp_path / "artifacts")
    created = service.create_session(str(assembly.path))
    assert created.ok and created.data is not None
    session_id = str(created.data["session"]["id"])
    try:
        result = service.dotnet_il(session_id, 0x06000099)
        assert not result.ok and result.error is not None
        assert result.error.code != "internal_error", result.error
        assert result.error.code == "not_found", result.error
    finally:
        service.close_session(session_id)


def _first_rowcount_offset(image: bytes) -> int:
    """File offset of the ``#~`` stream's first table row-count u32.

    Parses the metadata root exactly as :func:`_build_dotnet_assembly` writes it
    (BSJB header, 4-byte-rounded version, stream directory) so a test can reach
    in and corrupt the tables stream without hard-coding a brittle constant.
    """
    bsjb = image.find(b"BSJB")
    assert bsjb >= 0, "no metadata root in fixture"
    off = bsjb + 4 + 2 + 2 + 4  # signature, major, minor, reserved
    version_len = struct.unpack_from("<I", image, off)[0]
    off += 4 + ((version_len + 3) & ~3)
    off += 2  # flags
    stream_count = struct.unpack_from("<H", image, off)[0]
    off += 2
    tilde_payload: int | None = None
    for _ in range(stream_count):
        stream_off, _stream_size = struct.unpack_from("<II", image, off)
        off += 8
        name_start = off
        while image[off] != 0:
            off += 1
        name = image[name_start:off]
        off = name_start + (((len(name) + 1) + 3) & ~3)
        if name == b"#~":
            tilde_payload = bsjb + stream_off
    assert tilde_payload is not None, "no #~ stream in fixture"
    # #~ payload: reserved(4) + maj/min/heap/reserved(4) + valid(8) + sorted(8).
    return tilde_payload + 4 + 4 + 8 + 8


@pytest.mark.integration
def test_dotnet_readers_refuse_a_broken_metadata_signature(tmp_path: Path) -> None:
    """A clobbered BSJB signature must fail closed, never internal_error.

    The CLR verifier keys off the metadata-root signature; corrupting it should
    make every reader refuse cleanly (clr_unverified) rather than press on with a
    half-decoded blob. This is the fail-closed half of the .NET fault contract:
    when the metadata cannot be trusted, the tools say so instead of guessing.
    """
    assembly = _build_dotnet_assembly(tmp_path / _MODULE_NAME)
    image = bytearray(assembly.path.read_bytes())
    bsjb = image.find(b"BSJB")
    assert bsjb >= 0
    image[bsjb : bsjb + 4] = b"XXXX"
    broken = tmp_path / "bad-signature.dll"
    broken.write_bytes(bytes(image))

    service = _make_service(tmp_path / "artifacts")
    created = service.create_session(str(broken))
    assert created.ok and created.data is not None, created.error
    session_id = str(created.data["session"]["id"])
    try:
        calls = (
            lambda: service.dotnet_inspect(session_id, require_verified=True),
            lambda: service.dotnet_enumerate(session_id, "types", limit=8),
            lambda: service.dotnet_enumerate(session_id, "methods", limit=8),
            lambda: service.dotnet_il(session_id, _METHOD_TOKEN),
            lambda: service.dotnet_xrefs(session_id, limit=8),
        )
        for call in calls:
            result = call()
            assert not result.ok and result.error is not None, result
            assert result.error.code != "internal_error", result.error
            assert result.error.code == "clr_unverified", result.error
    finally:
        service.close_session(session_id)


@pytest.mark.integration
def test_dotnet_readers_survive_a_hostile_table_row_count(tmp_path: Path) -> None:
    """A ``#~`` row count of 2^31 must not run the table walker off the stream.

    A malformed (or deliberately adversarial) assembly can claim a table has far
    more rows than the stream can hold. The ECMA row-sizing walk multiplies row
    count by row width to locate later tables, so an unbounded count is exactly
    the shape that turns into a wild read or a MemoryError. Every reader must
    still return a structured envelope -- degrade to empty/not_found or refuse --
    but never internal_error and never an uncaught exception.
    """
    assembly = _build_dotnet_assembly(tmp_path / _MODULE_NAME)
    image = bytearray(assembly.path.read_bytes())
    struct.pack_into("<I", image, _first_rowcount_offset(image), 0x7FFFFFFF)
    hostile = tmp_path / "hostile-rowcount.dll"
    hostile.write_bytes(bytes(image))

    service = _make_service(tmp_path / "artifacts")
    created = service.create_session(str(hostile))
    assert created.ok and created.data is not None, created.error
    session_id = str(created.data["session"]["id"])
    try:
        calls = (
            lambda: service.dotnet_inspect(session_id, require_verified=True),
            lambda: service.dotnet_enumerate(session_id, "types", limit=8),
            lambda: service.dotnet_enumerate(session_id, "methods", limit=8),
            lambda: service.dotnet_il(session_id, _METHOD_TOKEN),
            lambda: service.dotnet_xrefs(session_id, limit=8),
        )
        for call in calls:
            result = call()
            # ok (clamped/empty) or a clean structured refusal are both fine; a
            # server-defect internal_error, or a raised exception, are not.
            if not result.ok:
                assert result.error is not None
                assert result.error.code != "internal_error", result.error
    finally:
        service.close_session(session_id)
