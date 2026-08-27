"""Assembly-name recovery walks past the tables that precede Assembly.

Regression: ``_parse_tables_and_names`` used to read the Module row, then stop
at the first other populated table. Assembly is table 0x20, and every real
assembly has TypeRef/TypeDef (tables 0x01/0x02) before it, so the walk stopped
early and ``assembly_name`` came back None for essentially every assembly. The
fix sizes each intervening table via the shared ECMA row-width machinery, so it
reaches the Assembly row's Name column.
"""

from __future__ import annotations

import struct

import pytest

from headless_re_mcp.dotnet import clr_inspect
from headless_re_mcp.dotnet.tables import (
    TableSizingError,
    table_row_size,
    table_start_offset,
)


def _u16(value: int) -> bytes:
    return struct.pack("<H", value)


def _u32(value: int) -> bytes:
    return struct.pack("<I", value)


def _name_padded(name: str) -> bytes:
    raw = name.encode("ascii") + b"\x00"
    return raw + b"\x00" * ((4 - (len(raw) % 4)) % 4)


def _build_metadata(*, with_assembly: bool) -> bytes:
    """A BSJB blob with Module, TypeDef, and optionally Assembly rows.

    heap_sizes is 0 so every heap index is two bytes; that keeps the row widths
    the reader computes matching the ones written here.
    """
    strings = bytearray(b"\x00")

    def add(text: str) -> int:
        index = len(strings)
        strings.extend(text.encode("utf-8") + b"\x00")
        return index

    idx_module = add("MyModule.dll")
    idx_type = add("MyType")
    idx_assembly = add("MyAssembly") if with_assembly else 0

    valid = (1 << 0x00) | (1 << 0x02)
    row_counts = [1, 1]
    if with_assembly:
        valid |= 1 << 0x20
        row_counts.append(1)

    tables = bytearray()
    tables += _u32(0)
    tables += bytes([2, 0, 0, 1])  # major, minor, heap_sizes=0, reserved
    tables += struct.pack("<Q", valid)
    tables += struct.pack("<Q", 0)
    for count in row_counts:
        tables += _u32(count)
    # Module: Generation, Name, Mvid, EncId, EncBaseId
    tables += _u16(0) + _u16(idx_module) + _u16(1) + _u16(0) + _u16(0)
    # TypeDef: Flags, Name, Namespace, Extends, FieldList, MethodList
    tables += _u32(0) + _u16(idx_type) + _u16(0) + _u16(0) + _u16(1) + _u16(1)
    if with_assembly:
        # HashAlgId, Major, Minor, Build, Rev, Flags, PublicKey(blob), Name, Culture
        tables += _u32(0x8004) + _u16(1) + _u16(0) + _u16(0) + _u16(0)
        tables += _u32(0) + _u16(0) + _u16(idx_assembly) + _u16(0)

    streams = [("#~", bytes(tables)), ("#Strings", bytes(strings))]
    version = b"v4.0.30319\x00"
    version_padded = version + b"\x00" * ((4 - (len(version) % 4)) % 4)
    root = bytearray()
    root += b"BSJB" + _u16(1) + _u16(1) + _u32(0) + _u32(len(version)) + version_padded
    root += _u16(0) + _u16(len(streams))
    header_len = len(root)
    for name, _payload in streams:
        header_len += 8 + len(_name_padded(name))
    cursor = header_len
    offsets: dict[str, int] = {}
    for name, payload in streams:
        offsets[name] = cursor
        cursor += len(payload)
    for name, payload in streams:
        root += _u32(offsets[name]) + _u32(len(payload)) + _name_padded(name)
    for _name, payload in streams:
        root += payload
    return bytes(root)


def test_assembly_name_resolved_past_intervening_typedef() -> None:
    meta = _build_metadata(with_assembly=True)
    _version, _streams, module_name, assembly_name, stats = clr_inspect._parse_metadata_root(meta)
    assert module_name == "MyModule.dll"
    assert assembly_name == "MyAssembly"
    assert stats is not None and stats.type_count == 1


def test_netmodule_without_assembly_table_reports_none() -> None:
    # A module with no Assembly table is legal; assembly_name must stay None
    # while module_name is still recovered.
    meta = _build_metadata(with_assembly=False)
    _version, _streams, module_name, assembly_name, _stats = clr_inspect._parse_metadata_root(meta)
    assert module_name == "MyModule.dll"
    assert assembly_name is None


def test_table_start_offset_sums_intervening_rows() -> None:
    # Module(10) + TypeDef(14) with 2-byte heaps => Assembly begins 24 bytes
    # after the table data starts.
    row_counts = {0x00: 1, 0x02: 1, 0x20: 1}
    start = table_start_offset(
        row_counts,
        0x20,
        table_data_offset=100,
        string_index_size=2,
        blob_index_size=2,
        guid_index_size=2,
    )
    assert start == 100 + 10 + 14


def test_table_row_size_known_widths() -> None:
    row_counts = {0x00: 1, 0x02: 1, 0x20: 1}
    kw = {"string_index_size": 2, "blob_index_size": 2, "guid_index_size": 2}
    assert table_row_size(row_counts, 0x00, **kw) == 2 + 2 + 2 + 2 + 2  # Module
    assert table_row_size(row_counts, 0x04, **kw) == 2 + 2 + 2  # Field
    assert table_row_size(row_counts, 0x20, **kw) == 4 + 2 + 2 + 2 + 2 + 4 + 2 + 2 + 2  # Assembly


def test_table_row_size_rejects_unknown_table() -> None:
    with pytest.raises(TableSizingError):
        table_row_size(
            {},
            0x3F,
            string_index_size=2,
            blob_index_size=2,
            guid_index_size=2,
        )
