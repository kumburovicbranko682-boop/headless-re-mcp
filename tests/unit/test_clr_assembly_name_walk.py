"""Assembly-name resolution must walk past the tables between Module and Assembly.

``_parse_tables_and_names`` reads the Module (0x00) and Assembly (0x20) names out
of the ``#~`` table stream. Assembly sits well after Module, with TypeRef/TypeDef
and friends in between, so reaching it requires skipping those rows at their true
on-disk widths. The earlier walk only knew the Module and Assembly row shapes and
stopped at the first other table, so ``assembly_name`` came back ``None`` for
essentially every real assembly. These tests build a minimal ``#~`` + ``#Strings``
pair and pin that the name is read past intervening tables.

Row widths below assume 2-byte string/guid/blob heap indexes (HeapSizes byte 0):
Module (II.22.30) = Generation(2)+Name(2)+Mvid(2)+EncId(2)+EncBaseId(2) = 10;
TypeRef (II.22.38) = ResolutionScope(2)+Name(2)+Namespace(2) = 6;
TypeDef (II.22.37) = Flags(4)+Name(2)+Namespace(2)+Extends(2)+FieldList(2)+MethodList(2) = 14;
Assembly (II.22.2) = HashAlgId(4)+Ver(2*4)+Flags(4)+PublicKey(2)+Name(2)+Culture(2) = 22.
"""

from __future__ import annotations

from headless_re_mcp.dotnet.clr_inspect import _parse_tables_and_names

_STRINGS = b"\x00" + b"mod.dll\x00" + b"MyAssembly\x00"  # "mod.dll"@1, "MyAssembly"@9
_MODULE_IDX = 1
_ASM_IDX = 9


def _meta(
    present: list[int],
    rows: dict[int, int],
    writes: list[tuple[int, int]],
    *,
    pad: int = 512,
) -> tuple[bytes, dict[str, tuple[int, int]]]:
    tables = bytearray(24 + 4 * len(present) + pad)
    tables[6] = 0  # HeapSizes = 0 -> every heap index is 2 bytes
    valid = 0
    for bit in present:
        valid |= 1 << bit
    tables[8:16] = valid.to_bytes(8, "little")
    cursor = 24
    for bit in sorted(present):
        tables[cursor : cursor + 4] = rows.get(bit, 1).to_bytes(4, "little")
        cursor += 4
    for offset, value in writes:
        tables[offset : offset + 2] = value.to_bytes(2, "little")
    meta = bytes(tables) + _STRINGS
    stream_map = {"#~": (0, len(tables)), "#Strings": (len(tables), len(_STRINGS))}
    return meta, stream_map


def test_assembly_name_is_read_past_the_typeref_table() -> None:
    # Present: Module, TypeRef, Assembly. Data starts at 24 + 4*3 = 36.
    # Module 36..46 (Name@38); TypeRef 46..52; Assembly@52, Name@52+18 = 70.
    meta, stream_map = _meta(
        [0x00, 0x01, 0x20],
        {0x00: 1, 0x01: 1, 0x20: 1},
        [(38, _MODULE_IDX), (70, _ASM_IDX)],
    )
    module_name, assembly_name, _stats = _parse_tables_and_names(meta, stream_map)
    assert module_name == "mod.dll"
    assert assembly_name == "MyAssembly"


def test_module_only_metadata_yields_no_assembly_name() -> None:
    # Present: Module, TypeRef (no Assembly). Data starts at 24 + 4*2 = 32.
    # Module 32..42 (Name@34). No Assembly table -> assembly_name is None.
    meta, stream_map = _meta([0x00, 0x01], {0x00: 1, 0x01: 1}, [(34, _MODULE_IDX)])
    module_name, assembly_name, _stats = _parse_tables_and_names(meta, stream_map)
    assert module_name == "mod.dll"
    assert assembly_name is None


def test_multiple_intervening_typedef_rows_are_skipped() -> None:
    # Present: Module, TypeDef(3 rows), Assembly. Data starts at 24 + 4*3 = 36.
    # Module 36..46 (Name@38); TypeDef 46..(46+3*14=88); Assembly@88, Name@88+18=106.
    meta, stream_map = _meta(
        [0x00, 0x02, 0x20],
        {0x00: 1, 0x02: 3, 0x20: 1},
        [(38, _MODULE_IDX), (106, _ASM_IDX)],
    )
    module_name, assembly_name, _stats = _parse_tables_and_names(meta, stream_map)
    assert module_name == "mod.dll"
    assert assembly_name == "MyAssembly"


def test_unsized_intervening_table_degrades_without_losing_module_name() -> None:
    # Bit 0x1E is a reserved table the enumerator's sizing does not model, and it
    # sits before Assembly. Locating Assembly must fail softly: assembly_name
    # comes back None, but the module name (read before the walk needs any sizing)
    # and the row-count stats still survive. Data starts at 24 + 4*3 = 36.
    meta, stream_map = _meta(
        [0x00, 0x1E, 0x20],
        {0x00: 1, 0x1E: 1, 0x20: 1},
        [(38, _MODULE_IDX)],
    )
    module_name, assembly_name, stats = _parse_tables_and_names(meta, stream_map)
    assert module_name == "mod.dll"
    assert assembly_name is None
    assert stats is not None


def test_assembly_row_running_past_the_buffer_yields_no_name() -> None:
    # Present: Module, Assembly. Data starts at 24 + 4*2 = 32; Module 32..42
    # (Name@34); Assembly@42 with its Name field at 42+18 = 60. Truncate the
    # tables buffer to 50 bytes so the Assembly name offset runs past the end:
    # the bounds check must return None for the assembly name while the module
    # name (fully inside the buffer) is still read.
    meta, stream_map = _meta(
        [0x00, 0x20],
        {0x00: 1, 0x20: 1},
        [(34, _MODULE_IDX)],
        pad=50 - 32,
    )
    module_name, assembly_name, _stats = _parse_tables_and_names(meta, stream_map)
    assert module_name == "mod.dll"
    assert assembly_name is None
