"""ECMA-335 II.22 row widths for the metadata tables that pick the wrong column.

``_table_row_size`` sums each table's on-disk row width so ``_table_start`` can
skip to the table an enumerator wants. If any width is off by even a byte, the
start of *every* table after it is wrong and the enumerator reads rows from the
middle of the previous table. Five entries used the wrong column type. Each test
below chooses a ``row_counts`` where the correct column and the buggy column
resolve to different byte widths, so a regression to the old type fails loudly
rather than only on assemblies large enough to widen a coded index.
"""

from __future__ import annotations

import types

from headless_re_mcp.dotnet.metadata_enum import _table_row_size, _table_start


def _ctx(
    row_counts: dict[int, int], *, s: int = 2, b: int = 2, g: int = 2
) -> types.SimpleNamespace:
    """A minimal stand-in exposing only what the sizing math reads."""
    return types.SimpleNamespace(
        row_counts=dict(row_counts),
        string_index_size=s,
        blob_index_size=b,
        guid_index_size=g,
        table_data_offset=0,
    )


def test_interfaceimpl_interface_is_typedeforref_not_methoddef() -> None:
    # TypeSpec crosses the TypeDefOrRef coded-index threshold (2**14) so Interface
    # must be 4 bytes, while MethodDef stays small (the buggy column would be 2).
    meta = _ctx({0x1B: 16384})
    # Class (TypeDef index, 2) + Interface (TypeDefOrRef coded index, 4).
    assert _table_row_size(meta, 0x09) == 6


def test_methodsemantics_method_is_plain_methoddef_not_coded() -> None:
    # MemberRef crosses the MethodDefOrRef threshold (2**15) so the buggy coded
    # index would widen to 4, but Method is really a plain MethodDef index (2).
    meta = _ctx({0x0A: 32768})
    # Semantics(2) + Method (MethodDef index, 2) + Association (HasSemantics, 2).
    assert _table_row_size(meta, 0x18) == 6


def test_assemblyref_has_no_hashalgid_and_trailing_hashvalue_blob() -> None:
    meta = _ctx({}, s=2, b=2)
    # II.22.5: Major/Minor/Build/Rev(2*4) + Flags(4) + PublicKeyOrToken(blob,2)
    #          + Name(str,2) + Culture(str,2) + HashValue(blob,2) = 20.
    # The old Assembly-shaped row (leading HashAlgId, no trailing blob) was 22.
    assert _table_row_size(meta, 0x23) == 20


def test_file_hashvalue_is_blob_index_not_implementation_coded() -> None:
    # AssemblyRef crosses the Implementation coded-index threshold (2**14) so the
    # buggy coded index would be 4; HashValue is really a blob index (kept at 2).
    meta = _ctx({0x23: 16384}, s=2, b=2)
    # II.22.19: Flags(4) + Name(str,2) + HashValue(blob,2) = 8.
    assert _table_row_size(meta, 0x26) == 8


def test_nestedclass_enclosing_is_typedef_index_not_implementation() -> None:
    # AssemblyRef crosses the Implementation threshold so the buggy coded index
    # would be 4; EnclosingClass is really a TypeDef index (2 here).
    meta = _ctx({0x23: 16384})
    # II.22.32: NestedClass (TypeDef index, 2) + EnclosingClass (TypeDef index, 2).
    assert _table_row_size(meta, 0x29) == 4


def test_wrong_row_width_would_shift_every_following_table_start() -> None:
    # Ten InterfaceImpl (0x09) rows sit before ModuleRef (0x1A). With the correct
    # 6-byte row, ModuleRef starts 60 bytes in; the old 4-byte row would have
    # placed it at 40 -- 20 bytes short, so every later row would be read from
    # the wrong offset. TypeSpec (0x1B) forces the wide Interface column but sits
    # after ModuleRef, so it does not itself contribute to this start offset.
    meta = _ctx({0x1B: 16384, 0x09: 10})
    assert _table_start(meta, 0x1A) == 60
