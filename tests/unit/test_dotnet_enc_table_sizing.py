"""Enumeration must survive EnC tables (EncLog 0x1E / EncMap 0x1F).

The #~ table sizer knew every ECMA-335 table from 0x00..0x2C *except* the two
edit-and-continue tables, EncLog (0x1E) and EncMap (0x1F). Those appear in the
uncompressed #- stream -- the same stream shape whose FieldPtr/MethodPtr/... Ptr
tables the sizer already handles -- so a real #- assembly can carry them. When
one did, sizing any table that lives after bit 0x1E (File, ExportedType,
ManifestResource, NestedClass, GenericParam, MethodSpec) had to skip past a
table whose width was unknown, and _table_start raised unsupported_metadata,
aborting an enumeration of rows that were sitting right there in the file.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.dotnet.clr_inspect import DotnetInspectError
from headless_re_mcp.dotnet.metadata_enum import (
    _iter_resources,
    _MetaCtx,
    _table_row_size,
    _table_start,
)

# EncLog rows are Token(4)+FuncCode(4); EncMap rows are Token(4). Two EncLog rows
# is 16 bytes, then one ManifestResource row: Offset(4)+Flags(4)+Name(str,2 with
# small #Strings)+Implementation(coded,2 when the referenced tables are empty).
_ENCLOG_ROWS = 2
_ENC_BYTES = _ENCLOG_ROWS * 8
_RESOURCE_ROW = bytes(
    [
        0x00,
        0x01,
        0x00,
        0x00,  # offset = 0x100
        0x01,
        0x00,
        0x00,
        0x00,  # flags = 1
        0x01,
        0x00,  # name index = 1 (#Strings)
        0x00,
        0x00,  # implementation coded index = 0
    ]
)


def _ctx_with_enc_then_resource() -> _MetaCtx:
    tables = bytes(_ENC_BYTES) + _RESOURCE_ROW
    return _MetaCtx(
        path=Path("synthetic.dll"),
        pe_data=b"",
        layout=None,
        meta=b"",
        stream_map={},
        tables=tables,
        strings=b"\x00Res\x00",
        heap_sizes=0,
        string_index_size=2,
        blob_index_size=2,
        guid_index_size=2,
        row_counts={0x1E: _ENCLOG_ROWS, 0x28: 1},
        table_data_offset=0,
    )


def test_enc_tables_have_fixed_token_widths() -> None:
    """EncLog is 8 bytes, EncMap is 4 -- independent of heap_sizes."""
    ctx = _ctx_with_enc_then_resource()
    assert _table_row_size(ctx, 0x1E) == 8
    assert _table_row_size(ctx, 0x1F) == 4

    wide = _MetaCtx(
        **{
            **ctx.__dict__,
            "heap_sizes": 0x07,
            "string_index_size": 4,
            "blob_index_size": 4,
            "guid_index_size": 4,
        }
    )
    assert _table_row_size(wide, 0x1E) == 8
    assert _table_row_size(wide, 0x1F) == 4


def test_table_start_skips_past_an_enc_table() -> None:
    """The resource table begins right after the two EncLog rows."""
    ctx = _ctx_with_enc_then_resource()
    assert _table_start(ctx, 0x28) == _ENC_BYTES


def test_resources_enumerate_across_a_preceding_enc_table() -> None:
    """Before the fix this raised unsupported_metadata for bit 0x1E."""
    ctx = _ctx_with_enc_then_resource()
    rows = list(_iter_resources(ctx))
    assert rows == [
        {
            "token": 0x28000001,
            "rid": 1,
            "name": "Res",
            "offset": 0x100,
            "flags": 1,
        }
    ]


def test_a_truly_unknown_table_still_aborts() -> None:
    """The fail-closed guard must remain for tables we genuinely cannot size.

    0x2D is past GenericParamConstraint (0x2C) and is not a real #~ table, so a
    valid bitmap claiming it is corrupt/hostile; sizing across it must still
    refuse rather than guess a width.
    """
    ctx = _MetaCtx(
        path=Path("synthetic.dll"),
        pe_data=b"",
        layout=None,
        meta=b"",
        stream_map={},
        tables=bytes(64),
        strings=b"\x00",
        heap_sizes=0,
        string_index_size=2,
        blob_index_size=2,
        guid_index_size=2,
        row_counts={0x2D: 1, 0x28: 1},
        table_data_offset=0,
    )
    with pytest.raises(DotnetInspectError) as excinfo:
        _table_start(ctx, 0x2E)
    assert excinfo.value.code == "unsupported_metadata"
