"""Shared ECMA-335 metadata table row sizing (Partition II.22).

Both :mod:`clr_inspect` (Module/Assembly name lookup) and :mod:`metadata_enum`
(full type/method/field enumeration) need to know how many bytes each metadata
table row occupies, so they can locate a table by summing the rows of every
table before it. Keeping that arithmetic here means the two callers cannot
drift, and -- more importantly -- it lets ``clr_inspect`` reach the Assembly
table (which follows TypeRef/TypeDef in every real assembly) without importing
the enumerator, which already imports ``clr_inspect``.

The functions are pure: they take the parsed ``#~`` header fields (row counts
and the 2/4-byte heap index widths) and return byte sizes. They never touch a
file or a PE layout.
"""

from __future__ import annotations

from typing import Final

RowCounts = dict[int, int]

# Assembly is table 0x20; it can only be reached after the lower-numbered
# tables (TypeRef 0x01, TypeDef 0x02, ...) have been sized and skipped.
TBL_MODULE: Final[int] = 0x00
TBL_ASSEMBLY: Final[int] = 0x20


class TableSizingError(ValueError):
    """A metadata table whose row width is not modelled; callers degrade."""

    def __init__(self, table: int) -> None:
        super().__init__(f"cannot size metadata table {table:#x}")
        self.table = table


def coded_index_size(row_counts: RowCounts, tables: tuple[int, ...], tag_bits: int) -> int:
    """Width of a coded index: 4 bytes once a referenced table is large."""
    max_rows = max((row_counts.get(t, 0) for t in tables), default=0)
    return 4 if max_rows >= (1 << (16 - tag_bits)) else 2


def simple_index_size(row_counts: RowCounts, table: int) -> int:
    """Width of a plain rid into ``table``: 4 bytes past 0xFFFF rows."""
    return 4 if row_counts.get(table, 0) >= 65536 else 2


def table_row_size(
    row_counts: RowCounts,
    table: int,
    *,
    string_index_size: int,
    blob_index_size: int,
    guid_index_size: int,
) -> int:
    """ECMA-335 II.22 row size for one metadata table, in bytes.

    Raises :class:`TableSizingError` for a table we do not model, so a caller
    walking to a later table can stop rather than mis-add an unknown width.
    """
    rc = row_counts
    s = string_index_size
    b = blob_index_size
    g = guid_index_size
    type_def_or_ref = coded_index_size(rc, (0x02, 0x01, 0x1B), 2)
    has_constant = coded_index_size(rc, (0x04, 0x08, 0x17), 2)
    has_custom_attribute = coded_index_size(
        rc,
        (
            0x06,
            0x04,
            0x01,
            0x02,
            0x08,
            0x09,
            0x0A,
            0x00,
            0x0E,
            0x17,
            0x14,
            0x11,
            0x1A,
            0x1B,
            0x20,
            0x23,
            0x26,
            0x27,
            0x28,
            0x2A,
            0x2C,
            0x2B,
        ),
        5,
    )
    has_field_marshal = coded_index_size(rc, (0x04, 0x08), 1)
    has_decl_security = coded_index_size(rc, (0x02, 0x06, 0x20), 2)
    member_ref_parent = coded_index_size(rc, (0x02, 0x01, 0x1A, 0x06, 0x1B), 3)
    has_semantics = coded_index_size(rc, (0x14, 0x17), 1)
    method_def_or_ref = coded_index_size(rc, (0x06, 0x0A), 1)
    member_forwarded = coded_index_size(rc, (0x04, 0x06), 1)
    implementation = coded_index_size(rc, (0x26, 0x23, 0x27), 2)
    custom_attribute_type = coded_index_size(rc, (0x06, 0x0A), 3)
    resolution_scope = coded_index_size(rc, (0x00, 0x1A, 0x23, 0x01), 2)
    type_or_method_def = coded_index_size(rc, (0x02, 0x06), 1)

    sizes: dict[int, int] = {
        0x00: 2 + s + g + g + g,  # Module
        0x01: resolution_scope + s + s,  # TypeRef
        0x02: (
            4
            + s
            + s
            + type_def_or_ref
            + simple_index_size(rc, 0x04)
            + simple_index_size(rc, 0x06)
        ),  # TypeDef
        0x03: simple_index_size(rc, 0x04),  # FieldPtr
        0x04: 2 + s + b,  # Field
        0x05: simple_index_size(rc, 0x06),  # MethodPtr
        0x06: 4 + 2 + 2 + s + b + simple_index_size(rc, 0x08),  # MethodDef
        0x07: simple_index_size(rc, 0x08),  # ParamPtr
        0x08: 2 + 2 + s,  # Param
        0x09: simple_index_size(rc, 0x02) + type_def_or_ref,  # InterfaceImpl
        0x0A: member_ref_parent + s + b,  # MemberRef
        0x0B: 2 + has_constant + b,  # Constant
        0x0C: has_custom_attribute + custom_attribute_type + b,  # CustomAttribute
        0x0D: has_field_marshal + b,  # FieldMarshal
        0x0E: 2 + has_decl_security + b,  # DeclSecurity
        0x0F: 2 + 4 + simple_index_size(rc, 0x02),  # ClassLayout
        0x10: 4 + simple_index_size(rc, 0x04),  # FieldLayout
        0x11: b,  # StandAloneSig
        0x12: simple_index_size(rc, 0x02) + simple_index_size(rc, 0x14),  # EventMap
        0x13: simple_index_size(rc, 0x14),  # EventPtr
        0x14: 2 + s + type_def_or_ref,  # Event
        0x15: simple_index_size(rc, 0x02) + simple_index_size(rc, 0x17),  # PropertyMap
        0x16: simple_index_size(rc, 0x17),  # PropertyPtr
        0x17: 2 + s + b,  # Property
        0x18: 2 + method_def_or_ref + has_semantics,  # MethodSemantics
        0x19: (
            simple_index_size(rc, 0x02) + method_def_or_ref + method_def_or_ref
        ),  # MethodImpl
        0x1A: s,  # ModuleRef
        0x1B: b,  # TypeSpec
        0x1C: 2 + member_forwarded + s + simple_index_size(rc, 0x1A),  # ImplMap
        0x1D: 4 + simple_index_size(rc, 0x04),  # FieldRVA
        0x20: 4 + 2 + 2 + 2 + 2 + 4 + b + s + s,  # Assembly
        0x21: 4,  # AssemblyProcessor
        0x22: 12,  # AssemblyOS
        0x23: 4 + 2 + 2 + 2 + 2 + 4 + b + s + s,  # AssemblyRef
        0x24: 4 + simple_index_size(rc, 0x23),  # AssemblyRefProcessor
        0x25: 12 + simple_index_size(rc, 0x23),  # AssemblyRefOS
        0x26: 4 + s + implementation,  # File
        0x27: 4 + 4 + s + s + implementation,  # ExportedType
        0x28: 4 + 4 + s + implementation,  # ManifestResource
        0x29: simple_index_size(rc, 0x02) + implementation,  # NestedClass
        0x2A: 2 + 2 + type_or_method_def + s,  # GenericParam
        0x2B: method_def_or_ref + b,  # MethodSpec
        0x2C: simple_index_size(rc, 0x2A) + type_def_or_ref,  # GenericParamConstraint
    }
    if table not in sizes:
        raise TableSizingError(table)
    return sizes[table]


def table_start_offset(
    row_counts: RowCounts,
    table: int,
    *,
    table_data_offset: int,
    string_index_size: int,
    blob_index_size: int,
    guid_index_size: int,
) -> int:
    """Byte offset of ``table``'s first row within the ``#~`` stream.

    Sums the row widths of every present table below ``table``. Propagates
    :class:`TableSizingError` if an intervening table cannot be sized.
    """
    offset = table_data_offset
    for bit in range(table):
        rows = row_counts.get(bit)
        if not rows:
            continue
        offset += (
            table_row_size(
                row_counts,
                bit,
                string_index_size=string_index_size,
                blob_index_size=blob_index_size,
                guid_index_size=guid_index_size,
            )
            * rows
        )
    return offset
