"""Shared ECMA-335 II.22 metadata table row sizing.

Both the CLR inspector (clr_inspect) and the metadata enumerator
(metadata_enum) need to know how wide each ``#~`` table row is so they can
walk from one table to the next. The rules are identical for both, so they
live here once. This module is deliberately dependency-free (no imports from
the rest of the package) so either side can use it without an import cycle:
``metadata_enum`` imports ``clr_inspect``, and ``clr_inspect`` needs this
sizing too, so the sizing cannot live in either of them.

``table_row_size`` returns ``None`` for a table it cannot size rather than
raising, so callers pick the failure mode that fits them -- the enumerator
turns it into a hard ``unsupported_metadata`` error, while the inspector's
best-effort name walk simply stops.
"""

from __future__ import annotations

TABLE_COUNT = 64

# The table lists behind the ECMA-335 II.24.2.6 coded indexes, exported so a
# reader that must *decode* one of these fields (not merely size a row) uses
# the same authoritative list the sizing does. Order is irrelevant for sizing
# (only the max row count matters); the tag values live with the decoders.
RESOLUTION_SCOPE_TABLES = (0x00, 0x1A, 0x23, 0x01)
MEMBER_REF_PARENT_TABLES = (0x02, 0x01, 0x1A, 0x06, 0x1B)
CUSTOM_ATTRIBUTE_TYPE_TABLES = (0x06, 0x0A)
HAS_CUSTOM_ATTRIBUTE_TABLES = (
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
)


def coded_index_size(row_counts: dict[int, int], tables: tuple[int, ...], tag_bits: int) -> int:
    """Width of a coded index over ``tables`` with ``tag_bits`` tag bits."""
    max_rows = max((row_counts.get(t, 0) for t in tables), default=0)
    return 4 if max_rows >= (1 << (16 - tag_bits)) else 2


def simple_index_size(row_counts: dict[int, int], table: int) -> int:
    """Width of a simple index into a single table."""
    return 4 if row_counts.get(table, 0) >= 65536 else 2


def table_row_size(
    row_counts: dict[int, int],
    string_index_size: int,
    blob_index_size: int,
    guid_index_size: int,
    table: int,
) -> int | None:
    """ECMA-335 II.22 row size for ``table``; ``None`` if we cannot size it."""
    rc = row_counts
    s = string_index_size
    b = blob_index_size
    g = guid_index_size
    type_def_or_ref = coded_index_size(rc, (0x02, 0x01, 0x1B), 2)
    has_constant = coded_index_size(rc, (0x04, 0x08, 0x17), 2)
    has_custom_attribute = coded_index_size(rc, HAS_CUSTOM_ATTRIBUTE_TABLES, 5)
    has_field_marshal = coded_index_size(rc, (0x04, 0x08), 1)
    has_decl_security = coded_index_size(rc, (0x02, 0x06, 0x20), 2)
    member_ref_parent = coded_index_size(rc, MEMBER_REF_PARENT_TABLES, 3)
    has_semantics = coded_index_size(rc, (0x14, 0x17), 1)
    method_def_or_ref = coded_index_size(rc, (0x06, 0x0A), 1)
    member_forwarded = coded_index_size(rc, (0x04, 0x06), 1)
    implementation = coded_index_size(rc, (0x26, 0x23, 0x27), 2)
    custom_attribute_type = coded_index_size(rc, CUSTOM_ATTRIBUTE_TYPE_TABLES, 3)
    resolution_scope = coded_index_size(rc, RESOLUTION_SCOPE_TABLES, 2)
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
        ),
        0x03: simple_index_size(rc, 0x04),  # FieldPtr
        0x04: 2 + s + b,  # Field
        0x05: simple_index_size(rc, 0x06),  # MethodPtr
        0x06: 4 + 2 + 2 + s + b + simple_index_size(rc, 0x08),  # MethodDef
        0x07: simple_index_size(rc, 0x08),  # ParamPtr
        0x08: 2 + 2 + s,  # Param
        0x09: simple_index_size(rc, 0x02) + simple_index_size(rc, 0x06),
        0x0A: member_ref_parent + s + b,  # MemberRef
        0x0B: 2 + has_constant + b,  # Constant
        0x0C: has_custom_attribute + custom_attribute_type + b,
        0x0D: has_field_marshal + b,  # FieldMarshal
        0x0E: 2 + has_decl_security + b,  # DeclSecurity
        0x0F: 2 + 4,  # ClassLayout placeholder; fixed below
        0x10: 4 + simple_index_size(rc, 0x04),  # FieldLayout
        0x11: b,  # StandAloneSig
        0x12: simple_index_size(rc, 0x02) + simple_index_size(rc, 0x14),
        0x13: simple_index_size(rc, 0x14),  # EventPtr
        0x14: 2 + s + type_def_or_ref,  # Event
        0x15: simple_index_size(rc, 0x02) + simple_index_size(rc, 0x17),
        0x16: simple_index_size(rc, 0x17),  # PropertyPtr
        0x17: 2 + s + b,  # Property
        0x18: 2 + method_def_or_ref + has_semantics,  # MethodSemantics
        0x19: (simple_index_size(rc, 0x02) + method_def_or_ref + method_def_or_ref),
        0x1A: s,  # ModuleRef
        0x1B: b,  # TypeSpec
        0x1C: 2 + member_forwarded + s + simple_index_size(rc, 0x1A),
        0x1D: 4 + simple_index_size(rc, 0x04),  # FieldRVA
        0x20: 4 + 2 + 2 + 2 + 2 + 4 + b + s + s,  # Assembly
        0x21: 4,  # AssemblyProcessor
        0x22: 12,  # AssemblyOS
        # AssemblyRef (II.22.5): four u16 version parts, Flags(4), then
        # PublicKeyOrToken(blob) + Name(str) + Culture(str) + HashValue(blob).
        # Unlike Assembly it has no leading HashAlgId(4) and carries a trailing
        # blob, so its width is NOT the Assembly row's with b/s swapped.
        0x23: 2 + 2 + 2 + 2 + 4 + b + s + s + b,  # AssemblyRef
        0x24: 4 + simple_index_size(rc, 0x23),  # AssemblyRefProcessor
        0x25: 12 + simple_index_size(rc, 0x23),  # AssemblyRefOS
        0x26: 4 + s + implementation,  # File
        0x27: 0,  # ExportedType; fixed below
        0x28: 4 + 4 + s + implementation,  # ManifestResource
        0x29: simple_index_size(rc, 0x02) + implementation,  # NestedClass
        0x2A: 0,  # GenericParam; fixed below
        0x2B: simple_index_size(rc, 0x2A) + type_def_or_ref,
        0x2C: method_def_or_ref + b,  # MethodSpec
    }
    # ClassLayout: PackingSize(2)+ClassSize(4)+Parent TypeDef
    sizes[0x0F] = 2 + 4 + simple_index_size(rc, 0x02)
    # AssemblyProcessor
    sizes[0x21] = 4
    # ExportedType: Flags(4)+TypeDefId(4)+TypeName(str)+TypeNamespace(str)+Implementation
    sizes[0x27] = 4 + 4 + s + s + implementation
    # GenericParam: Number(2)+Flags(2)+Owner+Name
    sizes[0x2A] = 2 + 2 + type_or_method_def + s

    return sizes.get(table)
