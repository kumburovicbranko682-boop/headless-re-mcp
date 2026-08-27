"""A clamped enumeration must say so, not report the floor as the total.

Two bounds cut ``enumerate_metadata`` listings short by design: table rows are
clamped to what the #~ stream physically holds (so a hostile row count cannot
balloon time and memory), and #Strings collection stops at ``MAX_STRINGS``
(which large real assemblies exceed). Both clamps were silent -- the last page
came back ``truncated=False`` with ``total`` equal to the clamped count, and a
caller had no way to tell a complete listing from one that was cut short.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from headless_re_mcp.dotnet import metadata_enum
from headless_re_mcp.dotnet.metadata_enum import MAX_STRINGS, enumerate_metadata

_TYPEDEF = 0x02
# TypeDef row with 2-byte heaps and tiny row counts: Flags(4) + Name(2) +
# Namespace(2) + Extends(coded TypeDefOrRef, 2) + FieldList(2) + MethodList(2).
_TYPEDEF_ROW_SIZE = 14


def _ctx(
    *,
    tables: bytes = b"",
    strings: bytes = b"",
    row_counts: dict[int, int] | None = None,
) -> metadata_enum._MetaCtx:
    return metadata_enum._MetaCtx(
        path=Path("synthetic.dll"),
        pe_data=b"",
        layout=None,
        meta=b"",
        stream_map={},
        tables=tables,
        strings=strings,
        heap_sizes=0,
        string_index_size=2,
        blob_index_size=2,
        guid_index_size=2,
        row_counts=row_counts or {},
        table_data_offset=0,
    )


def _wire(monkeypatch: pytest.MonkeyPatch, ctx: metadata_enum._MetaCtx) -> None:
    monkeypatch.setattr(metadata_enum, "inspect_dotnet", lambda *a, **k: None)
    monkeypatch.setattr(metadata_enum, "_load_metadata_context", lambda _path: ctx)


def _typedef_row(name_index: int) -> bytes:
    return struct.pack("<IHHHHH", 0, name_index, 0, 0, 1, 1)


def test_a_lying_row_count_sets_source_truncated(monkeypatch: pytest.MonkeyPatch) -> None:
    """Declaring 5 TypeDef rows over a stream holding 2 must flag the page."""
    tables = _typedef_row(1) + _typedef_row(7)
    assert len(tables) == 2 * _TYPEDEF_ROW_SIZE
    ctx = _ctx(tables=tables, strings=b"\0Alpha\0Beta\0", row_counts={_TYPEDEF: 5})
    _wire(monkeypatch, ctx)

    page = enumerate_metadata("synthetic.dll", "types", limit=20)

    assert [item["name"] for item in page.items] == ["Alpha", "Beta"]
    assert page.total == 2
    assert page.truncated is False  # pagination: this window is the last one
    assert page.source_truncated is True
    assert "source truncated" in page.note
    assert page.to_dict()["source_truncated"] is True


def test_an_honest_table_stays_clean(monkeypatch: pytest.MonkeyPatch) -> None:
    """A row count the stream can hold must not be flagged."""
    tables = _typedef_row(1) + _typedef_row(7)
    ctx = _ctx(tables=tables, strings=b"\0Alpha\0Beta\0", row_counts={_TYPEDEF: 2})
    _wire(monkeypatch, ctx)

    page = enumerate_metadata("synthetic.dll", "types", limit=20)

    assert page.total == 2
    assert page.source_truncated is False
    assert "source truncated" not in page.note
    assert page.to_dict()["source_truncated"] is False


def _strings_heap(entries: int) -> bytes:
    return b"\0" + b"".join(b"s%d\0" % i for i in range(entries))


def test_the_strings_cap_is_reported_not_silent(monkeypatch: pytest.MonkeyPatch) -> None:
    """A heap holding more than MAX_STRINGS must flag every page, incl. the last.

    ``truncated`` stays a pure pagination signal (a pager looping on it must
    terminate at ``total``), so on the final window it is False while
    ``source_truncated`` says the listing itself was cut short.
    """
    ctx = _ctx(strings=_strings_heap(MAX_STRINGS + 1))
    _wire(monkeypatch, ctx)

    page = enumerate_metadata("synthetic.dll", "strings", offset=MAX_STRINGS - 2, limit=64)

    assert page.total == MAX_STRINGS
    assert len(page.items) == 2
    assert page.truncated is False
    assert page.source_truncated is True
    assert "source truncated" in page.note


def test_a_heap_of_exactly_the_cap_is_not_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    """The flag means entries were dropped, not merely that the cap was reached."""
    ctx = _ctx(strings=_strings_heap(MAX_STRINGS))
    _wire(monkeypatch, ctx)

    page = enumerate_metadata("synthetic.dll", "strings", offset=MAX_STRINGS - 2, limit=64)

    assert page.total == MAX_STRINGS
    assert page.source_truncated is False
    assert "source truncated" not in page.note
