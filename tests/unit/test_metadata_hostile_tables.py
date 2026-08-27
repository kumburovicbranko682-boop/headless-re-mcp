"""Table row counts come out of the assembly, and the walker materialises them.

enumerate_metadata builds the whole table into a list before paging it, so the
declared row count decides how much work a request for twenty items does. A
TypeDef table claiming 0x7fffffff rows ran past twenty-five seconds and took
1.2 GB of heap, from a 60 KB file. That is a sample resisting analysis, which
is the ordinary case here rather than an exotic one.
"""

from __future__ import annotations

import struct
import time
import tracemalloc
from pathlib import Path

import pytest

from headless_re_mcp.dotnet.metadata_enum import enumerate_metadata

MANAGED = (
    Path(__file__).resolve().parents[2]
    / "artifacts" / "tools" / "de4dotEx-3.2.4-net48" / "AssemblyData.dll"
)

pytestmark = pytest.mark.skipif(
    not MANAGED.is_file(), reason="no managed assembly available to mutate"
)


def _file_offset(raw: bytes, rva: int) -> int:
    e_lfanew = struct.unpack_from("<I", raw, 0x3C)[0]
    coff = e_lfanew + 4
    sections = struct.unpack_from("<H", raw, coff + 2)[0]
    table = coff + 20 + struct.unpack_from("<H", raw, coff + 16)[0]
    for index in range(sections):
        base = table + index * 40
        virtual_address = struct.unpack_from("<I", raw, base + 12)[0]
        raw_size, raw_pointer = struct.unpack_from("<II", raw, base + 16)
        if virtual_address <= rva < virtual_address + max(raw_size, 1):
            return raw_pointer + (rva - virtual_address)
    raise AssertionError("rva is not inside any section")


def _tilde_stream(raw: bytes) -> int:
    e_lfanew = struct.unpack_from("<I", raw, 0x3C)[0]
    optional = e_lfanew + 24
    magic = struct.unpack_from("<H", raw, optional)[0]
    directories = optional + (112 if magic == 0x20B else 96)
    cli = _file_offset(raw, struct.unpack_from("<I", raw, directories + 14 * 8)[0])
    metadata = _file_offset(raw, struct.unpack_from("<I", raw, cli + 8)[0])

    version_length = struct.unpack_from("<I", raw, metadata + 12)[0]
    cursor = metadata + 16 + version_length
    streams = struct.unpack_from("<H", raw, cursor + 2)[0]
    cursor += 4
    for _ in range(streams):
        offset = struct.unpack_from("<I", raw, cursor)[0]
        name_start = cursor + 8
        end = raw.index(b"\0", name_start)
        cursor = name_start + ((end - name_start) // 4 + 1) * 4
        if raw[name_start:end] == b"#~":
            return metadata + offset
    raise AssertionError("no #~ stream in the fixture")


def _with_typedef_rows(value: int) -> bytes:
    raw = bytearray(MANAGED.read_bytes())
    # rows[] is packed in ascending table order for the bits set in `valid`;
    # this fixture has Module, TypeRef, TypeDef, so TypeDef is the third.
    offset = _tilde_stream(bytes(raw)) + 24 + 2 * 4
    raw[offset : offset + 4] = struct.pack("<I", value)
    return bytes(raw)


@pytest.mark.parametrize("declared", [0x7FFFFFFF, 0xFFFFFFFF])
def test_a_table_cannot_declare_more_rows_than_its_stream_holds(
    declared: int,
    tmp_path: Path,
) -> None:
    """The bound comes from the file: rows cannot run past the #~ stream."""
    path = tmp_path / "crafted.dll"
    path.write_bytes(_with_typedef_rows(declared))

    tracemalloc.start()
    started = time.perf_counter()
    page = enumerate_metadata(path, kind="types", offset=0, limit=20)
    elapsed = time.perf_counter() - started
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert elapsed < 5.0, f"{declared:#x} rows took {elapsed:.1f}s"
    assert peak < 64 * 1024 * 1024, f"{declared:#x} rows took {peak / 1024 / 1024:.0f} MB"
    assert page.total < 100_000, f"reported {page.total} rows from a 60 KB file"
    assert len(page.items) <= 20
    # The cap trims to what the stream holds; total is now far short of the
    # declared count, so the reply must say so rather than pass the slice off as
    # the whole table.
    assert page.rows_truncated is True
    assert page.declared_total == declared
    assert page.total < declared


def test_an_honest_assembly_enumerates_exactly_as_before() -> None:
    """The bound must not touch a file that was telling the truth."""
    page = enumerate_metadata(MANAGED, kind="types", offset=0, limit=20)

    assert page.total == 77
    assert len(page.items) == 20
    assert page.truncated is True
    # An honest table declares exactly what its stream holds, so the row-cap
    # verdict must stay off even though paging truncated the window.
    assert page.rows_truncated is False
    assert page.declared_total is None
