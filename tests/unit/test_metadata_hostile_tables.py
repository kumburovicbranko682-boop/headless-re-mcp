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

_DE4DOT = (
    Path(__file__).resolve().parents[2]
    / "artifacts" / "tools" / "de4dotEx-3.2.4-net48" / "AssemblyData.dll"
)
_FIXTURE = (
    Path(__file__).resolve().parents[2] / "fixtures" / "dotnet" / "minimal_assembly.exe"
)
# The row-count bound is size-independent: a table cannot declare more rows than
# its #~ stream holds, whether the file is a 60 KB de4dot build or the 1 KB
# committed fixture. Prefer the richer real assembly when a dev has one, but
# fall back to the fixture so this DoS guard actually runs in CI instead of
# skipping -- skip is not a pass on the path that once took 1.2 GB of heap.
MANAGED = _DE4DOT if _DE4DOT.is_file() else _FIXTURE

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


_TYPEDEF_TABLE = 0x02


def _typedef_rowcount_offset(raw: bytes) -> int:
    """File offset of the TypeDef row count inside the #~ header.

    rows[] is packed in ascending table order for the bits set in ``valid``, so
    TypeDef's slot is at ordinal = (number of set bits below 0x02). Computing it
    from ``valid`` rather than hardcoding a position lets this run against any
    assembly -- the de4dot build has TypeRef before TypeDef, the minimal fixture
    does not.
    """
    tilde = _tilde_stream(raw)
    valid = struct.unpack_from("<Q", raw, tilde + 8)[0]
    ordinal = bin(valid & ((1 << _TYPEDEF_TABLE) - 1)).count("1")
    return tilde + 24 + ordinal * 4


def _declared_typedef_rows(raw: bytes) -> int:
    return struct.unpack_from("<I", raw, _typedef_rowcount_offset(raw))[0]


def _with_typedef_rows(value: int) -> bytes:
    raw = bytearray(MANAGED.read_bytes())
    offset = _typedef_rowcount_offset(bytes(raw))
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


def test_an_honest_assembly_enumerates_exactly_as_before() -> None:
    """The bound must not touch a file that was telling the truth.

    The expected count is read straight from the file's own TypeDef row count so
    the assertion holds for whichever assembly backs the test -- the de4dot build
    reports 77 types, the committed fixture reports 2.
    """
    declared = _declared_typedef_rows(MANAGED.read_bytes())
    page = enumerate_metadata(MANAGED, kind="types", offset=0, limit=20)

    assert page.total == declared
    assert len(page.items) == min(declared, 20)
    assert page.truncated is (declared > 20)
