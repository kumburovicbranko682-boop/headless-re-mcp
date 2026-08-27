"""JS/WASM gate: real wabt, exercising the oversized-output spill.

The unit tests force the inline cap low and mock the subprocess, so a wabt
release that changed wasm2wat's output shape, or a regression in the spill
wiring, would pass every unit test and only surface in production. This gate
builds a genuinely valid .wasm whose text form (WAT) runs past the 400 KB
inline cap -- a large data segment is the cheapest way there -- and drives the
real service so wasm2wat actually runs and the full dump lands on disk. It
skips with an explicit "skip != pass" when wabt is not installed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import WasmClient
from headless_re_mcp.core.service import AnalysisService


def _leb128(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _section(section_id: int, body: bytes) -> bytes:
    return bytes([section_id]) + _leb128(len(body)) + body


def _wasm_with_big_data(data_bytes: int) -> bytes:
    """A minimal, valid module carrying one large active data segment.

    wasm2wat prints each non-printable data byte as a ``\\xx`` escape, so a
    ~200 KB segment expands to ~600 KB of WAT -- comfortably over the inline
    cap without needing thousands of hand-encoded functions.
    """
    magic = b"\x00asm\x01\x00\x00\x00"
    # One memory, sized to hold the segment (min pages, each 64 KiB).
    pages = (data_bytes + 65535) // 65536 + 1
    memory = _section(5, b"\x01" + b"\x00" + _leb128(pages))
    # Active data segment: memory 0, offset i32.const 0, then the byte vector.
    segment = b"\x00" + b"\x41\x00\x0b" + _leb128(data_bytes) + (b"\xAA" * data_bytes)
    data = _section(11, b"\x01" + segment)
    return magic + memory + data


def _wabt_available() -> bool:
    return WasmClient(AnalysisService().settings.wabt).available


@pytest.mark.integration
def test_wasm_wat_spills_a_large_disassembly_to_a_file(tmp_path: Path) -> None:
    """A WAT dump bigger than the inline cap must stay fully retrievable.

    Before the spill, the caller got the first 400 KB of the disassembly and no
    way to reach the rest. Build a module whose WAT is ~600 KB, convert it, and
    assert wat_path holds the whole thing (byte-for-byte the reported length),
    that it is larger than the inline slice, and that it is real WAT for our
    module.
    """
    if not _wabt_available():
        pytest.skip("wabt not installed — WASM WAT spill gate not run (skip != pass)")
    module = tmp_path / "big.wasm"
    module.write_bytes(_wasm_with_big_data(200_000))

    service = AnalysisService()
    spilled: Path | None = None
    try:
        result = service.wasm_wat(str(module))
        assert result.ok, result.error
        data = result.data
        assert data is not None
        assert data["truncated"] is True
        assert "wat_path" in data, data
        spilled = Path(data["wat_path"])
        assert spilled.is_file()
        full = spilled.read_bytes()
        assert len(full) == data["bytes"]
        # The inline copy is the bounded slice; the file is the whole dump.
        assert len(full) > len(str(data["wat"]).encode("utf-8"))
        text = full.decode("utf-8", errors="ignore")
        assert "(module" in text
        assert "(data" in text
    finally:
        service.close_all()
        if spilled is not None:
            spilled.unlink(missing_ok=True)


@pytest.mark.integration
def test_wasm_wat_inlines_a_small_module_without_spilling(tmp_path: Path) -> None:
    """A short conversion returns inline and leaves no spill file behind."""
    if not _wabt_available():
        pytest.skip("wabt not installed — WASM WAT spill gate not run (skip != pass)")
    module = tmp_path / "empty.wasm"
    module.write_bytes(b"\x00asm\x01\x00\x00\x00")

    service = AnalysisService()
    try:
        result = service.wasm_wat(str(module))
        assert result.ok, result.error
        data = result.data
        assert data is not None
        assert data["truncated"] is False
        assert "wat_path" not in data
        assert "(module" in str(data["wat"])
    finally:
        service.close_all()
