from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.detection.pe import scan_pe


@pytest.mark.parametrize(
    "blob",
    [
        b"",
        b"MZ",
        b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00",
        b"\xff" * 256,
        b"MZ" + bytes(range(256)) * 8,
        # Truncated PE with large claimed sizes
        b"MZ" + b"\x00" * 58 + (0x80).to_bytes(4, "little") + b"\x00" * 0x40 + b"PE\x00\x00",
    ],
)
def test_pe_parser_truncation_and_overflow(blob: bytes, tmp_path: Path) -> None:
    path = tmp_path / "sample.bin"
    path.write_bytes(blob)
    try:
        report = scan_pe(path)
    except Exception as exc:  # noqa: BLE001 — must stay bounded / typed
        # Fail-closed is fine; unexpected crash types are not.
        assert type(exc).__name__ not in {"MemoryError", "RecursionError"}
        return
    assert report is not None
