from __future__ import annotations

import tracemalloc
from pathlib import Path

import pytest

from headless_re_mcp.core import ui_ocr
from headless_re_mcp.core.windows import UiPidBoundaryError


def test_ocr_bitmap_read_is_byte_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ui_ocr, "_MAX_OCR_INPUT_BYTES", 8)
    bitmap = tmp_path / "capture.bmp"
    bitmap.write_bytes(b"BM" + b"x" * 8)

    with pytest.raises(UiPidBoundaryError, match="safety limit") as caught:
        ui_ocr._read_bounded_bmp(bitmap)

    assert caught.value.details["max_bytes"] == 8


def test_ocr_bitmap_read_accepts_the_exact_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ui_ocr, "_MAX_OCR_INPUT_BYTES", 8)
    bitmap = tmp_path / "capture.bmp"
    payload = b"BM" + b"x" * 6
    bitmap.write_bytes(payload)

    assert ui_ocr._read_bounded_bmp(bitmap) == payload


def test_ocr_bitmap_read_allocation_tracks_file_not_the_cap(tmp_path: Path) -> None:
    """A small screenshot must not cost the whole 128 MiB cap in transient heap.

    ``_read_bounded_bmp`` reads up to ``_MAX_OCR_INPUT_BYTES + 1`` bytes, but a
    buffered ``read(n)`` allocates all ``n`` bytes before shrinking. The old
    single-call ``read(cap + 1)`` therefore spiked the full 128 MiB cap on every
    OCR call, whatever the image's real size, and OCR runs on every ui.ocr call
    -- constantly in a UI-driving loop. Pin that the read now allocates in
    proportion to the file so nobody restores the one-shot read.
    """
    bitmap = tmp_path / "capture.bmp"
    bitmap.write_bytes(b"BM" + b"x" * (64 * 1024))  # ~64 KiB, cap stays 128 MiB

    tracemalloc.start()
    try:
        data = ui_ocr._read_bounded_bmp(bitmap)
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert len(data) == bitmap.stat().st_size
    # The pre-fix peak was the full 128 MiB cap; anything near it means the read
    # is again sizing to the cap rather than the file.
    assert peak < 8 * 1024 * 1024, f"reading a {len(data)}-byte bmp peaked at {peak} bytes"
