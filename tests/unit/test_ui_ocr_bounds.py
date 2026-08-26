from __future__ import annotations

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
