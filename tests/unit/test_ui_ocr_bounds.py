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


def test_ocr_windows_maps_a_non_json_last_line_to_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A polluted worker stdout must not escape as a raw JSONDecodeError.

    Every other exit from ocr_bmp_windows raises UiPidBoundaryError, but the
    worker's final stdout line was trusted to be the JSON it prints. winsdk
    import chatter or any library writing to stdout can make the last line
    something else, and it then escaped as an internal incident instead of the
    backend_error the function's contract promises.
    """
    bitmap = tmp_path / "capture.bmp"
    bitmap.write_bytes(b"BM" + b"x" * 6)

    def fake_run_ocr(command: list[str], *, timeout: float, env: object = None) -> object:
        del command, timeout, env
        return ui_ocr._OcrOutput(0, "winsdk: loaded plugin\nnot-json-at-all", "")

    monkeypatch.setattr(ui_ocr, "_run_ocr", fake_run_ocr)

    with pytest.raises(UiPidBoundaryError) as caught:
        ui_ocr.ocr_bmp_windows(bitmap)
    assert caught.value.code == "backend_error"
    assert "malformed JSON" in str(caught.value)
