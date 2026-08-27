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


def _stub_ocr_output(monkeypatch: pytest.MonkeyPatch, stdout: str) -> None:
    def fake_run(command: list[str], *, timeout: float, env: object = None) -> ui_ocr._OcrOutput:
        del command, timeout, env
        return ui_ocr._OcrOutput(0, stdout, "")

    monkeypatch.setattr(ui_ocr, "_run_ocr", fake_run)


@pytest.mark.parametrize(
    "stdout",
    [
        "this is not json\n",
        "[!] notice line only\n",
        '{"text": "ok"} trailing garbage that breaks the object\n',
        ("[" * 100_000) + ("]" * 100_000) + "\n",
    ],
)
def test_windows_ocr_maps_unparseable_output_to_a_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stdout: str
) -> None:
    """A worker line that is not the JSON result must not escape raw.

    json.loads raises JSONDecodeError (a ValueError) on a stray warning or a
    partial write, and RecursionError on a deeply nested flood. Either used to
    leave ocr_bmp_windows as an internal_error -- and an explicit
    backend="windows" call re-raises it -- instead of the backend_error every
    other failure in this module reports.
    """
    bitmap = tmp_path / "capture.bmp"
    bitmap.write_bytes(b"BM" + b"x" * 6)
    _stub_ocr_output(monkeypatch, stdout)

    with pytest.raises(UiPidBoundaryError) as caught:
        ui_ocr.ocr_bmp_windows(bitmap)

    assert caught.value.code == "backend_error"


def test_windows_ocr_returns_the_parsed_object_on_a_clean_last_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bitmap = tmp_path / "capture.bmp"
    bitmap.write_bytes(b"BM" + b"x" * 6)
    _stub_ocr_output(monkeypatch, 'warming up\n{"backend": "windows_ocr", "text": "hi"}\n')

    result = ui_ocr.ocr_bmp_windows(bitmap)

    assert result["backend"] == "windows_ocr"
    assert result["text"] == "hi"
