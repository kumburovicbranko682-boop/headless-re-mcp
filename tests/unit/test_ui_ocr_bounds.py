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


def test_malformed_worker_output_is_a_backend_error_not_an_incident(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A non-JSON last line from the OCR worker must not escape as a raw crash.

    The worker's stdout is not a clean JSON-only channel: WinRT/pythonnet
    startup or any imported library can print a stray line that ends up last.
    Every other failure in ocr_bmp_windows is a structured UiPidBoundaryError;
    an unguarded json.loads would instead let a JSONDecodeError propagate,
    which the error boundary records as an internal_error and mints an incident
    for -- misreporting a backend that merely returned malformed output as an
    internal defect. The parse must fail closed as backend_error.
    """
    bitmap = tmp_path / "capture.bmp"
    bitmap.write_bytes(b"BM" + b"x" * 6)

    def fake_run_ocr(command: list[str], **_: object) -> ui_ocr._OcrOutput:
        return ui_ocr._OcrOutput(0, "WinRT: COM initialized\nnot-json-at-all", "")

    monkeypatch.setattr(ui_ocr, "_run_ocr", fake_run_ocr)

    with pytest.raises(UiPidBoundaryError) as caught:
        ui_ocr.ocr_bmp_windows(bitmap)

    assert caught.value.code == "backend_error"
    assert "unparseable" in str(caught.value)


def test_well_formed_worker_output_is_returned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The guard leaves the ordinary success path intact.

    Non-vacuous companion to the malformed-output test: a valid JSON object on
    the last line still parses and returns, so the new try/except narrows only
    the failure it names and does not swallow good output.
    """
    bitmap = tmp_path / "capture.bmp"
    bitmap.write_bytes(b"BM" + b"x" * 6)

    def fake_run_ocr(command: list[str], **_: object) -> ui_ocr._OcrOutput:
        return ui_ocr._OcrOutput(0, '{"backend": "windows_ocr", "text": "hi"}', "")

    monkeypatch.setattr(ui_ocr, "_run_ocr", fake_run_ocr)

    assert ui_ocr.ocr_bmp_windows(bitmap) == {"backend": "windows_ocr", "text": "hi"}
