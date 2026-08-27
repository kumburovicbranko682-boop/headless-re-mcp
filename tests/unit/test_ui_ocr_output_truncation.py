"""OCR must say when its text was cut at the capture bound.

run_bounded discards stdout past a per-stream cap, and that stdout is the OCR
transcript. Dropping the cap flag left a partial page reading exactly like a
complete one; these tests pin the disclosure that both backends now carry.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from headless_re_mcp.backends.common.bounded_run import Completed
from headless_re_mcp.core import ui_ocr


def test_run_ocr_propagates_capture_truncation(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run_bounded(command: list[str], **kwargs: object) -> Completed:
        return Completed(0, b"partial", b"", stdout_truncated=True)

    monkeypatch.setattr(ui_ocr, "run_bounded", fake_run_bounded)

    out = ui_ocr._run_ocr(["tesseract"], timeout=1.0)

    assert out.stdout == "partial"
    assert out.stdout_truncated is True


def test_run_ocr_keeps_untruncated_output_unflagged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run_bounded(command: list[str], **kwargs: object) -> Completed:
        return Completed(0, b"whole", b"", stdout_truncated=False)

    monkeypatch.setattr(ui_ocr, "run_bounded", fake_run_bounded)

    out = ui_ocr._run_ocr(["tesseract"], timeout=1.0)

    assert out.stdout == "whole"
    assert out.stdout_truncated is False


def test_tesseract_discloses_a_cut_transcript(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "tesseract"
    exe.write_text("#!/bin/sh\n")
    bmp = tmp_path / "capture.bmp"
    bmp.write_bytes(b"BMxx")

    def fake_run_ocr(
        command: list[str], *, timeout: float, env: object = None
    ) -> ui_ocr._OcrOutput:
        return ui_ocr._OcrOutput(0, "hello\nworld\n", "", stdout_truncated=True)

    monkeypatch.setattr(ui_ocr, "_run_ocr", fake_run_ocr)

    result = ui_ocr.ocr_bmp_tesseract(bmp, tesseract=exe)

    assert result["backend"] == "tesseract"
    assert result["truncated"] is True
    assert result["text"] == "hello\nworld"
    assert result["lines"] == ["hello", "world"]


def test_tesseract_marks_a_whole_transcript_untruncated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "tesseract"
    exe.write_text("#!/bin/sh\n")
    bmp = tmp_path / "capture.bmp"
    bmp.write_bytes(b"BMxx")

    def fake_run_ocr(
        command: list[str], *, timeout: float, env: object = None
    ) -> ui_ocr._OcrOutput:
        return ui_ocr._OcrOutput(0, "complete text", "", stdout_truncated=False)

    monkeypatch.setattr(ui_ocr, "_run_ocr", fake_run_ocr)

    result = ui_ocr.ocr_bmp_tesseract(bmp, tesseract=exe)

    assert result["truncated"] is False
    assert result["text"] == "complete text"


def test_windows_ocr_carries_a_truncated_field(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bmp = tmp_path / "capture.bmp"
    bmp.write_bytes(b"BMxx")
    payload = {
        "backend": "windows_ocr",
        "language": "en-US",
        "text": "hi",
        "lines": ["hi"],
        "path": str(bmp),
    }

    def fake_run_ocr(
        command: list[str], *, timeout: float, env: object = None
    ) -> ui_ocr._OcrOutput:
        return ui_ocr._OcrOutput(0, json.dumps(payload), "", stdout_truncated=False)

    monkeypatch.setattr(ui_ocr, "_run_ocr", fake_run_ocr)

    result = ui_ocr.ocr_bmp_windows(bmp)

    assert result["truncated"] is False
    assert result["text"] == "hi"


def test_windows_ocr_does_not_override_a_worker_truncated_field(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bmp = tmp_path / "capture.bmp"
    bmp.write_bytes(b"BMxx")
    payload = {
        "backend": "windows_ocr",
        "text": "hi",
        "lines": ["hi"],
        "path": str(bmp),
        "truncated": True,
    }

    def fake_run_ocr(
        command: list[str], *, timeout: float, env: object = None
    ) -> ui_ocr._OcrOutput:
        return ui_ocr._OcrOutput(0, json.dumps(payload), "", stdout_truncated=False)

    monkeypatch.setattr(ui_ocr, "_run_ocr", fake_run_ocr)

    result = ui_ocr.ocr_bmp_windows(bmp)

    assert result["truncated"] is True
