"""Cover the Windows OCR subprocess entry point.

``core/_windows_ocr_worker.py`` is spawned as ``python -m ...worker <path> <lang>``
so the real OCR runs in a separate process. Its ``main`` reads the two argv
positionals and prints the OCR result as a single JSON line on stdout. The real
OCR is Windows-only, so the in-process OCR call is replaced with a stub; this
exercises the argv wiring and the JSON serialization on any platform.
"""

from __future__ import annotations

import json
import sys

import pytest

import headless_re_mcp.core._windows_ocr_worker as worker


def test_main_prints_ocr_result_as_a_json_line(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    captured: dict[str, object] = {}

    def fake_ocr(path: str, *, language: str) -> dict[str, object]:
        captured["path"] = path
        captured["language"] = language
        return {"text": "hello world", "lines": ["hello world"], "confidence": 0.9}

    monkeypatch.setattr(worker, "_ocr_bmp_windows_inprocess", fake_ocr)
    monkeypatch.setattr(sys, "argv", ["worker", r"C:\tmp\shot.bmp", "en-US"])

    worker.main()

    out = capsys.readouterr().out
    # Exactly one JSON document is emitted and it round-trips.
    assert json.loads(out) == {
        "text": "hello world",
        "lines": ["hello world"],
        "confidence": 0.9,
    }
    # The two positionals are forwarded as path and language.
    assert captured == {"path": r"C:\tmp\shot.bmp", "language": "en-US"}


def test_main_preserves_non_ascii_without_escaping(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # ensure_ascii=False, so non-ASCII OCR text is written through literally.
    monkeypatch.setattr(
        worker,
        "_ocr_bmp_windows_inprocess",
        lambda path, *, language: {"text": "\u4f60\u597d"},
    )
    monkeypatch.setattr(sys, "argv", ["worker", "img.bmp", "zh-Hans"])

    worker.main()

    out = capsys.readouterr().out
    assert "\u4f60\u597d" in out
    assert json.loads(out) == {"text": "\u4f60\u597d"}


def test_main_requires_both_positionals(monkeypatch: pytest.MonkeyPatch) -> None:
    # Missing the language argument is an IndexError, surfaced to the caller
    # (the parent maps a non-zero worker exit into an OCR failure).
    monkeypatch.setattr(sys, "argv", ["worker", "only-path.bmp"])
    with pytest.raises(IndexError):
        worker.main()
