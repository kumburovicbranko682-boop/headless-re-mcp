"""Contract test for the isolated Windows OCR subprocess entry point.

``core._windows_ocr_worker`` is the ``python -m`` target that
``ui_ocr.ocr_bmp_windows`` spawns to run WinRT OCR away from the UIA/COM state
of the main process. Its whole job is to take a bitmap path and a language off
``argv``, run the in-process OCR, and print the result as one JSON line the
parent parses back. These tests pin that argv-to-call wiring and, importantly,
that Unicode OCR text is emitted verbatim rather than ``\\uXXXX``-escaped, which
is what lets the parent recover non-Latin recognized text intact.
"""

from __future__ import annotations

import json
import sys
from typing import Any

import pytest

import headless_re_mcp.core._windows_ocr_worker as worker


def test_main_forwards_argv_and_prints_the_result_as_one_json_line(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    seen: dict[str, Any] = {}

    def fake_ocr(path: str, *, language: str = "en-US") -> dict[str, Any]:
        seen["path"] = path
        seen["language"] = language
        return {"ok": True, "lines": ["hello"]}

    monkeypatch.setattr(worker, "_ocr_bmp_windows_inprocess", fake_ocr)
    monkeypatch.setattr(sys, "argv", ["worker", "/tmp/frame.bmp", "de-DE"])

    worker.main()

    assert seen == {"path": "/tmp/frame.bmp", "language": "de-DE"}
    out = capsys.readouterr().out
    # Exactly one line, and it round-trips to the returned payload.
    assert out.count("\n") == 1
    assert json.loads(out) == {"ok": True, "lines": ["hello"]}


def test_main_emits_unicode_text_unescaped(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    payload = {"ok": True, "lines": ["登録", "café"]}
    monkeypatch.setattr(worker, "_ocr_bmp_windows_inprocess", lambda path, *, language: payload)
    monkeypatch.setattr(sys, "argv", ["worker", "shot.bmp", "ja-JP"])

    worker.main()

    out = capsys.readouterr().out
    # ensure_ascii=False: the raw glyphs are on the wire, not \\uXXXX escapes.
    assert "登録" in out
    assert "\\u" not in out
    assert json.loads(out) == payload


def test_main_requires_both_a_path_and_a_language(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The worker is an internal, fixed-arity target; a missing language is a
    # caller-side wiring bug, and surfacing it as IndexError (a nonzero exit)
    # is the honest failure rather than silently defaulting the language.
    monkeypatch.setattr(worker, "_ocr_bmp_windows_inprocess", lambda path, *, language: {})
    monkeypatch.setattr(sys, "argv", ["worker", "only-a-path.bmp"])

    with pytest.raises(IndexError):
        worker.main()
