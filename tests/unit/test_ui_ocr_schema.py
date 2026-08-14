"""ui.ocr must refuse unknown backend strings at the tool schema."""

from __future__ import annotations

import re
from pathlib import Path

from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.ui import build_ui_tools


def test_ui_ocr_schema_matches_ocr_backend_whitelist() -> None:
    """The catalog accepted an unbounded OCR backend string.

    Measured: input schema backend has no pattern. ocr_hwnd only tries
    windows/windows_ocr/winrt/auto and tesseract. A caller that sends a
    2 MiB backend still occupies a worker until that check runs.
    """
    source = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "core"
        / "ui_ocr.py"
    ).read_text(encoding="utf-8")
    start = source.index("def ocr_hwnd")
    chunk = source[start:]
    assert '{"windows", "windows_ocr", "winrt", "auto"}' in chunk
    assert '{"tesseract", "auto"}' in chunk
    handler = next(
        binding.handler
        for binding in build_ui_tools(object())  # type: ignore[arg-type]
        if binding.name == "ui.ocr"
    )
    pattern = input_schema_for(handler)["properties"]["backend"]["pattern"]
    for key in ("auto", "windows", "windows_ocr", "winrt", "tesseract"):
        assert re.fullmatch(pattern, key), key
    assert re.fullmatch(pattern, "not_an_ocr_backend") is None
