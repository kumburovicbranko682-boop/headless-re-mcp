"""ui.text.set must refuse oversized WM_SETTEXT at the tool schema."""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.ui import build_ui_tools


def test_ui_text_set_schema_matches_win32_char_cap() -> None:
    """The catalog accepted an unbounded WM_SETTEXT payload.

    Measured: input schema text has no maxLength. Win32 set_window_text and
    UIA set_value_uia both refuse above 4096 characters. A caller that pastes
    a 2 MiB string still occupies a worker until that check runs.
    """
    source = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "core"
        / "ui_win32.py"
    ).read_text(encoding="utf-8")
    assert "_MAX_TEXT_CHARS = 4096" in source
    handler = next(
        binding.handler
        for binding in build_ui_tools(object())  # type: ignore[arg-type]
        if binding.name == "ui.text.set"
    )
    props = input_schema_for(handler)["properties"]
    assert props["text"]["maxLength"] == 4096
