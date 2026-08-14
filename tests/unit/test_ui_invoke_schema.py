"""ui.invoke must refuse oversized set_text at the tool schema."""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.ui import build_ui_tools


def test_ui_invoke_schema_matches_win32_char_cap() -> None:
    """The catalog accepted an unbounded invoke text payload.

    Measured: input schema text has no maxLength. invoke_hwnd set_text calls
    set_window_text, which refuses above 4096 characters. A caller that pastes
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
    assert "return set_window_text(hwnd, text, allowed_pids" in source
    handler = next(
        binding.handler
        for binding in build_ui_tools(object())  # type: ignore[arg-type]
        if binding.name == "ui.invoke"
    )
    props = input_schema_for(handler)["properties"]
    text_schema = next(item for item in props["text"]["anyOf"] if item.get("type") == "string")
    assert text_schema["maxLength"] == 4096
