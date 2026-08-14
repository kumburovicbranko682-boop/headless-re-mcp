"""ui.window.close must refuse unknown close methods at the tool schema."""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.ui import build_ui_tools


def test_ui_window_close_schema_matches_close_method_whitelist() -> None:
    """The catalog accepted any close method string.

    Measured: input schema method has no pattern. close_hwnd only accepts
    nc_close, syscommand, wm_close and close. A caller that sends an arbitrary
    method still occupies a worker until that check runs.
    """
    source = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "core"
        / "ui_win32.py"
    ).read_text(encoding="utf-8")
    start = source.index("def close_hwnd")
    chunk = source[start : source.index("def set_window_text", start)]
    assert '{"nc_close", "syscommand", "wm_close", "close"}' in chunk
    handler = next(
        binding.handler
        for binding in build_ui_tools(object())  # type: ignore[arg-type]
        if binding.name == "ui.window.close"
    )
    props = input_schema_for(handler)["properties"]
    assert props["method"]["pattern"] == "^(nc_close|syscommand|wm_close|close)$"
