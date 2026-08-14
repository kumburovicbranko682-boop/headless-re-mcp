"""ui.invoke must refuse unknown Win32 actions at the tool schema."""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.ui import build_ui_tools


def test_ui_invoke_schema_matches_win32_action_whitelist() -> None:
    """The catalog accepted any invoke action string.

    Measured: input schema action has no pattern. invoke_hwnd only accepts
    the _INVOKE_WHITELIST keys. A caller that sends an arbitrary message name
    still occupies a worker until that check runs.
    """
    source = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "core"
        / "ui_win32.py"
    ).read_text(encoding="utf-8")
    start = source.index("_INVOKE_WHITELIST")
    chunk = source[start : source.index("def _user32", start)]
    names = (
        "click",
        "bm_click",
        "set_text",
        "wm_settext",
        "command",
        "wm_command",
        "close",
        "wm_close",
    )
    for name in names:
        assert f'"{name}":' in chunk
    handler = next(
        binding.handler
        for binding in build_ui_tools(object())  # type: ignore[arg-type]
        if binding.name == "ui.invoke"
    )
    props = input_schema_for(handler)["properties"]
    assert props["action"]["pattern"] == "^(" + "|".join(names) + ")$"
