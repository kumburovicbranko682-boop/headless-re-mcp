"""ui.text.set must refuse unknown backend strings at the tool schema."""

from __future__ import annotations

import re
from pathlib import Path

from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.ui import build_ui_tools


def test_ui_text_set_schema_matches_text_backend_whitelist() -> None:
    """The catalog accepted an unbounded text-set backend string.

    Measured: input schema backend has no pattern. ui_text_set only treats
    uia/uiautomation as UIA and silently uses WM_SETTEXT for every other
    string. A caller that asks for UIA under a typo still gets a successful
    WM_SETTEXT and retries as if ValuePattern ran.
    """
    source = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "core"
        / "service_ui.py"
    ).read_text(encoding="utf-8")
    start = source.index("def ui_text_set(")
    chunk = source[start : source.index("def ui_key(", start)]
    assert '{"uia", "uiautomation"}' in chunk
    handler = next(
        binding.handler
        for binding in build_ui_tools(object())  # type: ignore[arg-type]
        if binding.name == "ui.text.set"
    )
    pattern = input_schema_for(handler)["properties"]["backend"]["pattern"]
    for key in ("win32", "uia", "uiautomation"):
        assert re.fullmatch(pattern, key), key
    assert re.fullmatch(pattern, "not_a_text_backend") is None
