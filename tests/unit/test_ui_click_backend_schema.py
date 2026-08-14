"""ui.click must refuse unknown backend strings at the tool schema."""

from __future__ import annotations

import re
from pathlib import Path

from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.ui import build_ui_tools


def test_ui_click_schema_matches_click_backend_whitelist() -> None:
    """The catalog accepted an unbounded click backend string.

    Measured: input schema backend has no pattern. ui_click only treats
    uia/uiautomation and sendinput/input as those backends and silently
    uses PostMessage for every other string. A caller that asks for
    SendInput under a typo still gets a successful BM_CLICK, so the
    overnight driver retries as if the foreground PID check ran.
    """
    source = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "core"
        / "service_ui.py"
    ).read_text(encoding="utf-8")
    start = source.index("def ui_click(")
    chunk = source[start : source.index("def ui_click_at(", start)]
    assert '{"uia", "uiautomation"}' in chunk
    assert '{"sendinput", "input"}' in chunk
    handler = next(
        binding.handler
        for binding in build_ui_tools(object())  # type: ignore[arg-type]
        if binding.name == "ui.click"
    )
    pattern = input_schema_for(handler)["properties"]["backend"]["pattern"]
    for key in ("win32", "uia", "uiautomation", "sendinput", "input"):
        assert re.fullmatch(pattern, key), key
    assert re.fullmatch(pattern, "not_a_click_backend") is None
