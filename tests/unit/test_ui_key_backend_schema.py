"""ui.key must refuse unknown backend strings at the tool schema."""

from __future__ import annotations

import re
from pathlib import Path

from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.ui import build_ui_tools


def test_ui_key_schema_matches_key_backend_whitelist() -> None:
    """The catalog accepted an unbounded key backend string.

    Measured: input schema backend has no pattern. ui_key only treats
    sendinput/input as SendInput and silently uses WM_* for every other
    string. A caller that asks for SendInput under a typo still gets a
    successful WM_CHAR and retries as if the foreground check ran.
    """
    source = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "core"
        / "service_ui.py"
    ).read_text(encoding="utf-8")
    start = source.index("def ui_key(")
    chunk = source[start : source.index("def ui_invoke(", start)]
    assert '{"sendinput", "input"}' in chunk
    handler = next(
        binding.handler
        for binding in build_ui_tools(object())  # type: ignore[arg-type]
        if binding.name == "ui.key"
    )
    pattern = input_schema_for(handler)["properties"]["backend"]["pattern"]
    for key in ("win32", "sendinput", "input"):
        assert re.fullmatch(pattern, key), key
    assert re.fullmatch(pattern, "not_a_key_backend") is None
