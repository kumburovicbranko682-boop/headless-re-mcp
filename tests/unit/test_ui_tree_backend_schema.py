"""ui.tree must refuse unknown backend strings at the tool schema."""

from __future__ import annotations

import re
from pathlib import Path

from headless_re_mcp.tools.binding import input_schema_for
from headless_re_mcp.tools.ui import build_ui_tools


def test_ui_tree_schema_matches_tree_backend_whitelist() -> None:
    """The catalog accepted an unbounded tree backend string.

    Measured: input schema backend has no pattern. ui_tree only treats
    uia/uiautomation as UIA and silently walks Win32 for every other
    string. A caller that asks for UIA under a typo still gets a Win32
    tree and retries as if the UIA walk ran.
    """
    source = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "core"
        / "service_ui.py"
    ).read_text(encoding="utf-8")
    start = source.index("def ui_tree(")
    chunk = source[start : source.index("def ui_resolve(", start)]
    assert '{"uia", "uiautomation"}' in chunk
    handler = next(
        binding.handler
        for binding in build_ui_tools(object())  # type: ignore[arg-type]
        if binding.name == "ui.tree"
    )
    pattern = input_schema_for(handler)["properties"]["backend"]["pattern"]
    for key in ("win32", "uia", "uiautomation"):
        assert re.fullmatch(pattern, key), key
    assert re.fullmatch(pattern, "not_a_tree_backend") is None
