"""ui.window.close must name the fields the closer actually returns."""

from __future__ import annotations

import ast
from pathlib import Path

from headless_re_mcp.core.ui_win32 import close_hwnd
from headless_re_mcp.tools.ui import build_ui_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_ui_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            for keyword in decorator.keywords:
                if (
                    keyword.arg == "name"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value == name
                ):
                    return ast.get_docstring(node) or ""
    return ""


def test_ui_window_close_puts_the_result_in_action_not_closed() -> None:
    """The catalog said close and never named the payload.

    Measured: close_hwnd returns hwnd, action, method, backend,
    shown_noactivate, foreground_required and injection_required. There is
    no closed field. Looking for closed after a successful SC_CLOSE reads
    as a miss, so the overnight driver posts WM_CLOSE again.
    """
    source = Path(close_hwnd.__code__.co_filename).read_text(encoding="utf-8")
    start = source.index("def close_hwnd(")
    chunk = source[start : source.index("def set_window_text(", start)]
    returned = chunk[chunk.rindex("return {") :]
    assert '"hwnd"' in returned
    assert '"action"' in returned
    assert '"method"' in returned
    assert '"backend"' in returned
    assert '"closed"' not in returned
    described = _tool_docstring("ui.window.close")
    assert "Answers with hwnd" in described
    assert "method" in described
    assert "no closed" in described.replace("\n", " ")
