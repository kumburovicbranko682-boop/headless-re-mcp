"""ui.windows.list must name the field the enumerator actually returns."""

from __future__ import annotations

import ast
from pathlib import Path

from headless_re_mcp.core.service_ui import _ui_finalize_windows
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


def test_ui_windows_list_puts_hwnds_in_windows_not_items() -> None:
    """The catalog said list windows and never named the list field.

    Measured: _ui_finalize_windows keeps windows and sets count. There is no
    items or tree field. Looking for items after a successful list reads as
    the debuggee having no windows, so the agent retries or drives clicks
    against hwnds it never got.
    """
    payload = _ui_finalize_windows(
        {"windows": [{"hwnd": 1, "pid": 7, "class_name": "A", "title": "t"}]},
        {"allowed": frozenset({7}), "debuggee_pid": 7},
    )
    assert "items" not in payload
    assert "tree" not in payload
    assert payload["count"] == 1
    assert payload["windows"][0]["hwnd"] == 1
    described = _tool_docstring("ui.windows.list")
    assert "Answers with windows" in described
    assert "no items" in described
    assert "no tree field" in described
