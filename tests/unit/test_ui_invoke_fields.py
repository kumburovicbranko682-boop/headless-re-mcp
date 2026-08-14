"""ui.invoke must name the action fields it actually returns."""

from __future__ import annotations

import ast
from pathlib import Path

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


def test_ui_invoke_names_hwnd_action_not_invoked() -> None:
    """The live catalog only listed the whitelist verbs.

    invoke_hwnd returns hwnd, action and backend for click/set_text, and
    parent_hwnd, message and control_id on the WM_COMMAND path. There is no
    invoked field. A caller looking for invoked after a successful
    PostMessage reads the click as a miss and invokes the same hwnd again.
    """
    described = " ".join(_tool_docstring("ui.invoke").split())
    assert "Answers with hwnd, action and backend" in described
    assert "no invoked field" in described
    worker = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "core"
        / "ui_win32.py"
    ).read_text(encoding="utf-8")
    start = worker.index("def invoke_hwnd")
    chunk = worker[start : worker.index("def _window_capture_size", start)]
    assert '"hwnd": hwnd' in chunk
    assert '"action": "invoke"' in chunk
    assert '"parent_hwnd": parent' in chunk
    assert '"message": "wm_command"' in chunk
    assert '"invoked"' not in chunk
