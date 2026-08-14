"""ui.key must name the key fields it actually returns."""

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


def test_ui_key_names_hwnd_action_not_sent() -> None:
    """The live catalog only said it sends a key.

    send_key returns hwnd, action, backend and either text or vk. There is
    no sent field. A caller looking for sent after a successful WM_CHAR
    reads the key as dropped and posts the same character again.
    """
    described = " ".join(_tool_docstring("ui.key").split())
    assert "Answers with hwnd, action, backend" in described
    assert "no sent field" in described
    worker = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "core"
        / "ui_win32.py"
    ).read_text(encoding="utf-8")
    start = worker.index("def send_key")
    chunk = worker[start : worker.index("def invoke_hwnd", start)]
    assert '"hwnd": hwnd' in chunk
    assert '"action": "key"' in chunk
    assert '"backend": "win32_wm_char"' in chunk
    assert '"sent"' not in chunk
