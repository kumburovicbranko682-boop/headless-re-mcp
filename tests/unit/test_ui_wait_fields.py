"""ui.wait must name the match fields it actually returns."""

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


def test_ui_wait_nests_hwnd_under_window() -> None:
    """The live catalog only said it waits for a matching window.

    tests/integration/test_m10_ui_interact_gate.py already reads
    data['matched']. wait_for_window returns matched, window and waited_ms;
    the service adds backend win32_poll. hwnd lives under window, not at
    the top level, and there is no found field. A caller looking for hwnd
    after a successful wait reads the handle as missing and retries.
    """
    described = " ".join(_tool_docstring("ui.wait").split())
    assert "Answers with matched, window" in described
    assert "waited_ms" in described
    assert "no hwnd field at the top level" in described
    assert "no found field" in described
    worker = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "core"
        / "ui_win32.py"
    ).read_text(encoding="utf-8")
    start = worker.index("def wait_for_window")
    chunk = worker[start:]
    assert '"matched": True' in chunk
    assert '"window": found' in chunk
    assert '"waited_ms"' in chunk
    assert '"found"' not in chunk
