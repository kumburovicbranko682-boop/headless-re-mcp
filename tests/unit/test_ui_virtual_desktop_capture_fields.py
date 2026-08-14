"""ui.virtual_desktop.capture must name the BMP and degraded fields it returns."""

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


def test_ui_virtual_desktop_capture_is_bmp_with_degraded() -> None:
    """The live catalog mentioned degraded in prose and omitted the BMP fields.

    tests/integration/test_hidden_desktop_gate.py already reads
    data['degraded']. capture_hwnd_screenshot returns format bmp, path,
    width, height, degraded and degraded_reason; the service adds window
    and intrusion. There is no png field. A caller looking for png after
    a successful capture reads a painted frame as missing.
    """
    described = " ".join(_tool_docstring("ui.virtual_desktop.capture").split())
    assert "Answers with format bmp" in described
    assert "degraded" in described
    assert "no png field" in described
    worker = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "core"
        / "ui_win32.py"
    ).read_text(encoding="utf-8")
    start = worker.index("def capture_hwnd_screenshot")
    chunk = worker[start : worker.index("def wait_for_window", start)]
    returned = chunk[chunk.rindex("return {") :]
    assert '"format": "bmp"' in returned
    assert '"degraded"' in returned
    assert '"png"' not in returned
