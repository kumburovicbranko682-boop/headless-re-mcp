"""ui.screenshot must name the BMP artifact fields it actually returns."""

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


def test_ui_screenshot_is_bmp_with_artifact_id() -> None:
    """The live catalog omitted format and artifact_id.

    tests/unit/test_unattended_resource_bounds.py already reads
    result.data['artifact_id'] after a capture. The Win32 helper returns
    format bmp, path, width and height, and has no png field. A caller
    looking for png after a successful capture reads the bitmap as missing.
    """
    described = " ".join(_tool_docstring("ui.screenshot").split())
    assert "Answers with format bmp" in described
    assert "artifact_id" in described
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
    assert '"format": "bmp"' in chunk
    assert '"png"' not in chunk
