"""ui.ocr must name the text and artifact fields it actually returns."""

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


def test_ui_ocr_names_text_lines_and_ocr_backend() -> None:
    """The live catalog only said it OCRs via screenshot.

    tests/integration/test_m10_ui_backends_gate.py already reads
    data['ocr_backend'] and data['text']. The worker merges the BMP
    capture with text, lines and ocr_backend, then _register_ui_capture
    adds artifact_id. There is no ocr_text field. A caller looking for
    ocr_text after a successful OCR reads the recognised string as missing.
    """
    described = " ".join(_tool_docstring("ui.ocr").split())
    assert "Answers with text, lines, ocr_backend" in described
    assert "artifact_id" in described
    assert "no ocr_text field" in described
    worker = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "core"
        / "ui_ocr.py"
    ).read_text(encoding="utf-8")
    start = worker.index("def ocr_hwnd")
    chunk = worker[start:]
    assert '"ocr_backend": result["backend"]' in chunk
    assert '"ocr_text"' not in chunk
