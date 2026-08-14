"""ui.virtual_desktop.snapshot must name the window list it actually returns."""

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


def test_ui_virtual_desktop_snapshot_puts_hwnds_in_windows_not_items() -> None:
    """The live catalog said it lists windows and never named the list field.

    tests/integration/test_hidden_desktop_gate.py already reads
    data['windows'], data['mode'] and data['input_desktop']. HiddenDesktop
    snapshot returns windows and window_count; the service adds
    capture_mode and debuggee_pid. There is no items or tree field. A
    caller looking for items after a successful snapshot reads the hidden
    desktop as empty and retries capture against hwnds it never got.
    """
    described = " ".join(_tool_docstring("ui.virtual_desktop.snapshot").split())
    assert "Answers with windows" in described
    assert "window_count" in described
    assert "no items field" in described
    assert "no tree field" in described
    worker = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "core"
        / "hidden_desktop.py"
    ).read_text(encoding="utf-8")
    start = worker.index("def snapshot(")
    chunk = worker[start : worker.index("def capture(", start)]
    assert '"windows": rows' in chunk
    assert '"window_count": len(rows)' in chunk
    assert '"items"' not in chunk
    assert '"tree"' not in chunk
