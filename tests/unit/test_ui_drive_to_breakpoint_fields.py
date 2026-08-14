"""ui.drive_to_breakpoint must name the same goal fields as ui.drive_to_event."""

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


def test_ui_drive_to_breakpoint_names_ui_goal_not_hit() -> None:
    """The live catalog only said it drives until a breakpoint or UI goal.

    ui.drive_to_breakpoint calls the same _ui_drive helper as
    ui.drive_to_event, so a successful run is still ui_goal, steps and
    matched_event. There is no hit field and no top-level matched. A
    UI-goal finish leaves matched_event null, so a caller looking for hit
    after a successful Transform click reads the breakpoint as missed.
    """
    described = " ".join(_tool_docstring("ui.drive_to_breakpoint").split())
    assert "Answers with ui_goal, steps, matched_event" in described
    assert "no hit field" in described
    assert "no matched field at the top level" in described
    worker = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "core"
        / "service_ext.py"
    ).read_text(encoding="utf-8")
    start = worker.index("def ui_drive_to_breakpoint")
    chunk = worker[start : worker.index("class ExtAnalysisMixin", start)]
    assert "return _ui_drive(" in chunk
    payload_start = worker.index("payload = {")
    payload = worker[payload_start : worker.index("_timeline_append", payload_start)]
    assert '"ui_goal": ui_goal' in payload
    assert '"hit":' not in payload
    assert '"matched":' not in payload
