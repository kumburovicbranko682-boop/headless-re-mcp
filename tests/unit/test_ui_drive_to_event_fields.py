"""ui.drive_to_event must name the goal fields it actually returns."""

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


def test_ui_drive_to_event_names_ui_goal_not_matched() -> None:
    """The live catalog only said it drives until an event or UI goal.

    tests/integration/test_m10_ui_drive_gate.py already reads data['ui_goal']
    and data['steps']. _ui_drive returns matched_event, ui_goal, steps,
    events_seen, stopped and stop_reason. There is no top-level matched or
    event field. A UI-goal finish leaves matched_event null, so a caller
    looking for matched after a successful drive reads the run as a miss.
    """
    described = " ".join(_tool_docstring("ui.drive_to_event").split())
    assert "Answers with ui_goal, steps, matched_event" in described
    assert "no matched field at the top level" in described
    assert "no event field" in described
    worker = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "core"
        / "service_ext.py"
    ).read_text(encoding="utf-8")
    start = worker.index("payload = {")
    chunk = worker[start : worker.index("_timeline_append", start)]
    assert '"matched_event": matched_event' in chunk
    assert '"ui_goal": ui_goal' in chunk
    assert '"steps": step_results' in chunk
    assert '"events_seen": events_seen' in chunk
    assert '"matched":' not in chunk
    assert '"event":' not in chunk
