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

def test_ui_process_tree_puts_windows_in_debuggee_windows_not_tree() -> None:
    """The catalog said process-tree and never named the payload.

    Measured against the service action: windows are debuggee_windows, child
    processes are children, plus child_candidates and note. There is no tree
    or processes field. Looking for tree after a successful probe reads as
    the debuggee having no windows, so the agent never passes allow_child_pids.
    """
    source = Path(_ui_finalize_windows.__code__.co_filename).read_text(encoding="utf-8")
    start = source.index("def ui_process_tree")
    chunk = source[start : source.index("def ui_tree", start)]
    returned = chunk[chunk.index("return {") :]
    assert '"debuggee_windows"' in returned
    assert '"children"' in returned
    assert '"child_candidates"' in returned
    assert '"tree"' not in returned
    assert '"processes"' not in returned
    described = _tool_docstring("ui.process_tree")
    assert "Answers with debuggee_windows" in described
    assert "children" in described
    assert "no tree field" in described
    assert "no processes field" in described

def test_ui_resolve_nests_hwnd_under_window() -> None:
    """The catalog said resolve a window and never named the payload.

    Measured against the service action: the match is window (hwnd, pid,
    class_name, title), plus debuggee_pid, debugger_pid and backend. There is
    no top-level hwnd field. Looking for hwnd after a successful resolve
    reads as no match, so the agent retries or clicks a stale handle.
    """
    source = Path(_ui_finalize_windows.__code__.co_filename).read_text(encoding="utf-8")
    start = source.index("def ui_resolve")
    chunk = source[start : source.index("def ui_click", start)]
    returned = chunk[chunk.index("return {") :]
    assert '"window": window' in returned
    assert '"hwnd"' not in returned
    described = _tool_docstring("ui.resolve")
    assert "Answers with window" in described
    assert "no hwnd field" in described
