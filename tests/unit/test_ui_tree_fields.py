"""ui.tree descriptions must name the fields the walker actually returns."""

from __future__ import annotations

import ast
from pathlib import Path

from headless_re_mcp.core.ui_win32 import build_window_tree
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


def test_ui_tree_puts_the_walk_in_nodes_not_tree() -> None:
    """The catalog said tree; the walker has no such field.

    Measured: build_window_tree([], {1}) keys are count, max_depth,
    max_nodes, nodes, truncated. tree/windows are absent. Looking for tree
    after a successful call reads as an empty UI, so the agent retries the
    walk or drives clicks against hwnds it never got.
    """
    payload = build_window_tree([], frozenset({1}), max_depth=1, max_nodes=8)
    assert "tree" not in payload
    assert "windows" not in payload
    assert payload["nodes"] == []
    assert payload["count"] == 0
    assert payload["truncated"] is False
    doc = _tool_docstring("ui.tree")
    assert "Answers with nodes" in doc
    assert "truncated" in doc
