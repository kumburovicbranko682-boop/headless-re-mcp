"""workspace.mode descriptions must name the fields the payload actually has."""

from __future__ import annotations

import ast
from pathlib import Path

from headless_re_mcp.core.workspace import profile_summary
from headless_re_mcp.tools.workspace import build_workspace_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_workspace_tools.__code__.co_filename).read_text(encoding="utf-8")
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


def test_workspace_mode_get_names_profile_not_options() -> None:
    """The catalog said options; the payload has no such field.

    Measured: profile_summary('android') keys are available, hidden_prefixes,
    label, profile. mode/options/direction are absent. Looking for options
    after a successful get reads as an empty work direction, so the agent
    sets the profile again or skips the trim.
    """
    payload = profile_summary("android")
    assert payload["profile"] == "android"
    assert "options" not in payload
    assert "mode" not in payload
    assert "direction" not in payload
    assert "hidden_prefixes" in payload
    assert "available" in payload
    doc = _tool_docstring("workspace.mode.get")
    assert "Answers with profile" in doc
    assert "hidden_prefixes" in doc
    set_doc = _tool_docstring("workspace.mode.set")
    assert "Answers with profile" in set_doc
