"""dynamic.attach must name submitted/state, not attached."""

from __future__ import annotations

import ast
from pathlib import Path

from headless_re_mcp.tools.dynamic import build_dynamic_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_dynamic_tools.__code__.co_filename).read_text(encoding="utf-8")
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


def test_dynamic_attach_answers_with_submitted_and_state_not_attached() -> None:
    """The catalog said attach and never named the wait payload.

    Measured: _dynamic_request with wait_for returns submitted and state.
    dynamic_attach then may add child_windows_hint, suggested_child_pids
    and child_candidates. There is no attached or top-level pid. Looking
    for attached after success retries AttachDebugger on a live debuggee.
    """
    service = Path("src/headless_re_mcp/core/service.py").read_text(encoding="utf-8")
    request_at = service.index("def _dynamic_request(")
    request = service[request_at : service.index("def _runtime(", request_at)]
    assert '{"submitted": submitted, "state": state}' in request
    attach_at = service.index("def dynamic_attach(")
    attach = service[attach_at : service.index("def dynamic_stop(", attach_at)]
    assert '"child_windows_hint"' in attach
    assert '"suggested_child_pids"' in attach
    assert '"child_candidates"' in attach
    assert '"attached"' not in attach
    described = _tool_docstring("dynamic.attach")
    assert "Answers with submitted and state" in described
    assert "child_windows_hint" in described
    assert "no attached" in described
