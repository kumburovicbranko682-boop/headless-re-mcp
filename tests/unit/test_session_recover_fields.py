"""session.recover must name keep vs replace fields."""

from __future__ import annotations

import ast
from pathlib import Path

from headless_re_mcp.tools.meta import build_meta_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_meta_tools.__code__.co_filename).read_text(encoding="utf-8")
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


def test_session_recover_keep_has_no_previous_session_id() -> None:
    """The catalog said every recover returns previous_session_id.

    Measured: a keep returns replaced false, session_id, recovered, kept,
    failed and backends, with no previous_session_id. tests/unit/
    test_dynamic_service.py already reads kept==2 and replaced False for
    live workers, and previous_session_id only after a FAILED replace.
    Looking for previous_session_id after a keep treats a live recover as
    a missing replacement, so the overnight pass abandons the still-valid id.
    """
    service = Path("src/headless_re_mcp/core/service.py").read_text(encoding="utf-8")
    recover_at = service.index("def session_recover(")
    recover = service[recover_at : service.index("def _worker_is_alive(", recover_at)]
    replace_at = service.index("def _recover_by_replacement(")
    replace = service[replace_at : service.index("def _open_dynamic(", replace_at)]
    assert '"replaced": False' in recover
    assert '"previous_session_id"' not in recover
    assert '"replaced": True' in replace
    assert '"previous_session_id": session_id' in replace
    described = _tool_docstring("session.recover")
    assert "Answers with backends" in described
    assert "previous_session_id is present only when replaced is true" in described
    assert "replaced false" in described
