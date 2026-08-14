"""session.get must name the nested session object it returns."""

from __future__ import annotations

import ast
from pathlib import Path

from headless_re_mcp.tools.core import build_core_session_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_core_session_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        if node.name != "session_get":
            continue
        return ast.get_docstring(node) or ""
    return ""


def test_session_get_puts_the_id_under_session_not_session_id() -> None:
    """The catalog listed nested fields and never named the wrapper.

    Measured: AnalysisService.get_session returns session wrapping
    _session_json. Session fields are id, target, binary, locator, sha256,
    architecture, state, created_at, updated_at, backends and metadata.
    There is no top-level session_id. Looking for session_id after a
    successful get treats a live session as missing, so the overnight
    pass creates a second one.
    """
    service = Path("src/headless_re_mcp/core/service.py").read_text(encoding="utf-8")
    start = service.index("def get_session(")
    chunk = service[start : service.index("def list_sessions(", start)]
    assert 'return _success({"session": _session_json' in chunk
    success = chunk[chunk.index("return _success") : chunk.index("except")]
    assert '"session_id"' not in success
    described = _tool_docstring("session.get")
    assert "Answers with session holding" in described
    assert "no top-level session_id" in described
