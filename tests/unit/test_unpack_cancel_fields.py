"""unpack.cancel must name the retain/rollback fields it actually returns."""

from __future__ import annotations

import ast
from pathlib import Path

from headless_re_mcp.tools.unpack import build_unpack_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_unpack_tools.__code__.co_filename).read_text(encoding="utf-8")
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


def test_unpack_cancel_names_safe_rollback_false_not_cancelled() -> None:
    """The live catalog mentioned retain/rollback in prose and omitted the payload.

    tests/unit/test_m5_unpack_session.py already reads
    data['artifacts_retained'] and data['safe_rollback'] is False. The
    service also returns unpack, original_input_preserved and
    claims_universal_unpack false. There is no cancelled field. A caller
    looking for cancelled after a successful stop reads the cancel as a
    miss, or treats safe_rollback as true and retries on a dirty dump.
    """
    described = " ".join(_tool_docstring("unpack.cancel").split())
    assert "Answers with unpack" in described
    assert "artifacts_retained true" in described
    assert "safe_rollback false" in described
    assert "no cancelled field" in described
    source = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "core"
        / "service_unpack.py"
    ).read_text(encoding="utf-8")
    start = source.index("def unpack_cancel")
    chunk = source[start : source.index("def unpack_artifacts", start)]
    assert '"unpack": state.to_dict()' in chunk
    assert '"artifacts_retained": True' in chunk
    assert '"safe_rollback": False' in chunk
    assert '"claims_universal_unpack": False' in chunk
    assert '"cancelled":' not in chunk
