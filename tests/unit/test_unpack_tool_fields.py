"""unpack.upx.test must name the fields the service actually returns."""

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


def test_unpack_upx_test_nests_cli_result_under_upx() -> None:
    """The live catalog omitted the nested CLI result.

    service_unpack_cli.unpack_upx_test returns upx (UpxResult.to_dict) and
    input_unchanged. A caller looking for top-level stdout or ok-inside-data
    after a successful test reads it as UPX returning nothing.
    """
    described = " ".join(_tool_docstring("unpack.upx.test").split())
    assert "Answers with upx" in described
    assert "input_unchanged" in described
    assert "no top-level stdout field" in described
    source = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "headless_re_mcp"
        / "core"
        / "service_unpack_cli.py"
    ).read_text(encoding="utf-8")
    assert '{"upx": result.to_dict(), "input_unchanged": True}' in source
