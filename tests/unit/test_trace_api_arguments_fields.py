"""dynamic.trace_api_arguments must name hits/hit_count, not arguments."""

from __future__ import annotations

import ast
from pathlib import Path

from headless_re_mcp.core.service_trace import TraceMixin
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


def test_trace_api_arguments_puts_captures_under_hits_not_arguments() -> None:
    """The catalog said capture arguments and never named the list.

    Measured: trace_api_arguments returns hits, hit_count, truncated,
    stopped_elsewhere, convention, architecture, target and max_hits.
    tests/unit/test_dynamic_service.py already reads hit_count and hits[0]
    arguments. There is no top-level arguments or rip. Looking for
    arguments after success treats a live trace as empty.
    """
    source = Path(TraceMixin.trace_api_arguments.__code__.co_filename).read_text(
        encoding="utf-8"
    )
    start = source.index("def trace_api_arguments(")
    chunk = source[start : source.index("except BaseException as exc:", start)]
    returned = chunk[chunk.rindex("return _success(") :]
    assert '"hits": hits' in returned
    assert '"hit_count": len(hits)' in returned
    assert '"truncated":' in returned
    assert '"stopped_elsewhere": stopped_elsewhere' in returned
    assert '"convention":' in returned
    assert '"arguments": arguments' not in returned
    assert '"rip"' not in returned
    described = _tool_docstring("dynamic.trace_api_arguments")
    assert "Answers with hits" in described
    assert "hit_count" in described
    assert "no top-level arguments" in described
