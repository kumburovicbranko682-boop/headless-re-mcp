"""proxy.ca.install_android must name the push, not an install."""

from __future__ import annotations

import ast
from pathlib import Path

from headless_re_mcp.core.service_proxy import ProxyAnalysisMixin
from headless_re_mcp.tools.proxy import build_proxy_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_proxy_tools.__code__.co_filename).read_text(encoding="utf-8")
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


def test_ca_install_android_answers_with_pushed_to_not_installed() -> None:
    """The catalog said install and never named the payload.

    Measured against ProxyAnalysisMixin.proxy_ca_install_android: success
    is pushed_to and note. There is no installed, ok or path field.
    Looking for installed after a successful call reads as a system CA
    that was never imported; the note says root and remount are still
    required.
    """
    source = Path(
        ProxyAnalysisMixin.proxy_ca_install_android.__code__.co_filename
    ).read_text(encoding="utf-8")
    start = source.index("def proxy_ca_install_android")
    chunk = source[start : source.index("def _proxy_wrap", start)]
    marker = chunk.index("data = {")
    returned = chunk[marker : chunk.index("}", marker) + 1]
    assert '"pushed_to"' in returned
    assert '"note"' in returned
    assert '"installed"' not in returned
    assert '"ok"' not in returned
    assert '"path"' not in returned
    doc = _tool_docstring("proxy.ca.install_android")
    assert "Answers with pushed_to" in doc
    assert "note" in doc
    assert "installed" in doc
