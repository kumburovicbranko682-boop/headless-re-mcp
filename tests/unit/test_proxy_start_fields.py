"""proxy.start must name the fields the backend actually returns."""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

from headless_re_mcp.backends.proxy.client import ProxyBackend
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


def test_proxy_start_puts_the_result_in_running_host_port_endpoint() -> None:
    """The catalog said start and never named the payload.

    Measured against ProxyBackend.start: success is running, host, port
    and endpoint. There is no ok, started or url field. Looking for those
    after a successful start reads as a proxy that never bound a port.
    """
    chunk = inspect.getsource(ProxyBackend.start)
    returned = chunk[chunk.rindex("return {") :]
    assert '"running"' in returned
    assert '"host"' in returned
    assert '"port"' in returned
    assert '"endpoint"' in returned
    assert '"ssl_insecure"' in returned
    assert '"ok"' not in returned
    assert '"started"' not in returned
    assert '"url"' not in returned
    doc = _tool_docstring("proxy.start")
    assert "Answers with running" in doc
    assert "host" in doc
    assert "port" in doc
    assert "endpoint" in doc
    assert "ssl_insecure" in doc
