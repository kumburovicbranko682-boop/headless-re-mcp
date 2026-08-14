"""web.close description must name closed and clean."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.web.client import WebBackend, _WebSession
from headless_re_mcp.tools.web import build_web_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_web_tools.__code__.co_filename).read_text(encoding="utf-8")
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


class _Dummy:
    def close(self) -> None:
        return None

    def stop(self) -> None:
        return None


class _Runner:
    wedged = False

    def call(self, fn: Any, timeout: float | None = None) -> Any:
        return fn()

    def shutdown(self) -> None:
        return None


def test_web_close_puts_the_result_in_closed_and_clean() -> None:
    """The catalog said free resources and never named the payload.

    Measured: missing session -> closed=False plus note; with a browser
    thread -> closed=True plus clean=True; no ok, success or freed field.
    Looking for those after a successful close reads as still open.
    """
    backend = WebBackend()
    missing = backend.close("missing")
    assert missing["closed"] is False
    assert "note" in missing
    assert "ok" not in missing
    assert "success" not in missing
    assert "freed" not in missing

    handle = _WebSession(_Dummy(), _Dummy(), _Dummy(), _Dummy(), _Dummy())
    handle.runner = _Runner()
    backend._sessions["s"] = handle
    payload = backend.close("s")
    assert payload["closed"] is True
    assert payload["clean"] is True
    assert "ok" not in payload
    assert "success" not in payload
    assert "freed" not in payload
    doc = _tool_docstring("web.close")
    assert "Answers with closed" in doc
    assert "clean" in doc
