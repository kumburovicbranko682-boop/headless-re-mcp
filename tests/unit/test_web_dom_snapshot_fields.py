"""web.dom.snapshot description must name bytes and truncated."""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.web.client import WebBackend
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


class _Immediate:
    def call(self, work: Any, timeout: float | None = None) -> Any:
        return work()


def test_web_dom_snapshot_reports_bytes_so_a_clip_has_scale(monkeypatch: Any) -> None:
    """The reply carries the full DOM size even when html is clipped.

    Measured: a probe that reports a 900000-byte DOM clipped to a 100-char html
    -> bytes 900000, truncated True. Without bytes the clip gave no scale, so a
    caller could not tell a whole small page from the head of a huge one.
    """

    class _Page:
        url = "https://x/"

        def evaluate(self, script: str, arg: Any) -> Any:
            return {"html": "A" * 100, "truncated": True, "bytes": 900_000}

        def title(self) -> str:
            return "t"

    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(page=_Page()))
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())

    payload = backend.dom_snapshot("s")
    assert payload["bytes"] == 900_000
    assert payload["truncated"] is True
    assert len(payload["html"]) == 100
    assert "content" not in payload
    assert "dom" not in payload

    doc = _tool_docstring("web.dom.snapshot")
    assert "bytes" in doc
    assert "truncated" in doc
    assert "html" in doc
