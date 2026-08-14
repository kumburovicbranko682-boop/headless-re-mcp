"""web.screenshot description must name path, not screenshot."""

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


class _Page:
    def screenshot(self, path: str, full_page: bool = False) -> None:
        Path(path).write_bytes(b"PNG")


def test_web_screenshot_puts_the_file_in_path_not_screenshot(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The catalog said a PNG artifact and never named the payload.

    Measured: field is path, no screenshot or png key. Looking for those
    after a successful call reads as a missing capture.
    """
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(page=_Page()))
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    payload = backend.screenshot("s", tmp_path / "shot.png")
    assert "screenshot" not in payload
    assert "png" not in payload
    assert payload["path"].endswith("shot.png")
    doc = _tool_docstring("web.screenshot")
    assert "Answers with path" in doc
