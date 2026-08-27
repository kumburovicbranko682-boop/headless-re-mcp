"""web.dom.snapshot description must name html and truncated."""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.web.client import _MAX_INLINE_BODY, WebBackend
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
    url = "https://example/app"

    def __init__(self, char_count: int) -> None:
        self._char_count = char_count

    def evaluate(self, script: str, cap: int) -> dict[str, Any]:
        del script
        html = "x" * self._char_count
        return {"html": html[:cap], "over": self._char_count > cap}

    def title(self) -> str:
        return "Example"


def test_web_dom_snapshot_spills_a_large_dom_instead_of_losing_it(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A DOM over the inline cap used to come back cut with no recovery.

    script.source and network.get spill an oversized payload to an artifact;
    dom.snapshot only clipped at 200000 bytes, so the rest of a large page was
    gone. It now spills the full document to dom_path with html holding the
    prefix and truncated set -- the same contract as its sibling tools.
    """
    backend = WebBackend()
    page = _Page(_MAX_INLINE_BODY + 50)
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(page=page))
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    payload = backend.dom_snapshot("s", tmp_path)
    assert "content" not in payload
    assert "dom" not in payload
    assert "body" not in payload
    assert payload["truncated"] is True
    assert payload["url"] == "https://example/app"
    assert payload["title"] == "Example"
    # html is a prefix; the full DOM landed in the artifact.
    assert len(payload["html"]) == _MAX_INLINE_BODY
    spilled = Path(payload["dom_path"])
    assert spilled.parent == tmp_path
    assert spilled.stat().st_size == _MAX_INLINE_BODY + 50
    doc = _tool_docstring("web.dom.snapshot")
    assert "html" in doc
    assert "truncated" in doc
    assert "dom_path" in doc


def test_web_dom_snapshot_inlines_a_small_dom_without_spilling(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """Under the inline cap the whole DOM is html and nothing spills."""
    backend = WebBackend()
    page = _Page(1000)
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(page=page))
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    payload = backend.dom_snapshot("s", tmp_path)
    assert payload["truncated"] is False
    assert "dom_path" not in payload
    assert len(payload["html"]) == 1000
    assert list(tmp_path.iterdir()) == []
