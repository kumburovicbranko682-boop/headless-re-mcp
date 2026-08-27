"""web.dom.snapshot must name html/truncated and spill an oversized DOM."""

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
    """A page whose DOM overflows the inline cap but fits the transfer budget."""

    url = "https://example/app"

    def evaluate(self, script: str, cap: int) -> dict[str, Any]:
        del script
        html = "x" * (_MAX_INLINE_BODY + 50)
        # The real evaluate clips only at the transfer ceiling (the disk cap),
        # not the inline cap, so a slightly-oversized DOM crosses back whole and
        # the Python side is what decides to spill it.
        return {"html": html[:cap], "transfer_truncated": len(html) > cap}

    def title(self) -> str:
        return "Example"


class _SmallPage:
    """A page whose whole DOM fits inline, so nothing spills."""

    url = "https://example/small"

    def evaluate(self, script: str, cap: int) -> dict[str, Any]:
        del script, cap
        return {"html": "<html></html>", "transfer_truncated": False}

    def title(self) -> str:
        return "Small"


def test_web_dom_snapshot_spills_the_full_dom_and_flags_the_cut(
    monkeypatch: Any, tmp_path: Path
) -> None:
    """An oversized DOM must not be thrown away at the 200 KiB inline clip.

    The full document -- available nowhere else for a large SPA -- is written to
    the artifact dir and its path returned as html_path, with the inline html a
    bounded preview and truncated flagged, mirroring web.network.get /
    web.script.source. Measured: truncated True, html 200000 chars, and a
    spill file holding the entire 200050-char document. No content/dom/body key.
    """
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(page=_Page()))
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    payload = backend.dom_snapshot("s", tmp_path)
    assert "content" not in payload
    assert "dom" not in payload
    assert "body" not in payload
    assert payload["truncated"] is True
    assert payload["url"] == "https://example/app"
    assert len(payload["html"]) == _MAX_INLINE_BODY
    spill = Path(payload["html_path"])
    assert spill.is_file()
    assert spill.parent == tmp_path
    assert len(spill.read_text(encoding="utf-8")) == _MAX_INLINE_BODY + 50
    doc = _tool_docstring("web.dom.snapshot")
    assert "html" in doc
    assert "truncated" in doc
    assert "html_path" in doc


def test_web_dom_snapshot_inlines_a_small_dom_without_spilling(
    monkeypatch: Any, tmp_path: Path
) -> None:
    """A DOM under the inline cap comes back whole with no html_path and no file.

    The spill is only for oversized documents: an ordinary page must not litter
    the artifact dir, and truncated must read false so the caller trusts html as
    the complete document.
    """
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(page=_SmallPage()))
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    payload = backend.dom_snapshot("s", tmp_path)
    assert payload["html"] == "<html></html>"
    assert payload["truncated"] is False
    assert "html_path" not in payload
    assert list(tmp_path.iterdir()) == []
