"""web.frames lists the page's frame tree, host-classified and bounded.

Driven through the _get/_runner seam with a fake page exposing Playwright-like
Frame objects. No real browser is needed.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.web.client import WebBackend, _fold_frames
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


class _Frame:
    def __init__(self, url: str, name: str, parent: _Frame | None) -> None:
        self.url = url
        self.name = name
        self.parent_frame = parent


class _Page:
    def __init__(self, frames: list[_Frame], url: str) -> None:
        self.frames = frames
        self.url = url


def _backend_with(monkeypatch: Any, frames: list[_Frame], url: str) -> WebBackend:
    backend = WebBackend()
    page = _Page(frames, url)
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(page=page))
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    return backend


def _main_row(url: str) -> dict[str, Any]:
    return {"url": url, "name": "", "is_main": True, "parent_url": None, "depth": 0}


def _child_row(url: str, name: str, parent: str, depth: int = 1) -> dict[str, Any]:
    return {
        "url": url,
        "name": name,
        "is_main": False,
        "parent_url": parent,
        "depth": depth,
    }


def _rows() -> list[dict[str, Any]]:
    return [
        _main_row("https://example.com/"),
        _child_row("https://ads.thirdparty.net/banner", "ad", "https://example.com/"),
        _child_row("https://example.com/widget", "own", "https://example.com/"),
    ]


def test_frames_classify_cross_origin_children() -> None:
    payload = _fold_frames(_rows(), "https://example.com/")
    by_name = {f["name"]: f for f in payload["frames"]}
    assert by_name[""]["is_main"] is True
    assert by_name[""]["external"] is False
    assert by_name["ad"]["external"] is True
    assert by_name["ad"]["host"] == "ads.thirdparty.net"
    assert by_name["own"]["external"] is False
    # Only the third-party child counts toward the cross-origin tally.
    assert payload["cross_origin_count"] == 1
    assert payload["total"] == 3


def test_frames_carry_depth_and_parent() -> None:
    payload = _fold_frames(_rows(), "https://example.com/")
    ad = next(f for f in payload["frames"] if f["name"] == "ad")
    assert ad["depth"] == 1
    assert ad["parent_url"] == "https://example.com/"
    main = next(f for f in payload["frames"] if f["is_main"])
    assert main["parent_url"] is None
    assert main["depth"] == 0


def test_frames_on_a_single_document() -> None:
    rows = [_main_row("https://only.example/")]
    payload = _fold_frames(rows, "https://only.example/")
    assert payload["count"] == 1
    assert payload["cross_origin_count"] == 0


def test_frames_walk_the_backend_seam_and_compute_depth(monkeypatch: Any) -> None:
    main = _Frame("https://example.com/", "", None)
    child = _Frame("https://ads.net/x", "ad", main)
    grandchild = _Frame("https://ads.net/y", "deep", child)
    backend = _backend_with(monkeypatch, [main, child, grandchild], "https://example.com/")

    payload = backend.frames("s")

    assert payload["url"] == "https://example.com/"
    assert payload["count"] == 3
    deep = next(f for f in payload["frames"] if f["name"] == "deep")
    assert deep["depth"] == 2
    assert deep["parent_url"] == "https://ads.net/x"
    assert deep["external"] is True
    # ad (depth 1) and deep (depth 2) are both cross-origin children.
    assert payload["cross_origin_count"] == 2


def test_web_frames_docstring_names_the_shape() -> None:
    doc = _tool_docstring("web.frames")
    assert "cross_origin_count" in doc
    assert "parent_url" in doc
    assert "depth" in doc
    assert "is_main" in doc
