"""web.frames must expose the page's frame tree honestly."""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import headless_re_mcp.backends.web.client as webmod
from headless_re_mcp.backends.web.client import _MAX_METADATA_BYTES, WebBackend
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


class _DetachedFrame:
    """A frame that raises on property access, like a Playwright frame that
    detached mid-enumeration; reads must fall back to empty, not abort."""

    parent_frame = None

    @property
    def url(self) -> str:
        raise RuntimeError("frame detached")

    @property
    def name(self) -> str:
        raise RuntimeError("frame detached")


class _Page:
    def __init__(self, frames: list[Any], main: Any) -> None:
        self.frames = frames
        self.main_frame = main


def _backend_with(monkeypatch: Any, frames: list[Any], main: Any) -> WebBackend:
    backend = WebBackend()
    page = _Page(frames, main)
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(page=page))
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    return backend


def test_web_frames_reports_tree_order_depth_and_parent(monkeypatch: Any) -> None:
    """A single page URL hid every embedded iframe.

    The tree here is main -> ad -> pixel and main -> pay. Each row must name
    its depth (0 for main, 1 for a direct child, 2 for a grandchild) and, for
    every non-main frame, the parent's URL -- that is the cross-origin surface
    a bare page URL never showed.
    """
    main = _Frame("https://example/app", "", None)
    ad = _Frame("https://ads.example/iframe", "ad", main)
    pixel = _Frame("https://tracker.example/px", "", ad)
    pay = _Frame("https://pay.example/checkout", "pay", main)
    backend = _backend_with(monkeypatch, [main, ad, pixel, pay], main)

    payload = backend.frames("s")

    assert payload["total"] == 4
    assert payload["count"] == 4
    assert payload["offset"] == 0
    assert payload["has_more"] is False
    assert payload["scan_capped"] is False
    rows = payload["frames"]
    assert rows[0] == {
        "url": "https://example/app",
        "name": "",
        "is_main": True,
        "depth": 0,
    }
    assert rows[1]["is_main"] is False
    assert rows[1]["depth"] == 1
    assert rows[1]["parent_url"] == "https://example/app"
    assert rows[2]["depth"] == 2
    assert rows[2]["parent_url"] == "https://ads.example/iframe"
    assert rows[3]["depth"] == 1
    assert rows[3]["parent_url"] == "https://example/app"


def test_web_frames_marks_oversized_metadata(monkeypatch: Any) -> None:
    main = _Frame("https://example/app", "", None)
    big = _Frame("https://example/x", "n" * (_MAX_METADATA_BYTES + 10), main)
    backend = _backend_with(monkeypatch, [main, big], main)
    payload = backend.frames("s")
    assert "metadata_truncated" not in payload["frames"][0]
    assert payload["frames"][1]["metadata_truncated"] is True


def test_web_frames_survives_a_detached_frame(monkeypatch: Any) -> None:
    main = _Frame("https://example/app", "", None)
    detached = _DetachedFrame()
    backend = _backend_with(monkeypatch, [main, detached], main)
    payload = backend.frames("s")
    assert payload["total"] == 2
    assert payload["frames"][1]["url"] == ""
    assert payload["frames"][1]["name"] == ""
    assert payload["frames"][1]["is_main"] is False
    assert "parent_url" not in payload["frames"][1]


def test_web_frames_pages_with_offset_and_limit(monkeypatch: Any) -> None:
    main = _Frame("https://example/app", "", None)
    kids = [_Frame(f"https://example/{i}", "", main) for i in range(4)]
    backend = _backend_with(monkeypatch, [main, *kids], main)

    first = backend.frames("s", offset=0, limit=2)
    assert first["count"] == 2
    assert first["total"] == 5
    assert first["has_more"] is True

    tail = backend.frames("s", offset=4, limit=2)
    assert tail["count"] == 1
    assert tail["offset"] == 4
    assert tail["has_more"] is False


def test_web_frames_flags_scan_cap(monkeypatch: Any) -> None:
    monkeypatch.setattr(webmod, "_MAX_FRAMES_COLLECT", 2)
    main = _Frame("https://example/app", "", None)
    kids = [_Frame(f"https://example/{i}", "", main) for i in range(5)]
    backend = _backend_with(monkeypatch, [main, *kids], main)
    payload = backend.frames("s")
    assert payload["scan_capped"] is True
    assert payload["total"] == 2


def test_web_frames_docstring_names_the_fields() -> None:
    doc = _tool_docstring("web.frames")
    assert "is_main" in doc
    assert "depth" in doc
    assert "parent_url" in doc
    assert "iframe" in doc
