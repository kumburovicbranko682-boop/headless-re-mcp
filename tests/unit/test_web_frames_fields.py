"""web.frames lists the page's frame tree (main document plus every iframe).

These mock the browser handle's page.frames / main_frame so the shaping, the
main-vs-child distinction, the parent_url edge, the cap, and a detached frame
are pinned without a live browser.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.web.client import _MAX_FRAMES, WebBackend
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


class _FakeFrame:
    def __init__(
        self,
        url: str,
        name: str = "",
        parent: _FakeFrame | None = None,
        *,
        detached: bool = False,
    ) -> None:
        self._url = url
        self._name = name
        self._parent = parent
        self._detached = detached

    @property
    def url(self) -> str:
        if self._detached:
            raise RuntimeError("frame detached")
        return self._url

    @property
    def name(self) -> str:
        return self._name

    @property
    def parent_frame(self) -> _FakeFrame | None:
        return self._parent


class _FakePage:
    def __init__(self, frames: list[_FakeFrame], main: _FakeFrame) -> None:
        self._frames = frames
        self._main = main

    @property
    def frames(self) -> list[_FakeFrame]:
        return self._frames

    @property
    def main_frame(self) -> _FakeFrame:
        return self._main


class _FramesRunner:
    def call(self, work: Any, *, timeout: float = 0.0) -> Any:
        del timeout
        return work()


class _FramesHandle:
    def __init__(self, page: _FakePage) -> None:
        self.page = page
        self.runner = _FramesRunner()


def _backend_with(monkeypatch: Any, page: _FakePage) -> WebBackend:
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: _FramesHandle(page))
    return backend


def test_web_frames_lists_the_tree_with_main_and_parents(monkeypatch: Any) -> None:
    main = _FakeFrame("https://app.example/", name="")
    child = _FakeFrame("https://ads.evil/widget", name="ad", parent=main)
    page = _FakePage([main, child], main)
    backend = _backend_with(monkeypatch, page)
    result = backend.frames("s")
    assert result["count"] == 2
    assert result["total"] == 2
    assert result["has_more"] is False

    top = result["frames"][0]
    assert top["url"] == "https://app.example/"
    assert top["is_main"] is True
    assert "parent_url" not in top

    embed = result["frames"][1]
    assert embed["url"] == "https://ads.evil/widget"
    assert embed["name"] == "ad"
    assert embed["is_main"] is False
    assert embed["parent_url"] == "https://app.example/"


def test_web_frames_skips_a_frame_that_detached_mid_read(monkeypatch: Any) -> None:
    main = _FakeFrame("https://app.example/")
    gone = _FakeFrame("https://x/", parent=main, detached=True)
    page = _FakePage([main, gone], main)
    backend = _backend_with(monkeypatch, page)
    result = backend.frames("s")
    # total counts what the page reported; the detached one drops from the list.
    assert result["total"] == 2
    assert result["count"] == 1
    assert result["frames"][0]["is_main"] is True


def test_web_frames_caps_a_flood_of_iframes(monkeypatch: Any) -> None:
    main = _FakeFrame("https://app.example/")
    frames = [main] + [
        _FakeFrame(f"https://ad{index}/", parent=main) for index in range(_MAX_FRAMES + 20)
    ]
    page = _FakePage(frames, main)
    backend = _backend_with(monkeypatch, page)
    result = backend.frames("s")
    assert result["count"] == _MAX_FRAMES
    assert result["total"] == _MAX_FRAMES + 21
    assert result["has_more"] is True


def test_web_frames_docstring_names_the_shape() -> None:
    doc = _tool_docstring("web.frames")
    assert doc, "web.frames is missing its docstring"
    assert "is_main" in doc
    assert "parent_url" in doc
    assert "has_more" in doc
