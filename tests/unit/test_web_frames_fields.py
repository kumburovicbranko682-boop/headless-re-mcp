"""web.frames enumerates the frame tree with per-frame url/origin, paged.

The fakes stand in for Playwright's Frame/Page graph so the Python tree
flattening, origin derivation, bounding and pagination are what get exercised
(no browser, no page script -- that is the point of reading the frame graph).
"""

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


class _Frame:
    def __init__(
        self,
        url: str,
        *,
        name: str = "",
        parent: _Frame | None = None,
        raise_url: bool = False,
    ) -> None:
        self._url = url
        self._name = name
        self._parent = parent
        self._raise_url = raise_url

    @property
    def url(self) -> str:
        if self._raise_url:
            raise RuntimeError("frame detached")
        return self._url

    @property
    def name(self) -> str:
        return self._name

    @property
    def parent_frame(self) -> _Frame | None:
        return self._parent


class _Page:
    def __init__(self, frames: list[_Frame], main: _Frame) -> None:
        self._frames = frames
        self._main = main

    @property
    def frames(self) -> list[_Frame]:
        return self._frames

    @property
    def main_frame(self) -> _Frame:
        return self._main


def _backend(monkeypatch: Any, page: _Page) -> WebBackend:
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(page=page))
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    return backend


def _tree_page() -> _Page:
    main = _Frame("https://app.example/")
    same = _Frame("https://app.example/inner", name="inner", parent=main)
    cross = _Frame("https://pay.other.com/checkout", name="pay", parent=main)
    grand = _Frame("https://widget.other.com/w", name="w", parent=cross)
    return _Page([main, same, cross, grand], main)


def test_web_frames_flattens_tree_with_parents_and_origins(monkeypatch: Any) -> None:
    """The tree comes back flat with parent indices and per-frame origins.

    Measured: main is index 0 with parent null and is_main true; children
    point at their parent's index; a cross-origin payment iframe (invisible in
    dom.snapshot) shows up with its own origin distinct from main's.
    """
    payload = _backend(monkeypatch, _tree_page()).frames("s")
    frames = payload["frames"]
    assert payload["total"] == 4
    assert payload["count"] == 4
    assert payload["has_more"] is False
    assert frames[0] == {
        "index": 0,
        "parent": None,
        "url": "https://app.example/",
        "origin": "https://app.example",
        "name": "",
        "is_main": True,
    }
    assert frames[1]["parent"] == 0
    assert frames[1]["origin"] == "https://app.example"
    assert frames[1]["is_main"] is False
    assert frames[2]["parent"] == 0
    assert frames[2]["origin"] == "https://pay.other.com"
    assert frames[2]["name"] == "pay"
    assert frames[3]["parent"] == 2
    assert frames[3]["origin"] == "https://widget.other.com"
    assert frames[2]["origin"] != frames[0]["origin"]
    assert "children" not in payload
    assert "tree" not in payload


def test_web_frames_paginates_with_stable_absolute_indices(monkeypatch: Any) -> None:
    """A window keeps absolute index/parent and reports has_more.

    Measured: offset 1 limit 2 returns indices 1 and 2 (not renumbered), total
    stays 4, has_more true because index 3 is past the window.
    """
    payload = _backend(monkeypatch, _tree_page()).frames("s", offset=1, limit=2)
    frames = payload["frames"]
    assert [f["index"] for f in frames] == [1, 2]
    assert frames[1]["parent"] == 0
    assert payload["count"] == 2
    assert payload["total"] == 4
    assert payload["offset"] == 1
    assert payload["has_more"] is True


def test_web_frames_opaque_and_file_origins(monkeypatch: Any) -> None:
    """about:blank/data: are opaque ("") and file:// keeps its origin.

    Measured: an about:blank child and a data: child both report origin "",
    while a file:// child reports file:// -- so a caller can still group real
    origins and tell opaque frames apart.
    """
    main = _Frame("https://app.example/")
    blank = _Frame("about:blank", parent=main)
    data = _Frame("data:text/html,<p>x</p>", parent=main)
    local = _Frame("file:///tmp/x.html", parent=main)
    payload = _backend(monkeypatch, _Page([main, blank, data, local], main)).frames("s")
    origins = {f["url"]: f["origin"] for f in payload["frames"]}
    assert origins["about:blank"] == ""
    assert origins["data:text/html,<p>x</p>"] == ""
    assert origins["file:///tmp/x.html"] == "file://"


def test_web_frames_detached_frame_reads_empty_not_raises(monkeypatch: Any) -> None:
    """A frame that raises on url read degrades to an empty url/origin.

    Measured: the detaching child still yields a row (url "", origin "") rather
    than blowing up the whole enumeration.
    """
    main = _Frame("https://app.example/")
    gone = _Frame("https://app.example/gone", parent=main, raise_url=True)
    payload = _backend(monkeypatch, _Page([main, gone], main)).frames("s")
    assert payload["total"] == 2
    assert payload["frames"][1]["url"] == ""
    assert payload["frames"][1]["origin"] == ""
    assert payload["frames"][1]["parent"] == 0


def test_web_frames_docstring_names_shape() -> None:
    doc = _tool_docstring("web.frames")
    assert "frames" in doc
    assert "index" in doc
    assert "parent" in doc
    assert "origin" in doc
    assert "is_main" in doc
