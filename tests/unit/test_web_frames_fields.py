"""web.frames must flatten the frame tree, keep origins, and page it.

Cross-origin iframes (ads, payment widgets, embedded SPAs) are what the
main-frame DOM snapshot misses. These pin that web.frames flattens the CDP
Page.getFrameTree depth-first (parent before child), tags the main frame,
carries each frame's security origin and parent link, guards a pathological
tree, and pages like the other capture readers.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.web.client import _MAX_FRAMES, WebBackend, WebError
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


class _Cdp:
    def __init__(self, result: Any, *, raise_on_send: bool = False) -> None:
        self._result = result
        self._raise = raise_on_send

    def send(self, method: str, *args: Any) -> Any:
        del method, args
        if self._raise:
            raise RuntimeError("page domain gone")
        return self._result


class _Handle:
    def __init__(self, result: Any, *, raise_on_send: bool = False) -> None:
        self.cdp = _Cdp(result, raise_on_send=raise_on_send)


class _Runner:
    def call(self, fn: Any, *args: Any, **kwargs: Any) -> Any:
        del args, kwargs
        return fn()


def _backend_for(handle: _Handle, monkeypatch: Any) -> WebBackend:
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    monkeypatch.setattr(backend, "_runner", lambda h: _Runner())
    return backend


def _frame(fid: str, url: str, origin: str, parent: str | None = None) -> dict[str, Any]:
    node: dict[str, Any] = {
        "id": fid,
        "url": url,
        "securityOrigin": origin,
        "mimeType": "text/html",
        "name": "",
    }
    if parent is not None:
        node["parentId"] = parent
    return node


def _nested_tree() -> dict[str, Any]:
    # main -> child (cross-origin) -> grandchild (same as child).
    return {
        "frameTree": {
            "frame": _frame("F0", "http://main/", "http://main"),
            "childFrames": [
                {
                    "frame": _frame("F1", "https://ads.example/", "https://ads.example", "F0"),
                    "childFrames": [
                        {
                            "frame": _frame(
                                "F2", "https://ads.example/inner", "https://ads.example", "F1"
                            )
                        }
                    ],
                }
            ],
        }
    }


def test_frames_flatten_depth_first_with_parent_and_origin(monkeypatch: Any) -> None:
    backend = _backend_for(_Handle(_nested_tree()), monkeypatch)
    result = backend.frames("s")

    assert result["total"] == 3
    ids = [f["frameId"] for f in result["frames"]]
    # Parent precedes children, depth-first.
    assert ids == ["F0", "F1", "F2"]

    main = result["frames"][0]
    assert main["is_main"] is True
    assert main["depth"] == 0
    assert main["parentFrameId"] is None

    ad = result["frames"][1]
    assert ad["is_main"] is False
    assert ad["depth"] == 1
    assert ad["parentFrameId"] == "F0"
    # The cross-origin embedding is visible via securityOrigin.
    assert ad["securityOrigin"] == "https://ads.example"

    grand = result["frames"][2]
    assert grand["depth"] == 2
    assert grand["parentFrameId"] == "F1"
    assert result["scan_capped"] is False


def test_frames_paginate(monkeypatch: Any) -> None:
    # A main frame with five flat children.
    children = [
        {"frame": _frame(f"C{i}", f"http://main/{i}", "http://main", "F0")} for i in range(5)
    ]
    root = {"frame": _frame("F0", "http://main/", "http://main"), "childFrames": children}
    backend = _backend_for(_Handle({"frameTree": root}), monkeypatch)

    page = backend.frames("s", offset=1, limit=2)
    assert page["offset"] == 1
    assert page["count"] == 2
    assert page["total"] == 6
    assert page["has_more"] is True

    tail = backend.frames("s", offset=5, limit=10)
    assert tail["count"] == 1
    assert tail["has_more"] is False


def test_a_tree_past_the_guard_sets_scan_capped(monkeypatch: Any) -> None:
    children = [
        {"frame": _frame(f"C{i}", f"http://main/{i}", "http://main", "F0")}
        for i in range(_MAX_FRAMES + 50)
    ]
    root = {"frame": _frame("F0", "http://main/", "http://main"), "childFrames": children}
    backend = _backend_for(_Handle({"frameTree": root}), monkeypatch)
    result = backend.frames("s", limit=1000)

    assert result["total"] == _MAX_FRAMES
    assert result["scan_capped"] is True


def test_frames_fault_soft_when_the_page_domain_fails(monkeypatch: Any) -> None:
    backend = _backend_for(_Handle(None, raise_on_send=True), monkeypatch)
    with pytest.raises(WebError) as excinfo:
        backend.frames("s")
    assert excinfo.value.code == "backend_error"


def test_frames_docstring_names_the_tree_fields() -> None:
    doc = " ".join(_tool_docstring("web.frames").split())
    assert "iframe" in doc
    assert "parentFrameId" in doc
    assert "securityOrigin" in doc
    assert "is_main" in doc
    assert "scan_capped" in doc
