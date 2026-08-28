"""web.frames flattens Page.getFrameTree into one row per frame.

web.cookies and web.storage only reach the top document's origin, and
web.dom.snapshot is the top document's HTML; web.frames reveals the iframes
those tools do not see -- the cross-origin auth/payment/ad frames whose own
origin, storage and cookies form a separate boundary. These cover the
breadth-first flatten, the parent_id/depth/is_main shaping, the optional
name/mime_type fields, the url_filter, paging, the collection and page caps, the
backend-error and empty-tree paths, service routing, and the read-only class.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.web import client as web_client
from headless_re_mcp.backends.web.client import WebBackend, WebError
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


class _Cdp:
    def __init__(self, result: Any, *, boom: bool = False) -> None:
        self._result = result
        self._boom = boom

    def send(self, method: str, params: Any = None) -> dict[str, Any]:
        assert method == "Page.getFrameTree"
        if self._boom:
            raise RuntimeError("cdp channel is gone")
        return self._result


def _backend(result: Any, monkeypatch: Any, *, boom: bool = False) -> WebBackend:
    backend = WebBackend()
    handle = SimpleNamespace(cdp=_Cdp(result, boom=boom))
    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    return backend


# A main document with two child iframes, one of which nests a third frame.
_TREE = {
    "frameTree": {
        "frame": {
            "id": "MAIN",
            "url": "https://app.example.com/",
            "securityOrigin": "https://app.example.com",
            "mimeType": "text/html",
        },
        "childFrames": [
            {
                "frame": {
                    "id": "F1",
                    "parentId": "MAIN",
                    "url": "https://auth.other.com/login",
                    "securityOrigin": "https://auth.other.com",
                    "mimeType": "text/html",
                    "name": "authframe",
                }
            },
            {
                "frame": {
                    "id": "F2",
                    "parentId": "MAIN",
                    "url": "https://ads.tracker.net/ad",
                    "securityOrigin": "https://ads.tracker.net",
                },
                "childFrames": [
                    {
                        "frame": {
                            "id": "F3",
                            "parentId": "F2",
                            "url": "https://deep.tracker.net/pixel",
                            "securityOrigin": "https://deep.tracker.net",
                        }
                    }
                ],
            },
        ],
    }
}


def test_web_frames_flattens_breadth_first_with_parent_and_depth(monkeypatch: Any) -> None:
    out = _backend(_TREE, monkeypatch).frames("s")
    assert out["count"] == 4
    assert out["total"] == 4
    assert out["has_more"] is False
    assert out["frames_truncated"] is False
    ids = [row["frame_id"] for row in out["frames"]]
    # Breadth-first: main leads, then its two children, then the grandchild.
    assert ids == ["MAIN", "F1", "F2", "F3"]
    rows = {row["frame_id"]: row for row in out["frames"]}
    assert rows["MAIN"]["is_main"] is True
    assert rows["MAIN"]["depth"] == 0
    assert "parent_id" not in rows["MAIN"]
    assert rows["F1"]["is_main"] is False
    assert rows["F1"]["depth"] == 1
    assert rows["F1"]["parent_id"] == "MAIN"
    assert rows["F3"]["depth"] == 2
    assert rows["F3"]["parent_id"] == "F2"


def test_web_frames_surface_origin_and_optional_name_and_mime(monkeypatch: Any) -> None:
    out = _backend(_TREE, monkeypatch).frames("s")
    rows = {row["frame_id"]: row for row in out["frames"]}
    # The cross-origin auth iframe's own origin is the pivot cookies/storage miss.
    assert rows["F1"]["security_origin"] == "https://auth.other.com"
    assert rows["F1"]["name"] == "authframe"
    assert rows["F1"]["mime_type"] == "text/html"
    # A frame the browser reported without a name/mime keeps those fields off.
    assert "name" not in rows["F2"]
    assert "mime_type" not in rows["F2"]


def test_web_frames_filter_by_url_before_paging(monkeypatch: Any) -> None:
    out = _backend(_TREE, monkeypatch).frames("s", url_filter="TRACKER.NET")
    ids = [row["frame_id"] for row in out["frames"]]
    assert ids == ["F2", "F3"]
    # total is the match count, not the whole tree.
    assert out["total"] == 2


def test_web_frames_page_with_offset_and_limit(monkeypatch: Any) -> None:
    out = _backend(_TREE, monkeypatch).frames("s", offset=1, limit=2)
    assert out["offset"] == 1
    assert out["count"] == 2
    assert out["total"] == 4
    assert out["has_more"] is True
    assert [row["frame_id"] for row in out["frames"]] == ["F1", "F2"]


def test_web_frames_cap_a_pathological_tree(monkeypatch: Any) -> None:
    monkeypatch.setattr(web_client, "_MAX_FRAMES", 2)
    out = _backend(_TREE, monkeypatch).frames("s", limit=1000)
    assert out["total"] == 2
    assert out["frames_truncated"] is True


def test_web_frames_page_limit_is_capped(monkeypatch: Any) -> None:
    monkeypatch.setattr(web_client, "_MAX_FRAMES_PAGE", 2)
    out = _backend(_TREE, monkeypatch).frames("s", limit=1000)
    assert out["count"] == 2
    assert out["total"] == 4
    assert out["has_more"] is True


def test_web_frames_cdp_failure_is_backend_error(monkeypatch: Any) -> None:
    with pytest.raises(WebError) as info:
        _backend(_TREE, monkeypatch, boom=True).frames("s")
    assert info.value.code == "backend_error"


def test_web_frames_empty_tree_is_an_empty_list_not_an_error(monkeypatch: Any) -> None:
    out = _backend({}, monkeypatch).frames("s")
    assert out["frames"] == []
    assert out["count"] == 0
    assert out["total"] == 0
    assert out["has_more"] is False
    assert out["frames_truncated"] is False


def test_web_frames_session_fault_keeps_its_own_code(monkeypatch: Any) -> None:
    """A wedged/closed runner raises WebError, which must not be reclassed."""
    backend = WebBackend()
    handle = SimpleNamespace(cdp=_Cdp(_TREE))
    monkeypatch.setattr(backend, "_get", lambda session_id: handle)

    class _Wedged:
        def call(self, work: Any, timeout: float | None = None) -> Any:
            raise WebError("invalid_state", "web session has no browser thread")

    monkeypatch.setattr(backend, "_runner", lambda handle: _Wedged())
    with pytest.raises(WebError) as info:
        backend.frames("s")
    assert info.value.code == "invalid_state"


def test_service_web_frames_routes_to_the_owned_backend() -> None:
    from headless_re_mcp.core.service import AnalysisService

    service = AnalysisService()
    try:
        calls: list[Any] = []

        def fake(session_id: str, *, offset: int, limit: int, url_filter: str) -> Any:
            calls.append((session_id, offset, limit, url_filter))
            return {
                "frames": [{"frame_id": "MAIN", "url": "u", "depth": 0, "is_main": True}],
                "count": 1,
                "total": 1,
                "offset": 0,
                "has_more": False,
                "frames_truncated": False,
            }

        service._web.frames = fake  # type: ignore[method-assign]
        result = service.web_frames("s", offset=0, limit=50, url_filter="app")
        assert result.ok and result.data is not None
        assert result.data["frames"][0]["frame_id"] == "MAIN"
        assert calls == [("s", 0, 50, "app")]
    finally:
        service.close_all()


def test_web_frames_tool_docstring_and_read_only() -> None:
    doc = " ".join(_tool_docstring("web.frames").split())
    assert "iframe" in doc
    assert "security_origin" in doc
    assert "url_filter" in doc
    assert "Read-only" in doc
    from headless_re_mcp.tools.catalog import _READ_ONLY_NAMES

    assert "web.frames" in _READ_ONLY_NAMES
