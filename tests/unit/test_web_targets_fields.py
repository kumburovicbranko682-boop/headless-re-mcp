"""web.targets lists every page in the context with active/opener, paged.

The fakes stand in for Playwright's Context/Page so the Python enumeration,
opener mapping, degradation on a closing page, bounding and pagination are what
actually get exercised.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.web.client import _MAX_TARGETS, WebBackend
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
    def __init__(
        self,
        url: str,
        *,
        title: str = "",
        opener: _Page | None = None,
        raise_url: bool = False,
        raise_title: bool = False,
    ) -> None:
        self._url = url
        self._title = title
        self._opener = opener
        self._raise_url = raise_url
        self._raise_title = raise_title

    @property
    def url(self) -> str:
        if self._raise_url:
            raise RuntimeError("page is closing")
        return self._url

    def title(self) -> str:
        if self._raise_title:
            raise RuntimeError("page is closing")
        return self._title

    def opener(self) -> _Page | None:
        return self._opener


class _Context:
    def __init__(self, pages: list[_Page]) -> None:
        self._pages = pages

    @property
    def pages(self) -> list[_Page]:
        return self._pages


def _backend(monkeypatch: Any, pages: list[_Page], active: _Page) -> WebBackend:
    backend = WebBackend()
    monkeypatch.setattr(
        backend,
        "_get",
        lambda session_id: SimpleNamespace(context=_Context(pages), page=active),
    )
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    return backend


def test_targets_lists_pages_with_active_and_opener(monkeypatch: Any) -> None:
    """A popup shows up with is_active false and opener pointing at its parent.

    Measured: the driven page is index 0, is_active true, opener null; the
    window.open popup is index 1, is_active false, opener 0 -- and no pages,
    tabs or targetId field.
    """
    main = _Page("https://app.example/", title="App")
    popup = _Page("https://idp.example/oauth", title="Sign in", opener=main)
    payload = _backend(monkeypatch, [main, popup], main).targets("s")
    targets = payload["targets"]
    assert targets[0] == {
        "index": 0,
        "url": "https://app.example/",
        "title": "App",
        "is_active": True,
        "opener": None,
    }
    assert targets[1]["index"] == 1
    assert targets[1]["url"] == "https://idp.example/oauth"
    assert targets[1]["is_active"] is False
    assert targets[1]["opener"] == 0
    assert payload["total"] == 2
    assert payload["count"] == 2
    assert payload["has_more"] is False
    assert payload["targets_capped"] is False
    assert "pages" not in payload
    assert "tabs" not in payload
    assert "targetId" not in payload


def test_targets_detached_page_reads_empty_not_raises(monkeypatch: Any) -> None:
    """A page that raises on url/title read degrades to empty strings."""
    main = _Page("https://app.example/", title="App")
    gone = _Page("x", opener=main, raise_url=True, raise_title=True)
    payload = _backend(monkeypatch, [main, gone], main).targets("s")
    assert payload["total"] == 2
    assert payload["targets"][1]["url"] == ""
    assert payload["targets"][1]["title"] == ""
    assert payload["targets"][1]["opener"] == 0


def test_targets_opener_outside_list_is_null(monkeypatch: Any) -> None:
    """An opener that is not among the collected pages maps to null."""
    orphan = _Page("https://gone.example/")
    main = _Page("https://app.example/", title="App", opener=orphan)
    payload = _backend(monkeypatch, [main], main).targets("s")
    assert payload["targets"][0]["opener"] is None


def test_targets_caps_and_paginates(monkeypatch: Any) -> None:
    """Past the cap targets_capped is true; a small limit pages honestly.

    Measured: with one more page than the cap, total equals the cap and
    targets_capped is true; limit 10 returns a window with has_more, and the
    next offset returns a different first page.
    """
    pages = [_Page(f"https://p{i:04d}.example/") for i in range(_MAX_TARGETS + 1)]
    backend = _backend(monkeypatch, pages, pages[0])
    payload = backend.targets("s", offset=0, limit=10)
    assert payload["total"] == _MAX_TARGETS
    assert payload["targets_capped"] is True
    assert payload["count"] == 10
    assert payload["has_more"] is True
    nxt = backend.targets("s", offset=10, limit=10)
    assert nxt["offset"] == 10
    assert nxt["targets"][0]["index"] == 10


def test_targets_docstring_names_shape() -> None:
    doc = _tool_docstring("web.targets")
    assert "targets" in doc
    assert "is_active" in doc
    assert "opener" in doc
    assert "targets_capped" in doc
