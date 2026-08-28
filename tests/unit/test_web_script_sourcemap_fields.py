"""web.script.sourcemap recovers a live script's original sources from its map.

js.sourcemap needs the .map on disk; web.script.sourcemap fetches the script
source over CDP, reads its sourceMappingURL, decodes an inline data: URI or
fetches an external map in the page context, and parses it with the shared
js_sourcemap parser. These fake the parsed-script table, the CDP getScriptSource
fetch and the page.evaluate fetch, and cover inline maps, external fetch +
relative-URL resolution, list/extract modes, the no-map soft result, the
missing-script and fetch-failure errors, service routing, and the read-only
classification.
"""

from __future__ import annotations

import ast
import base64
import json
import threading
from collections import OrderedDict
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

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
        del timeout
        return work()


class _Cdp:
    def __init__(self, sources: dict[str, str], fail: set[str] | None = None) -> None:
        self._sources = sources
        self._fail = fail or set()

    def send(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        del method
        sid = str(params["scriptId"])
        if sid in self._fail:
            raise RuntimeError("no such script")
        return {"scriptSource": self._sources.get(sid, "")}


class _Page:
    def __init__(self, fetchable: dict[str, str], *, fail_status: int | None = None) -> None:
        self._fetchable = fetchable
        self._fail_status = fail_status
        self.evaluated: list[str] = []

    def evaluate(self, expression: str, arg: Any = None) -> Any:
        del expression
        url = arg["url"] if isinstance(arg, dict) else ""
        self.evaluated.append(url)
        if url in self._fetchable:
            return {"ok": True, "text": self._fetchable[url], "len": len(self._fetchable[url])}
        if self._fail_status is not None:
            return {"ok": False, "status": self._fail_status}
        return {"ok": False, "error": "TypeError: Failed to fetch"}


def _map_json(**overrides: Any) -> str:
    data: dict[str, Any] = {
        "version": 3,
        "file": "app.min.js",
        "sourceRoot": "",
        "sources": ["src/a.ts", "src/b.ts", "vendor/c.js"],
        "sourcesContent": ["export const a = 1;\n", "export const b = 2;\n", None],
        "names": [],
        "mappings": "AAAA",
    }
    data.update(overrides)
    return json.dumps(data)


def _handle(scripts: list[dict[str, Any]], cdp: _Cdp, page: _Page) -> Any:
    table: OrderedDict[str, dict[str, Any]] = OrderedDict()
    for entry in scripts:
        table[str(entry["scriptId"])] = entry
    return SimpleNamespace(
        scripts=table, cdp=cdp, page=page, scripts_dropped=0, lock=threading.Lock()
    )


def _backend(handle: Any, monkeypatch: Any) -> WebBackend:
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    return backend


def _script(sid: str, url: str, **extra: Any) -> dict[str, Any]:
    row = {"scriptId": sid, "url": url, "language": "JavaScript"}
    row.update(extra)
    return row


def test_web_sourcemap_inline_data_uri_lists_sources(monkeypatch: Any) -> None:
    encoded = base64.b64encode(_map_json().encode("utf-8")).decode("ascii")
    src = "console.log(1)\n//# sourceMappingURL=data:application/json;base64," + encoded + "\n"
    scripts = [_script("1", "https://app.example.com/app.min.js")]
    handle = _handle(scripts, _Cdp({"1": src}), _Page({}))
    out = _backend(handle, monkeypatch).script_sourcemap("s", "1")
    assert out["has_source_map"] is True
    assert out["origin"] == "inline"
    assert out["source_map_url"] == "data:"
    assert out["sources_total"] == 3
    assert out["with_content"] == 2
    names = {row["source"] for row in out["sources"]}
    assert "src/a.ts" in names


def test_web_sourcemap_fetches_external_map_resolving_relative_url(monkeypatch: Any) -> None:
    src = "console.log(1)\n//# sourceMappingURL=app.min.js.map\n"
    map_abs = "https://app.example.com/static/app.min.js.map"
    scripts = [_script("7", "https://app.example.com/static/app.min.js")]
    page = _Page({map_abs: _map_json()})
    out = _backend(_handle(scripts, _Cdp({"7": src}), page), monkeypatch).script_sourcemap("s", "7")
    # The relative map URL was resolved against the script URL and fetched.
    assert page.evaluated == [map_abs]
    assert out["origin"] == f"external:{map_abs}"
    assert out["source_map_url"] == map_abs
    assert out["sources_total"] == 3


def test_web_sourcemap_extract_returns_original_text(monkeypatch: Any) -> None:
    encoded = base64.b64encode(_map_json().encode("utf-8")).decode("ascii")
    src = "x\n//# sourceMappingURL=data:application/json;base64," + encoded + "\n"
    handle = _handle([_script("1", "https://h/app.js")], _Cdp({"1": src}), _Page({}))
    out = _backend(handle, monkeypatch).script_sourcemap("s", "1", extract="src/b.ts")
    assert out["matched"] is True
    assert out["source"] == "src/b.ts"
    assert out["content"] == "export const b = 2;\n"
    assert out["has_source_map"] is True


def test_web_sourcemap_name_filter_lists_matches(monkeypatch: Any) -> None:
    data = _map_json(
        sources=["src/a.ts", "src/b.ts", "lib/d.js"], sourcesContent=["a", "b", "d"]
    )
    encoded = base64.b64encode(data.encode("utf-8")).decode("ascii")
    src = "x\n//@ sourceMappingURL=data:application/json;base64," + encoded + "\n"
    handle = _handle([_script("1", "https://h/app.js")], _Cdp({"1": src}), _Page({}))
    out = _backend(handle, monkeypatch).script_sourcemap("s", "1", name_filter="src/")
    assert out["total"] == 2
    assert {row["source"] for row in out["sources"]} == {"src/a.ts", "src/b.ts"}


def test_web_sourcemap_no_pragma_is_soft_result(monkeypatch: Any) -> None:
    handle = _handle(
        [_script("1", "https://h/app.js")], _Cdp({"1": "var x=1;\n"}), _Page({})
    )
    out = _backend(handle, monkeypatch).script_sourcemap("s", "1")
    assert out["has_source_map"] is False
    assert out["sources"] == []
    assert out["total"] == 0
    assert out["script_id"] == "1"


def test_web_sourcemap_unknown_script_is_not_found(monkeypatch: Any) -> None:
    handle = _handle([_script("1", "https://h/app.js")], _Cdp({}, fail={"9"}), _Page({}))
    with pytest.raises(WebError) as caught:
        _backend(handle, monkeypatch).script_sourcemap("s", "9")
    assert caught.value.code == "not_found"


def test_web_sourcemap_relative_map_without_script_url_is_invalid_state(monkeypatch: Any) -> None:
    src = "x\n//# sourceMappingURL=app.js.map\n"
    handle = _handle([_script("1", "", dynamic=True)], _Cdp({"1": src}), _Page({}))
    with pytest.raises(WebError) as caught:
        _backend(handle, monkeypatch).script_sourcemap("s", "1")
    assert caught.value.code == "invalid_state"


def test_web_sourcemap_fetch_failure_is_backend_error(monkeypatch: Any) -> None:
    src = "x\n//# sourceMappingURL=https://cdn.example.com/app.js.map\n"
    page = _Page({}, fail_status=404)
    handle = _handle([_script("1", "https://h/app.js")], _Cdp({"1": src}), page)
    with pytest.raises(WebError) as caught:
        _backend(handle, monkeypatch).script_sourcemap("s", "1")
    assert caught.value.code == "backend_error"
    assert caught.value.details.get("url") == "https://cdn.example.com/app.js.map"


def test_service_web_script_sourcemap_routes_to_backend(monkeypatch: Any) -> None:
    from headless_re_mcp.core.service import AnalysisService

    service = AnalysisService()
    try:
        captured: dict[str, Any] = {}

        def fake(session_id: str, script_id: str, **kwargs: Any) -> dict[str, Any]:
            captured["session_id"] = session_id
            captured["script_id"] = script_id
            captured.update(kwargs)
            return {"has_source_map": False, "sources": []}

        monkeypatch.setattr(service._web, "script_sourcemap", fake)
        result = service.web_script_sourcemap(
            "sess", "42", limit=10, name_filter="src", extract="a.ts"
        )
        assert result.ok and result.data is not None
        assert captured["session_id"] == "sess"
        assert captured["script_id"] == "42"
        assert captured["limit"] == 10
        assert captured["name_filter"] == "src"
        assert captured["extract"] == "a.ts"
    finally:
        service.close_all()


def test_web_script_sourcemap_tool_docstring_and_read_only() -> None:
    doc = " ".join(_tool_docstring("web.script.sourcemap").split())
    assert "sourceMappingURL" in doc
    assert "extract" in doc
    assert "has_source_map" in doc
    assert "origin" in doc
    from headless_re_mcp.tools.catalog import _READ_ONLY_NAMES

    assert "web.script.sourcemap" in _READ_ONLY_NAMES
