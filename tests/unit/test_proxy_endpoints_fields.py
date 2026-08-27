"""proxy.endpoints must fold flows into a bounded, deduplicated endpoint map.

The tool collapses the flow ring into distinct (host, method, path) endpoints,
counting hits, stripping the query string, merging observed statuses, and
counting errored flows separately. It has to disclose every bound it hits -- an
over-cap endpoint list, an over-cap status list, and a clipped path -- so a
bounded map is never read as the whole API surface.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.proxy.client import ProxyBackend
from headless_re_mcp.tools.proxy import build_proxy_tools


class _FakeRecorder:
    def __init__(self, flows: list[dict[str, Any]]) -> None:
        self._flows = flows

    def snapshot(self) -> list[dict[str, Any]]:
        return list(self._flows)


class _FakeInstance:
    def __init__(self, flows: list[dict[str, Any]]) -> None:
        self.recorder = _FakeRecorder(flows)


def _backend_returning(flows: list[dict[str, Any]]) -> ProxyBackend:
    backend = ProxyBackend()
    backend._get = lambda _session_id: _FakeInstance(flows)  # type: ignore[method-assign]
    return backend


def _flow(url: str, host: str, method: str = "GET", **extra: Any) -> dict[str, Any]:
    entry = {"url": url, "host": host, "method": method}
    entry.update(extra)
    return entry


def _tool_docstring(name: str) -> str:
    source = Path(build_proxy_tools.__code__.co_filename).read_text(encoding="utf-8")
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


def test_endpoints_dedupes_strips_query_counts_and_merges_status() -> None:
    """Same path with different queries collapses; statuses merge; errors count.

    Measured intent: /v1/user?id=1 and ?id=2 are one GET endpoint hit twice
    with statuses [200, 404]; a POST to the same path is a distinct endpoint; a
    flow that errored (null status) adds to errors rather than statuses; sorting
    is host then path then method.
    """
    host = "api.example.com"
    flows = [
        _flow(f"https://{host}/v1/user?id=1", host, "GET", status=200),
        _flow(f"https://{host}/v1/user?id=2", host, "GET", status=404),
        _flow(f"https://{host}/v1/user", host, "POST", status=201),
        _flow(f"https://{host}/v1/login", host, "POST", status=None, error=True),
    ]
    payload = _backend_returning(flows).endpoints("s")

    assert payload["flows_scanned"] == 4
    assert payload["endpoint_count"] == 3
    assert payload["host_count"] == 1
    assert payload["has_more"] is False
    assert [(e["path"], e["method"]) for e in payload["endpoints"]] == [
        ("/v1/login", "POST"),
        ("/v1/user", "GET"),
        ("/v1/user", "POST"),
    ]

    login = payload["endpoints"][0]
    assert login["count"] == 1
    assert login["statuses"] == []
    assert login["errors"] == 1

    user_get = payload["endpoints"][1]
    assert user_get["count"] == 2
    assert user_get["statuses"] == [200, 404]
    assert "errors" not in user_get
    assert user_get["truncated"] is False

    doc = _tool_docstring("proxy.endpoints")
    assert "endpoints" in doc
    assert "has_more" in doc
    assert "statuses" in doc


def test_endpoints_falls_back_to_url_host_and_root_path() -> None:
    """A missing summary host is recovered from the URL; a bare URL is path /."""
    flows = [
        _flow("https://cdn.example.net/asset.js", "", "GET", status=200),
        _flow("https://cdn.example.net", "cdn.example.net", "GET", status=200),
    ]
    payload = _backend_returning(flows).endpoints("s")
    by_path = {(e["host"], e["path"]) for e in payload["endpoints"]}
    assert ("cdn.example.net", "/asset.js") in by_path
    assert ("cdn.example.net", "/") in by_path
    assert payload["host_count"] == 1


def test_endpoints_caps_and_discloses_has_more() -> None:
    """More than 512 distinct endpoints caps the list and sets has_more."""
    host = "h"
    flows = [
        _flow(f"https://{host}/p{index:04d}", host, "GET", status=200)
        for index in range(600)
    ]
    payload = _backend_returning(flows).endpoints("s")
    assert payload["endpoint_count"] == 600
    assert len(payload["endpoints"]) == 512
    assert payload["has_more"] is True


def test_endpoints_caps_status_list_and_clips_long_path() -> None:
    """An over-cap status list and a clipped oversized path both set truncated."""
    host = "h"
    many_statuses = [
        _flow("https://h/hot", host, "GET", status=200 + index) for index in range(20)
    ]
    long_path = "/" + "a" * 2000
    flows = [*many_statuses, _flow(f"https://h{long_path}", host, "GET", status=200)]
    payload = _backend_returning(flows).endpoints("s")
    by_path = {e["path"]: e for e in payload["endpoints"]}

    hot = by_path["/hot"]
    assert hot["count"] == 20
    assert len(hot["statuses"]) == 16
    assert hot["truncated"] is True

    clipped = next(e for e in payload["endpoints"] if e["path"].startswith("/aaa"))
    assert len(clipped["path"]) == 1024
    assert clipped["truncated"] is True
