"""web.endpoints extracts the network endpoints baked into the live page's scripts.

The dynamic-page counterpart to js.endpoints and the static complement to
web.network.list (which only shows endpoints the page actually hit): this fetches
the source of every script the running page parsed -- including runtime eval
scripts a packer unpacks in memory and never writes to disk -- and pulls URLs and
request paths out of each via the shared JS lexer. These fake the parsed-script
list and the CDP getScriptSource fetch and cover cross-script dedup, the host
summary, the dynamic_only/url filters, the WASM skip, include_paths, name_filter,
the failed-fetch skip, the script/byte/finding/host caps, paging, service routing
and the read-only classification.
"""

from __future__ import annotations

import ast
import threading
from collections import OrderedDict
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.web import client as web_client
from headless_re_mcp.backends.web.client import WebBackend
from headless_re_mcp.tools.web import build_web_tools

_LOGIN = "https://api.example.com/v1/login"
_ORDERS = "/api/orders"
_SOCKET = "wss://socket.example.com/live"


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
    def __init__(self, sources: dict[str, str], fail: set[str] | None = None) -> None:
        self._sources = sources
        self._fail = fail or set()
        self.calls: list[str] = []

    def send(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        del method
        sid = str(params["scriptId"])
        self.calls.append(sid)
        if sid in self._fail:
            raise RuntimeError("no such script")
        return {"scriptSource": self._sources.get(sid, "")}


def _handle(scripts: list[dict[str, Any]], cdp: _Cdp, *, dropped: int = 0) -> Any:
    table: OrderedDict[str, dict[str, Any]] = OrderedDict()
    for entry in scripts:
        table[str(entry["scriptId"])] = entry
    return SimpleNamespace(scripts=table, cdp=cdp, scripts_dropped=dropped, lock=threading.Lock())


def _backend(handle: Any, monkeypatch: Any) -> WebBackend:
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: handle)
    monkeypatch.setattr(backend, "_runner", lambda handle: _Immediate())
    return backend


def _js(entry_id: str, url: str, **extra: Any) -> dict[str, Any]:
    row = {"scriptId": entry_id, "url": url, "language": "JavaScript"}
    row.update(extra)
    return row


def _sample() -> tuple[list[dict[str, Any]], _Cdp]:
    scripts = [
        _js("1", "https://app.example.com/a.js"),
        _js("2", "https://app.example.com/b.js"),
        _js("3", "", dynamic=True),
    ]
    sources = {
        "1": f'var a = "{_LOGIN}"; var b = "{_ORDERS}";',
        "2": f'const w = "{_SOCKET}";',
        "3": f'x.fetch("{_LOGIN}");',
    }
    return scripts, _Cdp(sources)


def _by_value(out: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {row["value"]: row for row in out["endpoints"]}


def test_web_endpoints_scans_all_scripts_and_dedupes(monkeypatch: Any) -> None:
    scripts, cdp = _sample()
    out = _backend(_handle(scripts, cdp, dropped=2), monkeypatch).endpoints("s")
    assert out["scan_capped"] is False
    assert out["scanned_scripts"] == 3
    assert out["scripts_dropped"] == 2
    assert out["total"] == 3
    rows = _by_value(out)
    # The login URL is in scripts 1 and 3 -> deduped, count 2, first_script pins 1.
    assert rows[_LOGIN]["kind"] == "url"
    assert rows[_LOGIN]["host"] == "api.example.com"
    assert rows[_LOGIN]["count"] == 2
    assert rows[_LOGIN]["first_script"] == {
        "script_id": "1",
        "url": "https://app.example.com/a.js",
    }
    assert rows[_ORDERS]["kind"] == "path"
    assert out["hosts"] == ["api.example.com", "socket.example.com"]
    assert out["hosts_truncated"] is False


def test_web_endpoints_dynamic_only_isolates_runtime_scripts(monkeypatch: Any) -> None:
    scripts, cdp = _sample()
    out = _backend(_handle(scripts, cdp), monkeypatch).endpoints("s", dynamic_only=True)
    assert [r["value"] for r in out["endpoints"]] == [_LOGIN]
    assert out["scanned_scripts"] == 1
    assert cdp.calls == ["3"]


def test_web_endpoints_url_filter_narrows_scope(monkeypatch: Any) -> None:
    scripts, cdp = _sample()
    out = _backend(_handle(scripts, cdp), monkeypatch).endpoints("s", url_filter="b.js")
    assert [r["value"] for r in out["endpoints"]] == [_SOCKET]
    assert cdp.calls == ["2"]


def test_web_endpoints_skips_wasm_scripts(monkeypatch: Any) -> None:
    scripts = [
        _js("1", "https://app.example.com/a.js"),
        {"scriptId": "w", "url": "wasm://x", "language": "WebAssembly"},
    ]
    cdp = _Cdp({"1": f'var a = "{_LOGIN}";', "w": f'blob "{_SOCKET}"'})
    out = _backend(_handle(scripts, cdp), monkeypatch).endpoints("s")
    assert [r["value"] for r in out["endpoints"]] == [_LOGIN]
    assert "w" not in cdp.calls


def test_web_endpoints_include_paths_false_drops_relative_paths(monkeypatch: Any) -> None:
    scripts, cdp = _sample()
    out = _backend(_handle(scripts, cdp), monkeypatch).endpoints("s", include_paths=False)
    values = {r["value"] for r in out["endpoints"]}
    assert _ORDERS not in values
    assert _LOGIN in values
    assert all(r["kind"] == "url" for r in out["endpoints"])


def test_web_endpoints_name_filter_matches_value_or_host(monkeypatch: Any) -> None:
    scripts, cdp = _sample()
    backend = _backend(_handle(scripts, cdp), monkeypatch)
    by_host = backend.endpoints("s", name_filter="socket")
    assert [r["value"] for r in by_host["endpoints"]] == [_SOCKET]
    by_value = backend.endpoints("s", name_filter="orders")
    assert [r["value"] for r in by_value["endpoints"]] == [_ORDERS]


def test_web_endpoints_pages_and_reports_has_more(monkeypatch: Any) -> None:
    scripts, cdp = _sample()
    out = _backend(_handle(scripts, cdp), monkeypatch).endpoints("s", offset=0, limit=2)
    assert out["count"] == 2
    assert out["total"] == 3
    assert out["has_more"] is True


def test_web_endpoints_skips_a_failed_fetch(monkeypatch: Any) -> None:
    scripts, _cdp = _sample()
    cdp = _Cdp(_cdp._sources, fail={"2"})
    out = _backend(_handle(scripts, cdp), monkeypatch).endpoints("s")
    values = {r["value"] for r in out["endpoints"]}
    assert _SOCKET not in values
    assert _LOGIN in values
    assert out["scanned_scripts"] == 2


def test_web_endpoints_script_count_cap(monkeypatch: Any) -> None:
    monkeypatch.setattr(web_client, "_MAX_WEB_ENDPOINT_SCRIPTS", 1)
    scripts, cdp = _sample()
    out = _backend(_handle(scripts, cdp), monkeypatch).endpoints("s")
    assert out["scan_capped"] is True
    assert out["scanned_scripts"] == 1


def test_web_endpoints_scan_byte_budget(monkeypatch: Any) -> None:
    monkeypatch.setattr(web_client, "_MAX_WEB_ENDPOINT_SCAN_BYTES", 5)
    scripts, cdp = _sample()
    out = _backend(_handle(scripts, cdp), monkeypatch).endpoints("s")
    assert out["scan_capped"] is True
    assert out["scanned_scripts"] == 1


def test_web_endpoints_findings_cap(monkeypatch: Any) -> None:
    monkeypatch.setattr(web_client, "_MAX_WEB_ENDPOINT_FINDINGS", 1)
    scripts, cdp = _sample()
    out = _backend(_handle(scripts, cdp), monkeypatch).endpoints("s")
    assert out["scan_capped"] is True
    assert out["total"] == 1


def test_web_endpoints_hosts_truncated(monkeypatch: Any) -> None:
    monkeypatch.setattr(web_client, "_MAX_WEB_ENDPOINT_HOSTS", 1)
    scripts, cdp = _sample()
    out = _backend(_handle(scripts, cdp), monkeypatch).endpoints("s")
    assert out["hosts_truncated"] is True
    assert len(out["hosts"]) == 1


def test_service_web_endpoints_routes_to_backend(monkeypatch: Any) -> None:
    from headless_re_mcp.core.service import AnalysisService

    service = AnalysisService()
    try:
        captured: dict[str, Any] = {}

        def fake_endpoints(session_id: str, **kwargs: Any) -> dict[str, Any]:
            captured["session_id"] = session_id
            captured.update(kwargs)
            return {"endpoints": [], "total": 0}

        monkeypatch.setattr(service._web_backend, "endpoints", fake_endpoints)
        result = service.web_endpoints(
            "sess", limit=5, name_filter="api", include_paths=False,
            url_filter="app", dynamic_only=True,
        )
        assert result.ok and result.data is not None
        assert captured["session_id"] == "sess"
        assert captured["limit"] == 5
        assert captured["name_filter"] == "api"
        assert captured["include_paths"] is False
        assert captured["url_filter"] == "app"
        assert captured["dynamic_only"] is True
    finally:
        service.close_all()


def test_web_endpoints_tool_docstring_and_read_only() -> None:
    doc = " ".join(_tool_docstring("web.endpoints").split())
    assert "first_script" in doc
    assert "hosts" in doc
    assert "scan_capped" in doc
    from headless_re_mcp.tools.catalog import _READ_ONLY_NAMES

    assert "web.endpoints" in _READ_ONLY_NAMES
