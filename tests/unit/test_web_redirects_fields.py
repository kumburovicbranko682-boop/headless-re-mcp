"""web.redirects reconstructs redirect chains CDP otherwise overwrites.

Covers both halves: the Network.requestWillBeSent capture (driven through the
_wire_events seam with a fake CDP, proving the redirectResponse hop is recorded
before the request row is overwritten) and the redirects query method plus the
pure fold_redirects (driven with fake rows).
"""

from __future__ import annotations

import ast
from collections import deque
from pathlib import Path
from threading import Lock
from typing import Any

from headless_re_mcp.backends.web.client import WebBackend, fold_redirects
from headless_re_mcp.core.service_web import WebAnalysisMixin
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
    def __init__(self) -> None:
        self.handlers: dict[str, Any] = {}

    def send(self, method: str) -> None:
        del method

    def on(self, event: str, handler: Any) -> None:
        self.handlers[event] = handler


class _Handle:
    def __init__(self) -> None:
        self.lock = Lock()
        self.requests: dict[str, dict[str, Any]] = {}
        self.scripts: dict[str, dict[str, Any]] = {}
        self.console: deque[dict[str, Any]] = deque()
        self.requests_dropped = 0
        self.scripts_dropped = 0
        self.console_dropped = 0
        self.cdp = _Cdp()


def _will_be_sent(
    request_id: str,
    url: str,
    *,
    redirect: dict[str, Any] | None = None,
    rtype: str = "Document",
) -> dict[str, Any]:
    params: dict[str, Any] = {
        "requestId": request_id,
        "request": {"url": url, "method": "GET"},
        "type": rtype,
    }
    if redirect is not None:
        params["redirectResponse"] = redirect
    return params


def _hop(from_url: str, status: int, to_url: str, *, rid: str = "r1") -> dict[str, Any]:
    return {
        "requestId": rid,
        "from_url": from_url,
        "status": status,
        "to_url": to_url,
        "location": to_url,
        "resource_type": "Document",
    }


# ---- pure fold_redirects ----------------------------------------------------


def test_fold_builds_ordered_chain_with_statuses() -> None:
    rows = [
        _hop("http://a/1", 301, "http://a/2"),
        _hop("http://a/2", 302, "http://a/3"),
    ]
    result = fold_redirects(rows)
    assert result["total"] == 1
    chain = result["chains"][0]
    assert chain["requestId"] == "r1"
    assert chain["start_url"] == "http://a/1"
    assert chain["final_url"] == "http://a/3"
    assert chain["length"] == 2
    assert chain["statuses"] == [301, 302]
    assert len(chain["hops"]) == 2
    assert result["aggregate"]["max_length"] == 2


def test_fold_flags_https_to_http_downgrade() -> None:
    rows = [_hop("https://secure/login", 302, "http://secure/landing")]
    chain = fold_redirects(rows)["chains"][0]
    assert chain["downgrade"] is True
    assert fold_redirects(rows)["aggregate"]["downgrades"] == 1


def test_fold_flags_cross_host_and_cross_origin() -> None:
    rows = [_hop("https://a.example/x", 302, "https://b.example/y")]
    chain = fold_redirects(rows)["chains"][0]
    assert chain["cross_host"] is True
    assert chain["cross_origin"] is True
    # A same-host scheme change is cross_origin but not cross_host.
    same_host = [_hop("http://a.example/x", 301, "https://a.example/x")]
    ch2 = fold_redirects(same_host)["chains"][0]
    assert ch2["cross_host"] is False
    assert ch2["cross_origin"] is True
    assert ch2["downgrade"] is False


def test_fold_groups_by_request_id_and_ranks_longest_first() -> None:
    rows = [
        _hop("http://s/a", 302, "http://s/b", rid="short"),
        _hop("http://l/1", 302, "http://l/2", rid="long"),
        _hop("http://l/2", 302, "http://l/3", rid="long"),
    ]
    result = fold_redirects(rows)
    assert result["total"] == 2
    assert [c["requestId"] for c in result["chains"]] == ["long", "short"]


def test_fold_pages_and_reports_truncation() -> None:
    rows = [_hop(f"http://h/{i}", 302, f"http://h/{i}b", rid=f"r{i}") for i in range(5)]
    result = fold_redirects(rows, limit=2)
    assert result["count"] == 2
    assert result["total"] == 5
    assert result["truncated"] is True


def test_fold_on_no_redirects() -> None:
    result = fold_redirects([])
    assert result["chains"] == []
    assert result["total"] == 0
    assert result["aggregate"]["max_length"] == 0


# ---- capture through the CDP event wiring ----------------------------------


def test_redirect_response_hop_is_captured_before_row_overwrite() -> None:
    handle = _Handle()
    WebBackend()._wire_events(handle)  # type: ignore[arg-type]
    cdp = handle.cdp

    # First hop: the original request, no redirectResponse yet.
    cdp.handlers["Network.requestWillBeSent"](
        _will_be_sent("r1", "https://site/start")
    )
    # Second hop: same requestId, carrying the 302 that just fired.
    cdp.handlers["Network.requestWillBeSent"](
        _will_be_sent(
            "r1",
            "https://site/next",
            redirect={
                "url": "https://site/start",
                "status": 302,
                "headers": {"Location": "https://site/next"},
            },
        )
    )
    # The request row shows only the final hop (CDP overwrote it)...
    assert handle.requests["r1"]["url"] == "https://site/next"
    # ...but the redirect hop was captured.
    hops = list(handle.redirects)
    assert len(hops) == 1
    assert hops[0]["from_url"] == "https://site/start"
    assert hops[0]["status"] == 302
    assert hops[0]["to_url"] == "https://site/next"
    assert hops[0]["location"] == "https://site/next"

    folded = fold_redirects(list(handle.redirects))
    chain = folded["chains"][0]
    assert chain["start_url"] == "https://site/start"
    assert chain["final_url"] == "https://site/next"


def test_plain_request_records_no_redirect_hop() -> None:
    handle = _Handle()
    WebBackend()._wire_events(handle)  # type: ignore[arg-type]
    handle.cdp.handlers["Network.requestWillBeSent"](
        _will_be_sent("ok", "https://x/y")
    )
    assert list(handle.redirects) == []


# ---- query method + service dispatch + tool --------------------------------


def test_backend_redirects_folds_and_reports_dropped(monkeypatch: Any) -> None:
    handle = _Handle()
    handle.redirects = deque(  # type: ignore[attr-defined]
        [
            _hop("http://a/1", 302, "http://a/2"),
            _hop("http://a/2", 302, "http://a/3"),
        ]
    )
    handle.redirects_dropped = 4  # type: ignore[attr-defined]
    backend = WebBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: handle)

    payload = backend.redirects("s", limit=10)
    assert payload["total"] == 1
    assert payload["dropped"] == 4
    assert payload["chains"][0]["length"] == 2


class _StubService(WebAnalysisMixin):
    def __init__(self, backend: Any) -> None:
        self._web_backend = backend


def test_service_web_redirects_dispatches_to_backend() -> None:
    calls: list[tuple[str, dict[str, Any]]] = []

    class _FakeBackend:
        def redirects(self, session_id: str, *, limit: int = 100) -> dict[str, Any]:
            calls.append((session_id, {"limit": limit}))
            return {"chains": [], "total": 0}

    service = _StubService(_FakeBackend())
    result = service.web_redirects("sess-1", limit=25)
    assert result.ok is True
    assert calls == [("sess-1", {"limit": 25})]


def test_web_redirects_docstring_names_the_shape() -> None:
    doc = _tool_docstring("web.redirects")
    assert doc
    for field in ("start_url", "final_url", "downgrade", "cross_origin", "hops", "statuses"):
        assert field in doc
