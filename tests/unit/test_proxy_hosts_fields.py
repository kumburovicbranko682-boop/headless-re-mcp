"""proxy.hosts rolls the capture up per host for at-a-glance triage.

proxy.flows is one row per request; proxy.hosts aggregates the retained flows
by host (count, failed, methods, content-types, status codes, upstream IPs) so a
C2/CDN/telemetry endpoint stands out without a page-by-page walk. These cover
the aggregation and field shapes, the busiest-first ordering, the content-type
normalisation, the per-host set caps/truncation, the host_filter, paging, the
dropped/total_flows accounting, an integration pass through the real recorder,
and the read-only classification.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.proxy.client import (
    _MAX_HOST_CONTENT_TYPES,
    ProxyBackend,
    _FlowRecorder,
)
from headless_re_mcp.tools.proxy import build_proxy_tools


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


def _backend_with(items: list[dict[str, Any]], monkeypatch: Any) -> ProxyBackend:
    recorder = SimpleNamespace(snapshot=lambda: list(items))
    backend = ProxyBackend()
    monkeypatch.setattr(
        backend, "_get", lambda session_id: SimpleNamespace(recorder=recorder)
    )
    return backend


def _flow(
    seq: int,
    host: str,
    *,
    method: str = "GET",
    status: int | None = 200,
    content_type: str = "",
    failed: bool = False,
    remote_ip: str = "",
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "id": str(seq),
        "seq": seq,
        "host": host,
        "method": method,
        "status": status,
        "content_type": content_type,
    }
    if failed:
        item["failed"] = True
    if remote_ip:
        item["remote_ip"] = remote_ip
    return item


def test_proxy_hosts_aggregates_and_orders_by_flow_count(monkeypatch: Any) -> None:
    items = [
        _flow(1, "api.example.com", method="GET", status=200,
              content_type="application/json", remote_ip="1.2.3.4"),
        _flow(2, "api.example.com", method="POST", status=200,
              content_type="application/json", remote_ip="1.2.3.4"),
        _flow(3, "api.example.com", method="GET", status=500,
              content_type="application/json", remote_ip="1.2.3.4"),
        _flow(4, "cdn.example.com", method="GET", status=200,
              content_type="image/png", remote_ip="5.6.7.8"),
        _flow(5, "tracker.io", method="GET", status=None, failed=True),
        _flow(6, "tracker.io", method="GET", status=204, content_type=""),
    ]
    backend = _backend_with(items, monkeypatch)
    payload = backend.hosts("s")
    assert payload["total"] == 3
    assert payload["total_flows"] == 6
    assert payload["dropped"] == 0
    assert [row["host"] for row in payload["hosts"]] == [
        "api.example.com",
        "tracker.io",
        "cdn.example.com",
    ]
    api = payload["hosts"][0]
    assert api["flows"] == 3
    assert api["failed"] == 0
    assert api["methods"] == ["GET", "POST"]
    assert api["content_types"] == ["application/json"]
    assert api["statuses"] == {"200": 2, "500": 1}
    assert api["remote_ips"] == ["1.2.3.4"]
    tracker = payload["hosts"][1]
    assert tracker["flows"] == 2
    assert tracker["failed"] == 1
    # The failed flow has no status, so it is not tallied; the empty
    # content-type is not listed as a bogus member, and no IP was seen.
    assert tracker["statuses"] == {"204": 1}
    assert tracker["content_types"] == []
    assert "remote_ips" not in tracker


def test_proxy_hosts_normalises_content_type(monkeypatch: Any) -> None:
    items = [
        _flow(1, "h", content_type="application/json; charset=utf-8"),
        _flow(2, "h", content_type="application/json"),
    ]
    payload = _backend_with(items, monkeypatch).hosts("s")
    assert payload["hosts"][0]["content_types"] == ["application/json"]


def test_proxy_hosts_caps_a_hostile_set_and_flags_truncated(monkeypatch: Any) -> None:
    items = [
        _flow(index + 1, "noisy", content_type=f"type/{index}")
        for index in range(_MAX_HOST_CONTENT_TYPES + 8)
    ]
    row = _backend_with(items, monkeypatch).hosts("s")["hosts"][0]
    assert len(row["content_types"]) == _MAX_HOST_CONTENT_TYPES
    assert row["truncated"] is True


def test_proxy_hosts_host_filter_before_paging(monkeypatch: Any) -> None:
    items = [
        _flow(1, "api.example.com"),
        _flow(2, "cdn.example.com"),
        _flow(3, "api.other.com"),
    ]
    payload = _backend_with(items, monkeypatch).hosts("s", host_filter="api.")
    assert payload["total"] == 2
    assert {row["host"] for row in payload["hosts"]} == {
        "api.example.com",
        "api.other.com",
    }
    # total_flows still counts the whole capture, not just matched hosts.
    assert payload["total_flows"] == 3


def test_proxy_hosts_pages_and_reports_has_more(monkeypatch: Any) -> None:
    items = [_flow(index + 1, f"host-{index:02d}") for index in range(5)]
    payload = _backend_with(items, monkeypatch).hosts("s", offset=0, limit=2)
    assert payload["count"] == 2
    assert payload["total"] == 5
    assert payload["has_more"] is True
    assert payload["offset"] == 0


def test_proxy_hosts_reports_ring_evictions_in_dropped(monkeypatch: Any) -> None:
    # The last seq is well past the retained count: the ring evicted the rest.
    items = [_flow(95, "h"), _flow(100, "h")]
    payload = _backend_with(items, monkeypatch).hosts("s")
    assert payload["dropped"] == 98  # 100 - 2 retained


def test_proxy_hosts_via_real_recorder(monkeypatch: Any) -> None:
    recorder = _FlowRecorder(capacity=50)
    for index in range(4):
        host = "a.test" if index % 2 == 0 else "b.test"
        request = SimpleNamespace(method="GET", pretty_url=f"http://{host}/{index}", host=host)
        response = SimpleNamespace(status_code=200, headers={"content-type": "text/html"})
        recorder.response(SimpleNamespace(id=str(index), request=request, response=response))
    backend = ProxyBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(recorder=recorder))
    payload = backend.hosts("s")
    by_host = {row["host"]: row for row in payload["hosts"]}
    assert by_host["a.test"]["flows"] == 2
    assert by_host["b.test"]["flows"] == 2
    assert by_host["a.test"]["content_types"] == ["text/html"]


def test_proxy_hosts_tool_docstring_and_read_only() -> None:
    doc = " ".join(_tool_docstring("proxy.hosts").split())
    assert "hosts" in doc
    assert "total_flows" in doc
    from headless_re_mcp.tools.catalog import _READ_ONLY_NAMES

    assert "proxy.hosts" in _READ_ONLY_NAMES
