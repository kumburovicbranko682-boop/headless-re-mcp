"""proxy.stats folds the capture ring into a triage summary."""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.proxy.client import (
    _MAX_STATS_HOSTS,
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


def _respond(
    recorder: _FlowRecorder,
    fid: str,
    method: str,
    url: str,
    host: str,
    status: int,
    content_type: str,
    *,
    body: bytes | None = None,
) -> None:
    request = SimpleNamespace(method=method, pretty_url=url, host=host)
    if body is not None:
        request.raw_content = body
    response = SimpleNamespace(status_code=status, headers={"content-type": content_type})
    recorder.response(SimpleNamespace(id=fid, request=request, response=response))


def test_proxy_stats_folds_the_capture_into_a_summary(monkeypatch: Any) -> None:
    """A capture of mixed traffic must summarize by method/status/host/type.

    Drive GETs, POSTs (with request bodies), a 4xx and a 5xx, a WebSocket upgrade
    and a failed flow, then assert the aggregate: method counts, status classes,
    top hosts, merged content types, and the failed/websocket/with_request_body/
    no_status tallies.
    """
    recorder = _FlowRecorder(capacity=50)
    _respond(recorder, "1", "GET", "http://a/1", "a", 200, "text/html; charset=utf-8")
    _respond(recorder, "2", "GET", "http://a/2", "a", 200, "text/html")
    _respond(recorder, "3", "GET", "http://a/3", "a", 404, "text/plain")
    _respond(recorder, "4", "POST", "http://b/login", "b", 200, "application/json", body=b"{}")
    _respond(recorder, "5", "POST", "http://b/submit", "b", 500, "application/json", body=b"{}")
    # A WebSocket upgrade: a 101 handshake plus a frame flags the flow.
    _respond(recorder, "ws", "GET", "http://d/socket", "d", 101, "")
    recorder.websocket_message(
        SimpleNamespace(id="ws", websocket=SimpleNamespace(
            messages=[SimpleNamespace(from_client=True, content=b"hi")]
        ))
    )
    # A failed flow carries no status and no content type.
    recorder.error(
        SimpleNamespace(
            id="dead",
            request=SimpleNamespace(method="GET", pretty_url="http://c/x", host="c", headers={}),
            response=None,
            error=SimpleNamespace(msg="connection refused"),
        )
    )

    backend = ProxyBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(recorder=recorder))
    stats = backend.stats("s")

    assert stats["total"] == 7
    assert stats["by_method"] == {"GET": 5, "POST": 2}
    assert stats["by_status_class"] == {"1xx": 1, "2xx": 3, "4xx": 1, "5xx": 1}
    assert stats["no_status"] == 1
    assert stats["failed"] == 1
    assert stats["websockets"] == 1
    assert stats["with_request_body"] == 2
    # Hosts are ranked by count; a leads with three flows.
    assert stats["top_hosts"][0] == {"host": "a", "count": 3}
    assert stats["host_count"] == 4
    # "text/html; charset=utf-8" and "text/html" collapse to one bucket.
    by_type = {row["content_type"]: row["count"] for row in stats["top_content_types"]}
    assert by_type["text/html"] == 2
    assert by_type["application/json"] == 2
    assert by_type["text/plain"] == 1
    assert stats["content_type_count"] == 3
    # An empty capture would still be summarizable, so there is no flows list.
    assert "flows" not in stats


def test_proxy_stats_caps_the_top_lists_but_counts_all(monkeypatch: Any) -> None:
    """Hundreds of hosts must not become a second full listing.

    Feed more distinct hosts than the top cap and assert top_hosts is trimmed to
    the cap while host_count still reports every distinct host, so a trimmed list
    is visible rather than mistaken for the whole picture.
    """
    recorder = _FlowRecorder(capacity=200)
    hosts = _MAX_STATS_HOSTS + 5
    for index in range(hosts):
        _respond(recorder, str(index), "GET", f"http://h{index}/", f"h{index}", 200, "text/plain")

    backend = ProxyBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(recorder=recorder))
    stats = backend.stats("s")

    assert len(stats["top_hosts"]) == _MAX_STATS_HOSTS
    assert stats["host_count"] == hosts
    # Every host had exactly one flow, so all counts are 1 and the ranking is a
    # stable alphabetical tie-break, not a random slice.
    assert all(row["count"] == 1 for row in stats["top_hosts"])
    assert len(stats["top_content_types"]) == 1
    assert stats["content_type_count"] == 1


def test_proxy_stats_docstring_names_the_shape() -> None:
    doc = _tool_docstring("proxy.stats")
    assert doc, "proxy.stats is missing its docstring"
    assert "by_method" in doc
    assert "by_status_class" in doc
    assert "top_hosts" in doc
    assert "no_status" in doc
    assert "dropped" in doc
