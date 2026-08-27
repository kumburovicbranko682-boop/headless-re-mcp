"""proxy.hosts aggregates the capture ring into an honest per-host footprint."""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.proxy.client import (
    _MAX_HOST_METHODS,
    _MAX_HOST_STATUSES,
    _FlowRecorder,
    _summarize_hosts,
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


def _row(
    host: str, method: str = "GET", status: int | None = 200, size: int = 0, error: bool = False
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "host": host,
        "method": method,
        "status": None if error else status,
        "response_size": size,
    }
    if error:
        row["error"] = True
    return row


def test_summarize_hosts_aggregates_and_sorts_by_flow_count() -> None:
    """Rows fold into one per host, most-contacted first, tie-broken by name.

    Measured: three flows to api (two methods, three statuses, 150 body bytes),
    one to cdn, one errored flow to auth -> api first with flows 3, then auth
    and cdn (each 1) ordered by name. The errored host shows errors 1 with no
    status, so it is not read as having served content. Field is hosts.
    """
    rows = [
        _row("api.example.com", "GET", 200, 100),
        _row("api.example.com", "POST", 201, 50),
        _row("api.example.com", "GET", 500, 0),
        _row("cdn.example.com", "GET", 200, 4000),
        _row("auth.example.com", error=True),
    ]
    payload = _summarize_hosts(rows, offset=0, limit=50)
    assert "items" not in payload
    assert payload["total"] == 3
    assert [h["host"] for h in payload["hosts"]] == [
        "api.example.com",
        "auth.example.com",
        "cdn.example.com",
    ]
    api = payload["hosts"][0]
    assert api["flows"] == 3
    assert api["errors"] == 0
    assert api["response_bytes"] == 150
    assert api["methods"] == ["GET", "POST"]
    assert api["statuses"] == [200, 201, 500]
    auth = payload["hosts"][1]
    assert auth["flows"] == 1
    assert auth["errors"] == 1
    assert auth["statuses"] == []
    cdn = payload["hosts"][2]
    assert cdn["response_bytes"] == 4000


def test_summarize_hosts_degrades_on_odd_shapes() -> None:
    """Non-dict rows and a non-list argument answer empty, not an exception."""
    assert _summarize_hosts(["x", 7, None], offset=0, limit=10)["hosts"] == []
    assert _summarize_hosts(None, offset=0, limit=10)["total"] == 0


def test_summarize_hosts_caps_the_per_host_method_and_status_lists() -> None:
    """A hostile host cannot make its methods/statuses lists unbounded."""
    rows = [_row("noisy.test", method=f"M{index:03d}") for index in range(40)]
    rows += [_row("noisy.test", status=200 + index) for index in range(80)]
    host = _summarize_hosts(rows, offset=0, limit=10)["hosts"][0]
    assert len(host["methods"]) == _MAX_HOST_METHODS
    assert len(host["statuses"]) == _MAX_HOST_STATUSES


def test_summarize_hosts_paginates() -> None:
    rows = [_row(f"h{index:03d}.test") for index in range(25)]
    page0 = _summarize_hosts(rows, offset=0, limit=10)
    assert page0["count"] == 10
    assert page0["total"] == 25
    assert page0["has_more"] is True
    tail = _summarize_hosts(rows, offset=20, limit=10)
    assert tail["count"] == 5
    assert tail["has_more"] is False


def _ok_flow(flow_id: str, host: str) -> Any:
    request = SimpleNamespace(method="GET", pretty_url=f"http://{host}/{flow_id}", host=host)
    response = SimpleNamespace(status_code=200, headers={"content-type": "text/plain"})
    return SimpleNamespace(id=flow_id, request=request, response=response)


def _err_flow(flow_id: str, host: str) -> Any:
    request = SimpleNamespace(method="GET", pretty_url=f"http://{host}/{flow_id}", host=host)
    error = SimpleNamespace(msg="net::ERR_CONNECTION_REFUSED")
    return SimpleNamespace(id=flow_id, request=request, response=None, error=error)


def test_summarize_hosts_matches_real_recorder_entries() -> None:
    """The aggregate lines up with the actual entry shape the recorder writes."""
    recorder = _FlowRecorder(capacity=16)
    recorder.response(_ok_flow("ok1", "a.test"))
    recorder.response(_ok_flow("ok2", "a.test"))
    recorder.error(_err_flow("e1", "b.test"))
    payload = _summarize_hosts(recorder.snapshot(), offset=0, limit=10)
    by_host = {h["host"]: h for h in payload["hosts"]}
    assert by_host["a.test"]["flows"] == 2
    assert by_host["a.test"]["errors"] == 0
    assert 200 in by_host["a.test"]["statuses"]
    assert by_host["b.test"]["errors"] == 1
    assert by_host["b.test"]["statuses"] == []
    doc = _tool_docstring("proxy.hosts")
    assert "hosts" in doc
    assert "response_bytes" in doc
    assert "errors" in doc
