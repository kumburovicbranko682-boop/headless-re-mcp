"""proxy.clear resets the capture ring while keeping the proxy running.

Drives the real _FlowRecorder with SimpleNamespace flows (same shape the other
proxy unit tests use) and the ProxyBackend.clear wiring through the _get seam.
No live proxy needed.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.proxy.client import (
    ProxyBackend,
    ProxyError,
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


def _fill(recorder: _FlowRecorder, count: int) -> None:
    for index in range(count):
        request = SimpleNamespace(method="GET", pretty_url=f"http://x/{index}", host="x")
        response = SimpleNamespace(status_code=200, headers={"content-type": "text/plain"})
        recorder.response(
            SimpleNamespace(id=str(index), request=request, response=response)
        )


def test_clear_drops_flows_and_bytes() -> None:
    recorder = _FlowRecorder(capacity=50)
    _fill(recorder, 6)
    assert recorder.count() == 6
    assert recorder.retained_bytes() > 0

    cleared = recorder.clear()
    assert cleared == 6
    assert recorder.count() == 0
    assert recorder.retained_bytes() == 0
    assert recorder.snapshot() == []


def test_clear_resets_the_sequence_so_dropped_starts_fresh() -> None:
    recorder = _FlowRecorder(capacity=3)
    _fill(recorder, 5)  # seq is now 5, two evicted
    recorder.clear()
    _fill(recorder, 1)  # first flow of the new window
    row = recorder.snapshot()[0]
    assert row["seq"] == 1


def test_backend_clear_reports_count_and_running(monkeypatch: Any) -> None:
    recorder = _FlowRecorder(capacity=50)
    _fill(recorder, 4)
    backend = ProxyBackend()
    monkeypatch.setattr(
        backend, "_get", lambda session_id: SimpleNamespace(recorder=recorder)
    )
    payload = backend.clear("s")
    assert payload == {"cleared": 4, "running": True}
    assert recorder.count() == 0


def test_backend_clear_without_a_proxy_is_invalid_state() -> None:
    backend = ProxyBackend()
    with pytest.raises(ProxyError) as caught:
        backend.clear("no-such-session")
    assert caught.value.code == "invalid_state"


def test_proxy_clear_docstring_names_the_shape() -> None:
    doc = _tool_docstring("proxy.clear")
    assert "cleared" in doc
    assert "running" in doc
    assert "proxy.stop" in doc
