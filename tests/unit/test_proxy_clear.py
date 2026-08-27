"""proxy.clear empties the capture ring without stopping the proxy."""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.proxy.client import ProxyBackend, _FlowRecorder
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


def _respond(recorder: _FlowRecorder, fid: str, host: str, *, body: bytes | None = None) -> None:
    request = SimpleNamespace(method="GET", pretty_url=f"http://{host}/{fid}", host=host)
    if body is not None:
        request.raw_content = body
    response = SimpleNamespace(status_code=200, headers={"content-type": "text/html"})
    recorder.response(SimpleNamespace(id=fid, request=request, response=response))


def test_proxy_clear_empties_the_recorder_and_resets_the_baseline() -> None:
    """Clearing must drop every flow and reset seq so dropped restarts clean.

    Record a few flows, clear, and assert the snapshot is empty, the discard
    count is right, retained bytes are back to zero, and a flow captured after
    the clear starts a fresh sequence (seq 1, no phantom eviction) -- the whole
    point of clear is a clean baseline, not a paused counter.
    """
    recorder = _FlowRecorder(capacity=50)
    _respond(recorder, "1", "a", body=b"{}")
    _respond(recorder, "2", "b")
    _respond(recorder, "3", "b")
    assert len(recorder.snapshot()) == 3
    assert recorder.retained_bytes() > 0

    cleared = recorder.clear()
    assert cleared == 3
    assert recorder.snapshot() == []
    assert recorder.count() == 0
    assert recorder.retained_bytes() == 0

    # A flow after the clear starts the sequence over, so the summary's dropped
    # (last seq - held) is 0 rather than reporting the pre-clear history as lost.
    _respond(recorder, "4", "c")
    snapshot = recorder.snapshot()
    assert len(snapshot) == 1
    assert snapshot[-1]["seq"] == 1


def test_proxy_clear_backend_reports_count_and_keeps_running(monkeypatch: Any) -> None:
    recorder = _FlowRecorder(capacity=50)
    _respond(recorder, "1", "a")
    _respond(recorder, "2", "a")

    backend = ProxyBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(recorder=recorder))
    result = backend.clear("s")
    assert result == {"cleared": 2, "running": True}
    # A second clear on the now-empty ring is a no-op count, still running.
    assert backend.clear("s") == {"cleared": 0, "running": True}


def test_proxy_clear_docstring_names_the_shape() -> None:
    doc = _tool_docstring("proxy.clear")
    assert doc, "proxy.clear is missing its docstring"
    assert "cleared" in doc
    assert "running" in doc
    assert "without stopping" in doc
    assert "invalid_state" in doc
