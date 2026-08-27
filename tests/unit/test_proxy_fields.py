"""proxy tool descriptions must name the fields the backends return."""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.proxy.client import (
    _MAX_FLOWS,
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


def test_proxy_flows_puts_the_page_in_flows_with_content_type(
    monkeypatch: Any,
) -> None:
    """The catalog said content type and never named the list field.

    Measured: 25 held, limit 10 -> count 10, total 25, field is flows not
    items or requests, and each row carries content_type with no
    'content type' key. Looking for those after a successful call reads as
    an empty capture, and a full page with no total reads as the whole log.
    """
    recorder = _FlowRecorder(capacity=50)
    for index in range(25):
        request = SimpleNamespace(
            method="GET", pretty_url=f"http://x/{index}", host="x"
        )
        response = SimpleNamespace(
            status_code=200, headers={"content-type": "text/plain"}
        )
        recorder.response(
            SimpleNamespace(id=str(index), request=request, response=response)
        )

    backend = ProxyBackend()
    monkeypatch.setattr(
        backend, "_get", lambda session_id: SimpleNamespace(recorder=recorder)
    )
    payload = backend.flows("s", offset=0, limit=10)
    assert "items" not in payload
    assert "requests" not in payload
    assert payload["count"] == 10
    assert payload["total"] == 25
    assert len(payload["flows"]) == 10
    row = payload["flows"][0]
    assert "content type" not in row
    assert row["content_type"] == "text/plain"
    normalized = backend.flows("s", offset=-10, limit=0)
    assert normalized["offset"] == 0
    assert normalized["count"] == 1
    assert normalized["has_more"] is True
    doc = _tool_docstring("proxy.flows")
    assert "Answers with flows" in doc
    assert "content_type" in doc
    assert "total" in doc
    assert "body_omitted" in doc
    assert "metadata_truncated" in doc


def test_proxy_flows_names_has_more_and_dropped(monkeypatch: Any) -> None:
    """The catalog named the page and never said when the ring had already lost rows.

    Measured: capacity 5, 12 responses, limit 3 -> count 3, total 5, has_more
    True, dropped 7. Looking at a full page with no has_more reads as the
    whole capture; looking with no dropped reads as nothing evicted.
    """
    recorder = _FlowRecorder(capacity=5)
    for index in range(12):
        request = SimpleNamespace(
            method="GET", pretty_url=f"http://x/{index}", host="x"
        )
        response = SimpleNamespace(
            status_code=200, headers={"content-type": "text/plain"}
        )
        recorder.response(
            SimpleNamespace(id=str(index), request=request, response=response)
        )

    backend = ProxyBackend()
    monkeypatch.setattr(
        backend, "_get", lambda session_id: SimpleNamespace(recorder=recorder)
    )
    payload = backend.flows("s", offset=0, limit=3)
    assert payload["count"] == 3
    assert payload["total"] == 5
    assert payload["has_more"] is True
    assert payload["dropped"] == 7
    assert len(payload["flows"]) == 3
    doc = _tool_docstring("proxy.flows")
    assert "has_more" in doc
    assert "dropped" in doc


def test_proxy_flow_get_names_body_path_on_the_response(tmp_path: Path, monkeypatch: Any) -> None:
    """The catalog said headers and body, never where a spill actually lands.

    Measured: 200001-byte body -> no top-level body or headers, response.size
    200001, response.body_path set, response.body absent. Looking for body
    after a successful large fetch reads as a missing capture.
    """
    request = SimpleNamespace(
        method="GET", pretty_url="http://x/1", headers={"accept": "text/plain"}
    )
    response = SimpleNamespace(
        status_code=200,
        headers={"content-type": "text/plain"},
        raw_content=b"x" * 200_001,
    )
    flow = SimpleNamespace(request=request, response=response)

    class _Recorder:
        def raw(self, flow_id: str) -> Any:
            return flow

    backend = ProxyBackend()
    monkeypatch.setattr(
        backend, "_get", lambda session_id: SimpleNamespace(recorder=_Recorder())
    )
    payload = backend.flow_get("s", "f1", tmp_path)
    repeated = backend.flow_get("s", "f1", tmp_path)
    hostile = backend.flow_get("s", "../../escaped", tmp_path)
    assert "body" not in payload
    assert "headers" not in payload
    assert "body" not in payload["response"]
    assert payload["response"]["size"] == 200_001
    paths = [
        Path(str(item["response"]["body_path"]))
        for item in (payload, repeated, hostile)
    ]
    assert len(set(paths)) == 3
    assert all(path.parent == tmp_path for path in paths)
    assert all(path.name.startswith("flow-") and path.suffix == ".bin" for path in paths)
    assert all(path.is_file() for path in paths)
    assert not (tmp_path.parent / "escaped.bin").exists()
    doc = _tool_docstring("proxy.flow.get")
    assert "body_path" in doc
    assert "response" in doc


def test_proxy_status_names_flow_count_and_retained_max() -> None:
    """The catalog said how many flows and never named the count field.

    Measured: 3 retained -> running True, flow_count 3, retained_max 2000,
    no count or flows key. Looking for count after a successful status
    reads as a proxy that captured nothing.
    """
    recorder = _FlowRecorder(capacity=8)
    for index in range(3):
        request = SimpleNamespace(
            method="GET", pretty_url=f"http://x/{index}", host="x"
        )
        response = SimpleNamespace(
            status_code=200, headers={"content-type": "text/plain"}
        )
        recorder.response(
            SimpleNamespace(id=str(index), request=request, response=response)
        )
    backend = ProxyBackend()
    backend._instances["s"] = SimpleNamespace(
        host="127.0.0.1", port=8080, recorder=recorder
    )
    payload = backend.status("s")
    assert "count" not in payload
    assert "flows" not in payload
    assert payload["running"] is True
    assert payload["flow_count"] == 3
    assert payload["retained_max"] == _MAX_FLOWS
    assert payload["retained_bytes"] >= 0
    assert payload["retained_bytes_max"] > payload["retained_bytes"]
    idle = backend.status("missing")
    assert idle == {"running": False}
    doc = _tool_docstring("proxy.status")
    assert "flow_count" in doc
    assert "retained_max" in doc
    assert "retained_bytes" in doc
    assert "retained_bytes_max" in doc


def test_proxy_export_har_names_path_and_entry_count(
    tmp_path: Path,
) -> None:
    """The catalog said a HAR artifact and never named the payload.

    Measured: 4 flows -> path ending capture.har, entry_count 4, no har or
    output key. Looking for har after a successful export reads as a missing
    capture.
    """
    recorder = _FlowRecorder()
    for index in range(4):
        request = SimpleNamespace(
            method="GET", pretty_url=f"http://x/{index}", host="x"
        )
        response = SimpleNamespace(
            status_code=200, headers={"content-type": "text/plain"}
        )
        recorder.response(
            SimpleNamespace(id=str(index), request=request, response=response)
        )
    backend = ProxyBackend()
    backend._instances["s"] = SimpleNamespace(recorder=recorder)
    payload = backend.export_har("s", tmp_path / "capture.har")
    assert "har" not in payload
    assert "output" not in payload
    assert payload["entry_count"] == 4
    assert payload["path"].endswith("capture.har")
    # Nothing evicted from a fresh ring, so a clean export says dropped 0.
    assert payload["dropped"] == 0
    doc = _tool_docstring("proxy.export_har")
    assert "path" in doc
    assert "entry_count" in doc
    assert "dropped" in doc


def test_proxy_export_har_reports_flows_the_ring_evicted(tmp_path: Path) -> None:
    """A HAR from a capture longer than the ring must not read as complete.

    Measured: capacity 5, 12 responses -> the HAR holds the newest 5 entries
    and dropped is 7, matching proxy.flows. Without dropped, a HAR of a long
    session looks like the whole session.
    """
    recorder = _FlowRecorder(capacity=5)
    for index in range(12):
        request = SimpleNamespace(method="GET", pretty_url=f"http://x/{index}", host="x")
        response = SimpleNamespace(status_code=200, headers={"content-type": "text/plain"})
        recorder.response(
            SimpleNamespace(id=str(index), request=request, response=response)
        )
    backend = ProxyBackend()
    backend._instances["s"] = SimpleNamespace(recorder=recorder)
    payload = backend.export_har("s", tmp_path / "capture.har")
    assert payload["entry_count"] == 5
    assert payload["dropped"] == 7
