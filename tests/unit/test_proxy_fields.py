"""proxy tool descriptions must name the fields the backends return."""

from __future__ import annotations

import ast
import gzip
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

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


def _flow_get_response(monkeypatch: Any, tmp_path: Path, response: Any) -> dict[str, Any]:
    request = SimpleNamespace(method="GET", pretty_url="http://x/1", headers={"accept": "*/*"})
    flow = SimpleNamespace(request=request, response=response)

    class _Recorder:
        def raw(self, flow_id: str) -> Any:
            return flow

    backend = ProxyBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(recorder=_Recorder()))
    return backend.flow_get("s", "f1", tmp_path)["response"]


def test_proxy_flow_get_decodes_a_gzip_body(tmp_path: Path, monkeypatch: Any) -> None:
    """raw_content is the on-wire body; for gzip that is not the text.

    Returned verbatim it decoded to noise, so the tool that exists to show a
    response body handed back garbage for the encoding most of the web uses.
    """
    text = "hello gzip world " * 20
    response = SimpleNamespace(
        status_code=200,
        headers={"content-type": "text/plain", "content-encoding": "gzip"},
        raw_content=gzip.compress(text.encode("utf-8")),
    )
    result = _flow_get_response(monkeypatch, tmp_path, response)
    assert result["body"] == text
    assert result["body_encoding"] == "gzip"
    assert result["body_decoded"] is True
    assert result["size"] == len(text.encode("utf-8"))
    # A compressible body is smaller on the wire than decoded.
    assert result["encoded_size"] < result["size"]


def test_proxy_flow_get_labels_a_body_it_will_not_decode(tmp_path: Path, monkeypatch: Any) -> None:
    """Brotli cannot be output-bounded here, so it is flagged, not mislabelled.

    The old code decoded the raw brotli bytes as UTF-8 and called them the body.
    Now the caller is told the bytes are still brotli (body_decoded false) rather
    than handed noise dressed as text.
    """
    brotli = pytest.importorskip("brotli")
    blob = brotli.compress(b"this content is really still brotli " * 5)
    response = SimpleNamespace(
        status_code=200,
        headers={"content-encoding": "br"},
        raw_content=blob,
    )
    result = _flow_get_response(monkeypatch, tmp_path, response)
    assert result["body_encoding"] == "br"
    assert result["body_decoded"] is False
    assert result["encoded_size"] == len(blob)


def test_proxy_flow_get_decodes_a_zstd_body(tmp_path: Path, monkeypatch: Any) -> None:
    zstandard = pytest.importorskip("zstandard")
    text = "zstandard payload " * 20
    response = SimpleNamespace(
        status_code=200,
        headers={"content-encoding": "zstd"},
        raw_content=zstandard.ZstdCompressor().compress(text.encode("utf-8")),
    )
    result = _flow_get_response(monkeypatch, tmp_path, response)
    assert result["body"] == text
    assert result["body_encoding"] == "zstd"
    assert result["body_decoded"] is True


def test_proxy_flow_get_bounds_a_decompression_bomb(tmp_path: Path, monkeypatch: Any) -> None:
    """A retained few-KB body can inflate to gigabytes; the decode stops early."""
    from headless_re_mcp.backends.proxy import client as mod

    monkeypatch.setattr(mod, "_MAX_DECODED_BODY", 1024)
    bomb = gzip.compress(b"\x00" * (5 * 1024 * 1024))
    assert len(bomb) < 10_000  # tiny on the wire, huge decoded
    response = SimpleNamespace(
        status_code=200,
        headers={"content-encoding": "gzip"},
        raw_content=bomb,
    )
    result = _flow_get_response(monkeypatch, tmp_path, response)
    assert result["body_decoded"] is True
    assert result["body_truncated"] is True
    assert result["size"] == 1024


def _flow_get_full(monkeypatch: Any, tmp_path: Path, request: Any, response: Any) -> dict[str, Any]:
    flow = SimpleNamespace(request=request, response=response)

    class _Recorder:
        def raw(self, flow_id: str) -> Any:
            return flow

    backend = ProxyBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(recorder=_Recorder()))
    return backend.flow_get("s", "f1", tmp_path)


def test_proxy_flow_get_preserves_every_set_cookie(tmp_path: Path, monkeypatch: Any) -> None:
    """dict(headers) folds repeats into one comma-joined value; Set-Cookie can't.

    A response setting several cookies used to come back as a single mangled
    string (and an Expires date's own comma made it ambiguous), losing exactly
    the session/auth data flow.get exists to surface. Headers now come back as an
    ordered list of {name, value}, so each Set-Cookie is its own entry.
    """
    from mitmproxy.http import Headers

    resp_headers = Headers()
    resp_headers.add("Set-Cookie", "sid=abc; Expires=Wed, 21 Oct 2025 07:28:00 GMT")
    resp_headers.add("Set-Cookie", "token=xyz")
    resp_headers.add("Content-Type", "text/html")
    request = SimpleNamespace(method="GET", pretty_url="http://x/", headers={}, raw_content=b"")
    response = SimpleNamespace(status_code=200, headers=resp_headers, raw_content=b"ok")
    payload = _flow_get_full(monkeypatch, tmp_path, request, response)

    headers = payload["response"]["headers"]
    assert isinstance(headers, list)
    cookies = [h["value"] for h in headers if h["name"].lower() == "set-cookie"]
    assert cookies == [
        "sid=abc; Expires=Wed, 21 Oct 2025 07:28:00 GMT",
        "token=xyz",
    ]
    assert {"name": "Content-Type", "value": "text/html"} in headers


def test_proxy_flow_get_returns_the_request_body(tmp_path: Path, monkeypatch: Any) -> None:
    """The POST payload -- the params traffic analysis is usually after -- was
    unreachable when only the response body came back."""
    text = '{"user":"alice","token":"secret"}'
    request = SimpleNamespace(
        method="POST",
        pretty_url="http://x/login",
        headers={"content-type": "application/json"},
        raw_content=text.encode("utf-8"),
    )
    response = SimpleNamespace(status_code=200, headers={}, raw_content=b"ok")
    payload = _flow_get_full(monkeypatch, tmp_path, request, response)
    assert payload["request"]["body"] == text
    assert payload["request"]["size"] == len(text.encode("utf-8"))
    assert payload["response"]["body"] == "ok"


def test_proxy_flow_get_omits_the_body_for_a_bodyless_get(
    tmp_path: Path, monkeypatch: Any
) -> None:
    request = SimpleNamespace(method="GET", pretty_url="http://x/", headers={}, raw_content=b"")
    response = SimpleNamespace(status_code=200, headers={}, raw_content=b"hello")
    payload = _flow_get_full(monkeypatch, tmp_path, request, response)
    assert "body" not in payload["request"]
    assert "body_path" not in payload["request"]
    assert payload["response"]["body"] == "hello"


def test_proxy_flow_get_decodes_a_gzip_request_body(tmp_path: Path, monkeypatch: Any) -> None:
    text = "field=value&" * 30
    request = SimpleNamespace(
        method="POST",
        pretty_url="http://x/",
        headers={"content-encoding": "gzip"},
        raw_content=gzip.compress(text.encode("utf-8")),
    )
    response = SimpleNamespace(status_code=204, headers={}, raw_content=b"")
    payload = _flow_get_full(monkeypatch, tmp_path, request, response)
    assert payload["request"]["body"] == text
    assert payload["request"]["body_encoding"] == "gzip"
    assert payload["request"]["body_decoded"] is True


def test_proxy_flow_get_spills_a_large_request_body(tmp_path: Path, monkeypatch: Any) -> None:
    blob = b"A" * 200_001
    request = SimpleNamespace(
        method="PUT", pretty_url="http://x/upload", headers={}, raw_content=blob
    )
    response = SimpleNamespace(status_code=200, headers={}, raw_content=b"ok")
    payload = _flow_get_full(monkeypatch, tmp_path, request, response)
    assert "body" not in payload["request"]
    spill = Path(str(payload["request"]["body_path"]))
    assert spill.parent == tmp_path
    assert spill.name.startswith("flow-req-") and spill.suffix == ".bin"
    assert spill.read_bytes() == blob


def test_proxy_flow_get_registers_both_spilled_bodies(tmp_path: Path, monkeypatch: Any) -> None:
    """Both halves can spill; the service must record each so retention reclaims
    them, and the request id must not overwrite the response id."""
    from dataclasses import replace

    from headless_re_mcp.config import Settings
    from headless_re_mcp.core.service import AnalysisService

    service = AnalysisService(replace(Settings.load(), artifact_root=tmp_path / "artifacts"))
    try:
        req_body = tmp_path / "flow-req-x.bin"
        resp_body = tmp_path / "flow-resp-y.bin"
        req_body.write_bytes(b"q" * 10)
        resp_body.write_bytes(b"r" * 10)
        fake = {
            "id": "f1",
            "request": {"method": "POST", "body_path": str(req_body)},
            "response": {"status": 200, "body_path": str(resp_body)},
        }
        service._proxy_backend.flow_get = (  # type: ignore[method-assign]
            lambda session_id, flow_id, artifact_dir: fake
        )
        monkeypatch.setattr(service, "_proxy_artifact_dir", lambda session_id: tmp_path)
        result = service.proxy_flow_get("s", "f1")
        assert result.ok is True and result.data is not None
        assert "artifact_id" in result.data
        assert "request_artifact_id" in result.data
        assert result.data["artifact_id"] != result.data["request_artifact_id"]
        # Both files are known to retention, not orphaned on disk.
        assert service.repository.list_artifacts()["total"] == 2
    finally:
        service.close_all()


def _make_error_flow(
    flow_id: str = "e1",
    *,
    url: str = "http://x/pinned",
    msg: str = "Client TLS handshake failed",
) -> Any:
    request = SimpleNamespace(
        method="POST",
        pretty_url=url,
        host="x",
        headers={},
        raw_content=b"",
        timestamp_start=1000.0,
    )
    return SimpleNamespace(
        id=flow_id, request=request, response=None, error=SimpleNamespace(msg=msg)
    )


def test_proxy_records_a_failed_flow_marked_with_its_error(monkeypatch: Any) -> None:
    """error(), not response(), fires when a flow fails before any response.

    Without wiring it, every reset/refused/TLS-handshake-failure connection was
    dropped from proxy.flows -- exactly the evidence a proxy is set up to catch.
    Measured: one error flow -> one row, status None, failed True, error_text set,
    with the attempted method/url still on the summary.
    """
    recorder = _FlowRecorder(capacity=50)
    recorder.error(_make_error_flow())

    backend = ProxyBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(recorder=recorder))
    payload = backend.flows("s", offset=0, limit=10)
    assert payload["count"] == 1
    row = payload["flows"][0]
    assert row["status"] is None
    assert row["failed"] is True
    assert row["error_text"] == "Client TLS handshake failed"
    assert row["method"] == "POST"
    assert row["url"] == "http://x/pinned"
    doc = _tool_docstring("proxy.flows")
    assert "failed" in doc
    assert "error_text" in doc


def test_proxy_flow_get_reports_the_error_on_a_failed_flow(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A failed flow retains the attempted request; flow.get says why the
    response is empty rather than let it read as a fetch of a zero-length body."""
    flow = _make_error_flow(url="http://x/login")
    flow.request.raw_content = b'{"u":"a"}'

    class _Recorder:
        def raw(self, flow_id: str) -> Any:
            return flow

    backend = ProxyBackend()
    monkeypatch.setattr(backend, "_get", lambda session_id: SimpleNamespace(recorder=_Recorder()))
    payload = backend.flow_get("s", "e1", tmp_path)
    assert payload["failed"] is True
    assert payload["error_text"] == "Client TLS handshake failed"
    assert payload["request"]["method"] == "POST"
    assert payload["request"]["body"] == '{"u":"a"}'
    assert payload["response"]["status"] is None
    doc = _tool_docstring("proxy.flow.get")
    assert "failed" in doc
    assert "error_text" in doc


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
    doc = _tool_docstring("proxy.export_har")
    assert "path" in doc
    assert "entry_count" in doc
