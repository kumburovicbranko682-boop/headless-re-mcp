"""proxy.flow.get must return both bodies and never a lossy binary decode."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.proxy.client import _MAX_METADATA_BYTES, ProxyBackend
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService


def _backend_with_flow(monkeypatch: Any, flow: Any) -> ProxyBackend:
    class _Recorder:
        def raw(self, flow_id: str) -> Any:
            return flow

    backend = ProxyBackend()
    monkeypatch.setattr(
        backend, "_get", lambda session_id: SimpleNamespace(recorder=_Recorder())
    )
    return backend


def test_flow_get_returns_the_request_body_as_text(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The request payload is what an API RE agent most needs, and used to be dropped.

    Measured: a JSON request body -> request.body is the exact text, request.size
    its byte length, and the response body still comes back too.
    """
    sent = b'{"user":"root","pin":1234}'
    request = SimpleNamespace(
        method="POST",
        pretty_url="http://x/login",
        headers={"content-type": "application/json"},
        raw_content=sent,
    )
    response = SimpleNamespace(
        status_code=200,
        headers={"content-type": "text/plain"},
        raw_content=b"ok",
    )
    backend = _backend_with_flow(monkeypatch, SimpleNamespace(request=request, response=response))

    payload = backend.flow_get("s", "f1", tmp_path)

    assert payload["request"]["body"] == sent.decode("utf-8")
    assert payload["request"]["size"] == len(sent)
    assert "body_path" not in payload["request"]
    assert payload["response"]["body"] == "ok"
    assert payload["response"]["size"] == 2


def test_flow_get_spills_a_small_binary_body_instead_of_mangling_it(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A small binary response used to be decoded with errors=replace and handed back as text.

    Measured: a PNG-signature body under the inline cap -> no response.body,
    response.body_path holds the exact bytes and response.spill_reason is
    binary, so an agent never mistakes mojibake for the real payload.
    """
    blob = b"\x89PNG\r\n\x1a\n\x00\x01\x02\xff\xfe" + bytes(range(256)) * 4
    request = SimpleNamespace(
        method="GET",
        pretty_url="http://x/img",
        headers={"accept": "*/*"},
    )
    response = SimpleNamespace(
        status_code=200,
        headers={"content-type": "image/png"},
        raw_content=blob,
    )
    backend = _backend_with_flow(monkeypatch, SimpleNamespace(request=request, response=response))

    payload = backend.flow_get("s", "f2", tmp_path)

    resp = payload["response"]
    assert "body" not in resp
    assert resp["size"] == len(blob)
    assert resp["spill_reason"] == "binary"
    spilled = Path(resp["body_path"])
    assert spilled.parent == tmp_path
    assert spilled.read_bytes() == blob
    # An empty request body stays inline and honest rather than spilling.
    assert payload["request"]["body"] == ""
    assert payload["request"]["size"] == 0


def test_flow_get_spills_a_binary_request_body_too(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A binary request body is retrievable, not silently corrupted, on the request side.

    Measured: a protobuf-ish request body -> request.body_path holds the exact
    bytes, request.spill_reason binary, and the request and response spills land
    in distinct files.
    """
    sent = bytes([0x08, 0x96, 0x01, 0x00, 0xFF, 0xFE, 0xFD])
    request = SimpleNamespace(
        method="POST",
        pretty_url="http://x/rpc",
        headers={"content-type": "application/x-protobuf"},
        raw_content=sent,
    )
    response = SimpleNamespace(
        status_code=200,
        headers={"content-type": "application/octet-stream"},
        raw_content=b"\x00\x01\x02\x80\x81",
    )
    backend = _backend_with_flow(monkeypatch, SimpleNamespace(request=request, response=response))

    payload = backend.flow_get("s", "f3", tmp_path)

    req = payload["request"]
    assert "body" not in req
    assert req["spill_reason"] == "binary"
    assert Path(req["body_path"]).read_bytes() == sent
    resp = payload["response"]
    assert resp["spill_reason"] == "binary"
    assert Path(req["body_path"]) != Path(resp["body_path"])


def test_flow_get_discloses_the_error_of_a_flow_that_never_got_a_response(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """proxy.flows marks an errored flow (error/error_msg, null status); the
    detail view dropped it, so a failed flow read as a blank reply. Pin that
    flow_get now carries the same fields, extracted the way the capture does.
    """
    request = SimpleNamespace(
        method="GET",
        pretty_url="https://blocked.example/x",
        headers={"accept": "*/*"},
    )
    flow = SimpleNamespace(
        request=request,
        response=None,
        error=SimpleNamespace(msg="net::ERR_CONNECTION_REFUSED"),
    )
    backend = _backend_with_flow(monkeypatch, flow)

    payload = backend.flow_get("s", "e1", tmp_path)

    assert payload["error"] is True
    assert payload["error_msg"] == "net::ERR_CONNECTION_REFUSED"
    # A response-less flow reports a null status and an empty body, not a fake
    # one, and the error is what says why.
    assert payload["response"]["status"] is None
    assert payload["response"]["body"] == ""


def test_flow_get_falls_back_and_bounds_the_error_message(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """No message falls back to a constant; an oversized one is bounded and
    flagged, matching the capture hook."""
    request = SimpleNamespace(method="GET", pretty_url="https://x/y", headers={})
    errored = SimpleNamespace(request=request, response=None, error=SimpleNamespace(msg=None))
    no_msg = _backend_with_flow(monkeypatch, errored)
    payload = no_msg.flow_get("s", "e2", tmp_path)
    assert payload["error"] is True
    assert payload["error_msg"] == "flow error"

    big = _backend_with_flow(
        monkeypatch,
        SimpleNamespace(
            request=request,
            response=None,
            error=SimpleNamespace(msg="é" * (_MAX_METADATA_BYTES + 1)),
        ),
    )
    payload = big.flow_get("s", "e3", tmp_path)
    assert len(str(payload["error_msg"]).encode()) <= _MAX_METADATA_BYTES
    assert payload["metadata_truncated"] is True


def test_flow_get_of_a_completed_flow_carries_no_error_field(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A flow that got a response must not sprout an error field."""
    request = SimpleNamespace(method="GET", pretty_url="http://x/ok", headers={})
    response = SimpleNamespace(status_code=204, headers={}, raw_content=b"")
    backend = _backend_with_flow(
        monkeypatch, SimpleNamespace(request=request, response=response, error=None)
    )
    payload = backend.flow_get("s", "ok", tmp_path)
    assert "error" not in payload
    assert "error_msg" not in payload
    assert payload["response"]["status"] == 204


def test_service_registers_a_spilled_flow_body_under_its_part(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A spilled body must become a reclaimable, re-openable artifact.

    Measured: a response body spilled by the backend -> the service records it
    and hangs artifact_id off response (not the top level), so a request body
    and a response body could never overwrite one another's id, and the file is
    describable through artifacts.describe.
    """
    root = tmp_path / "artifacts"
    service = AnalysisService(replace(Settings.load(), artifact_root=root))
    try:
        created = service.create_session("https://example.com/app", target="web")
        assert created.data is not None
        session_id = created.data["session"]["id"]
        blob = bytes(range(256))

        def fake_flow_get(sid: str, fid: str, artifact_dir: Path) -> dict[str, Any]:
            artifact_dir.mkdir(parents=True, exist_ok=True)
            dest = artifact_dir / "flow-fixed.bin"
            dest.write_bytes(blob)
            return {
                "id": fid,
                "request": {
                    "method": "GET",
                    "url": "http://x/i",
                    "headers": {},
                    "size": 0,
                    "body": "",
                },
                "response": {
                    "status": 200,
                    "headers": {},
                    "size": len(blob),
                    "body_path": str(dest),
                    "spill_reason": "binary",
                },
            }

        monkeypatch.setattr(service._proxy_backend, "flow_get", fake_flow_get)
        result = service.proxy_flow_get(session_id, "f1")
        assert result.ok, result.error
        assert result.data is not None
        data = result.data
        assert "artifact_id" not in data
        assert "artifact_id" not in data["request"]
        artifact_id = data["response"]["artifact_id"]
        described = service.artifacts_describe(artifact_id)
        assert described.ok, described.error
    finally:
        service.close_all()
