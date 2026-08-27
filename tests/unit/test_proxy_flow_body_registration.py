"""proxy.flow.get must register each spilled body as its own readable artifact.

A flow has two sides, and either can spill an oversized/binary body. The
service registers each under a distinct kind (proxy_flow_request_body vs
proxy_flow_response_body) and hangs the artifact id off that part, so a request
body and a response body never overwrite one another's id and each spilled body
is reclaimable and re-openable -- the two-sided twin of the web
network.get/script.source spill registration. That per-part wiring
(service_proxy proxy_flow_get) had no coverage: the backend flow_get is tested
directly, and _register_capture is tested in isolation, but nothing proved the
service hangs a resolvable id off each side.

A fake ProxyBackend spills where the service points it (artifact_root/proxy/
<session_id>) and returns the two-part payload the real backend produces. The
ids are followed through artifacts.describe/read, not merely asserted present:
an id that does not resolve, or one side clobbering the other, is exactly what
this must catch. No mitmproxy needed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

JsonObject = dict[str, Any]

_REQ_BODY = b"POST body: " + bytes(range(256))
_RESP_BODY = b"\x89PNG\r\n\x1a\n" + bytes(range(200))


class _FakeProxy:
    """ProxyBackend stand-in: spills the sides it is told to, binds no port."""

    def __init__(self, *, spill_request: bool = True, spill_response: bool = True) -> None:
        self._spill_request = spill_request
        self._spill_response = spill_response

    def flow_get(self, session_id: str, flow_id: str, artifact_dir: Path) -> JsonObject:
        request: JsonObject = {"method": "POST", "url": "http://x/login", "size": len(_REQ_BODY)}
        response: JsonObject = {"status": 200, "size": len(_RESP_BODY)}
        if self._spill_request:
            path = Path(artifact_dir) / f"req-{flow_id}.bin"
            path.write_bytes(_REQ_BODY)
            request["body_path"] = str(path)
            request["spill_reason"] = "too_large"
        else:
            request["body"] = "small"
        if self._spill_response:
            path = Path(artifact_dir) / f"resp-{flow_id}.bin"
            path.write_bytes(_RESP_BODY)
            response["body_path"] = str(path)
            response["spill_reason"] = "binary"
        else:
            response["body"] = "ok"
        return {"id": flow_id, "request": request, "response": response}

    def close_all(self) -> None:
        return None


def _service(tmp_path: Path) -> AnalysisService:
    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )
    return AnalysisService(settings)


def _web_session(service: AnalysisService) -> str:
    created = service.create_session("https://example.com/app", target="web")
    assert created.ok and created.data is not None, created.error
    return str(created.data["session"]["id"])


def _read_back(service: AnalysisService, artifact_id: str) -> bytes:
    read = service.artifacts_read(artifact_id, limit=4096)
    assert read.ok and read.data is not None, read.error
    return bytes.fromhex(str(read.data["data"]))


def test_both_spilled_bodies_get_distinct_readable_artifacts(tmp_path: Path) -> None:
    service = _service(tmp_path)
    try:
        session_id = _web_session(service)
        service._proxy_backend = _FakeProxy()  # type: ignore[assignment]

        result = service.proxy_flow_get(session_id, "f1")

        assert result.ok and result.data is not None, result.error
        req = result.data["request"]
        resp = result.data["response"]
        req_id = req.get("artifact_id")
        resp_id = resp.get("artifact_id")
        assert isinstance(req_id, str) and req_id, "request body must carry an artifact id"
        assert isinstance(resp_id, str) and resp_id, "response body must carry an artifact id"
        assert req_id != resp_id, "the two sides must not share (or overwrite) one id"

        req_art = service.artifacts_describe(req_id)
        resp_art = service.artifacts_describe(resp_id)
        assert req_art.ok and req_art.data is not None, req_art.error
        assert resp_art.ok and resp_art.data is not None, resp_art.error
        assert req_art.data["artifact"]["kind"] == "proxy_flow_request_body"
        assert resp_art.data["artifact"]["kind"] == "proxy_flow_response_body"
        assert req_art.data["artifact"]["source"] == "proxy.flow.get"

        # The bytes round-trip, and the sides are not swapped.
        assert _read_back(service, req_id) == _REQ_BODY
        assert _read_back(service, resp_id) == _RESP_BODY
    finally:
        service.close_all()


def test_only_the_spilled_side_is_registered(tmp_path: Path) -> None:
    """An inline side carries no body_path, so it must not gain an artifact id;
    registering it would mint an id for a file that does not exist."""
    service = _service(tmp_path)
    try:
        session_id = _web_session(service)
        service._proxy_backend = _FakeProxy(spill_request=False)  # type: ignore[assignment]

        result = service.proxy_flow_get(session_id, "f1")

        assert result.ok and result.data is not None, result.error
        assert "artifact_id" not in result.data["request"]
        assert result.data["request"]["body"] == "small"
        assert isinstance(result.data["response"].get("artifact_id"), str)
    finally:
        service.close_all()
