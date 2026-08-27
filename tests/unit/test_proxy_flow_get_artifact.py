"""proxy.flow_get must register each spilled body and degrade, not crash, on failure.

``ProxyBackend.flow_get`` can spill a request and/or a response body to disk and
hand back their paths. The *service* wiring around it (never touched by the
backend tests) is what makes those bodies usable and safe:

* each spilled body is registered as its own artifact under a distinct kind, so
  a request body and a response body never overwrite one another's id and each
  is re-openable and reclaimable like every other capture;
* registration must never fail the read -- the body file exists either way -- so
  a registration failure travels back on that part as ``artifact_error`` while
  the flow data still returns ``ok``. That degradation branch is the one this
  pins, since a bare unregistered path is a dead end but a crashed flow_get is
  worse.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

JsonObject = dict[str, Any]


def _write_minimal_pe(path: Path) -> None:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = (0x8664).to_bytes(2, "little")
    path.write_bytes(image)


class _FakeProxy:
    """Stand-in for the one call proxy_flow_get makes.

    It writes real (small) body files into the artifact dir the service chose,
    so the service's own registration -- hash, size, record -- runs against
    genuine files, which is the wiring under test.
    """

    def __init__(self) -> None:
        self.flow_calls: list[tuple[str, str]] = []

    def flow_get(self, session_id: str, flow_id: str, artifact_dir: Path) -> JsonObject:
        self.flow_calls.append((session_id, flow_id))
        artifact_dir.mkdir(parents=True, exist_ok=True)
        req_body = artifact_dir / f"{flow_id}-req.bin"
        req_body.write_bytes(b"POST body bytes")
        resp_body = artifact_dir / f"{flow_id}-resp.bin"
        resp_body.write_bytes(b"response body bytes")
        return {
            "id": flow_id,
            "request": {
                "method": "POST",
                "url": "https://example.com/api",
                "headers": {},
                "body_path": str(req_body),
            },
            "response": {
                "status": 200,
                "headers": {},
                "body_path": str(resp_body),
            },
        }

    def close_all(self) -> None:  # close_all() calls this unguarded
        pass


def _open_session(tmp_path: Path) -> tuple[AnalysisService, str, _FakeProxy]:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    fake = _FakeProxy()
    service._proxy_backend = fake  # type: ignore[attr-defined]
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None, created.error
    return service, created.data["session"]["id"], fake


def test_proxy_flow_get_registers_each_body_under_its_own_kind(tmp_path: Path) -> None:
    service, session_id, _fake = _open_session(tmp_path)
    try:
        result = service.proxy_flow_get(session_id, "flow-1")
        assert result.ok is True, result.error
        assert result.data is not None

        request = result.data["request"]
        response = result.data["response"]
        req_id = request.get("artifact_id")
        resp_id = response.get("artifact_id")
        # Each part carries its own registered id (never an error on the happy
        # path), and the two ids are distinct so neither body overwrote the
        # other's registration.
        assert isinstance(req_id, str) and req_id
        assert isinstance(resp_id, str) and resp_id
        assert req_id != resp_id
        assert "artifact_error" not in request
        assert "artifact_error" not in response

        req_art = service.repository.describe_artifact(req_id)
        resp_art = service.repository.describe_artifact(resp_id)
        assert req_art is not None and req_art["kind"] == "proxy_flow_request_body"
        assert resp_art is not None and resp_art["kind"] == "proxy_flow_response_body"
        assert Path(req_art["path"]).is_file()
        assert Path(resp_art["path"]).is_file()
    finally:
        service.close_all()


def test_proxy_flow_get_reports_artifact_error_without_failing_the_read(
    tmp_path: Path,
) -> None:
    """A body that cannot be registered still returns, annotated, not crashed.

    Registration is best-effort: the spilled file exists regardless, so a
    repository that refuses the record must surface as ``artifact_error`` on the
    affected part while the flow itself stays ``ok`` -- losing the ability to
    re-open that one body, never the whole exchange the agent asked for.
    """
    service, session_id, _fake = _open_session(tmp_path)
    try:

        def _boom(**_fields: Any) -> JsonObject:
            raise RuntimeError("artifact registry unavailable")

        service.record_artifact = _boom  # type: ignore[attr-defined]

        result = service.proxy_flow_get(session_id, "flow-2")
        assert result.ok is True, result.error
        assert result.data is not None

        request = result.data["request"]
        response = result.data["response"]
        # Neither part got an id, and each names why -- the read did not raise.
        assert "artifact_id" not in request
        assert "artifact_id" not in response
        assert "artifact registry unavailable" in request["artifact_error"]
        assert "artifact registry unavailable" in response["artifact_error"]
    finally:
        service.close_all()
