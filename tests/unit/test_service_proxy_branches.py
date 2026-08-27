"""Branch coverage for the proxy service mixin (ProxyAnalysisMixin).

The mixin wraps the mitmproxy backend for the tool surface: it maps ProxyError
and AdbError into the canonical failure envelope, refuses proxy work against a
closing/closed/failed session (including a race where the session closes while
the proxy is coming up), registers spilled flow bodies and the HAR as
reclaimable artifacts, and pushes the CA to a device best-effort. These drive
those honesty branches against a real AnalysisService with a fake backend, so
no socket is bound and no device is required.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb import AdbError
from headless_re_mcp.backends.proxy import ProxyError
from headless_re_mcp.config import Settings
from headless_re_mcp.core import service_proxy
from headless_re_mcp.core.models import SessionState
from headless_re_mcp.core.service import AnalysisService

MP = pytest.MonkeyPatch


@pytest.fixture
def service(tmp_path: Path) -> Iterator[AnalysisService]:
    svc = AnalysisService(replace(Settings.load(), artifact_root=tmp_path / "artifacts"))
    try:
        yield svc
    finally:
        svc.close_all()


def _new_session(service: AnalysisService) -> str:
    created = service.create_session("https://example.com/app", target="web")
    assert created.data is not None
    return str(created.data["session"]["id"])


def _force_state(service: AnalysisService, session_id: str, state: SessionState) -> None:
    service.registry._sessions[session_id].state = state


class TestProxyStart:
    def test_start_records_backend_and_returns_endpoint(
        self, service: AnalysisService, monkeypatch: MP
    ) -> None:
        sid = _new_session(service)
        monkeypatch.setattr(
            service._proxy_backend,
            "start",
            lambda session_id, host="127.0.0.1", port=8080: {
                "running": True,
                "host": host,
                "port": port,
                "endpoint": f"{host}:{port}",
            },
        )
        result = service.proxy_start(sid, port=9090)
        assert result.ok, result.error
        assert result.data is not None
        assert result.data["endpoint"] == "127.0.0.1:9090"
        assert result.meta.get("backend") == "proxy"

    def test_start_refuses_a_closed_session(
        self, service: AnalysisService, monkeypatch: MP
    ) -> None:
        sid = _new_session(service)
        _force_state(service, sid, SessionState.CLOSED)
        started: list[str] = []
        monkeypatch.setattr(
            service._proxy_backend, "start", lambda *a, **k: started.append("started")
        )
        result = service.proxy_start(sid)
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "invalid_request"
        assert started == []  # never reached the backend

    def test_start_stops_the_proxy_when_the_session_closes_mid_launch(
        self, service: AnalysisService, monkeypatch: MP
    ) -> None:
        sid = _new_session(service)
        stops: list[str] = []

        def _start(session_id: str, host: str = "127.0.0.1", port: int = 8080) -> dict[str, Any]:
            _force_state(service, sid, SessionState.CLOSED)  # closed underneath us
            return {"endpoint": f"{host}:{port}"}

        monkeypatch.setattr(service._proxy_backend, "start", _start)
        monkeypatch.setattr(service._proxy_backend, "stop", lambda sid: stops.append(sid))
        result = service.proxy_start(sid)
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "invalid_request"
        assert stops == [sid]  # the just-started proxy was torn back down

    def test_start_maps_a_proxy_error(self, service: AnalysisService, monkeypatch: MP) -> None:
        sid = _new_session(service)

        def _boom(*_a: object, **_k: object) -> None:
            raise ProxyError("backend_error", "mitmproxy failed to start")

        monkeypatch.setattr(service._proxy_backend, "start", _boom)
        result = service.proxy_start(sid)
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "backend_error"


class TestProxyStopStatusFlows:
    def test_stop_returns_the_backend_payload(
        self, service: AnalysisService, monkeypatch: MP
    ) -> None:
        sid = _new_session(service)
        monkeypatch.setattr(service._proxy_backend, "stop", lambda sid: {"stopped": True})
        result = service.proxy_stop(sid)
        assert result.ok, result.error
        assert result.data == {"stopped": True}

    def test_stop_maps_a_proxy_error(self, service: AnalysisService, monkeypatch: MP) -> None:
        sid = _new_session(service)

        def _boom(_sid: str) -> None:
            raise ProxyError("invalid_state", "already gone")

        monkeypatch.setattr(service._proxy_backend, "stop", _boom)
        result = service.proxy_stop(sid)
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "invalid_state"

    def test_stop_maps_a_generic_failure(
        self, service: AnalysisService, monkeypatch: MP
    ) -> None:
        sid = _new_session(service)

        def _boom(_sid: str) -> None:
            raise RuntimeError("unexpected stop failure")

        monkeypatch.setattr(service._proxy_backend, "stop", _boom)
        result = service.proxy_stop(sid)
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "internal_error"

    def test_status_flows_go_through_the_wrap(
        self, service: AnalysisService, monkeypatch: MP
    ) -> None:
        sid = _new_session(service)
        monkeypatch.setattr(service._proxy_backend, "status", lambda sid: {"running": False})
        monkeypatch.setattr(
            service._proxy_backend,
            "flows",
            lambda sid, offset=0, limit=100: {"flows": [], "total": 0, "offset": offset},
        )
        assert service.proxy_status(sid).data == {"running": False}
        flows = service.proxy_flows(sid, offset=3, limit=10)
        assert flows.ok, flows.error
        assert flows.data is not None
        assert flows.data["offset"] == 3

    def test_wrap_maps_proxy_error_and_generic(
        self, service: AnalysisService, monkeypatch: MP
    ) -> None:
        sid = _new_session(service)

        def _proxy_err(_sid: str) -> None:
            raise ProxyError("invalid_state", "no proxy running")

        monkeypatch.setattr(service._proxy_backend, "status", _proxy_err)
        mapped = service.proxy_status(sid)
        assert not mapped.ok
        assert mapped.error is not None
        assert mapped.error.code == "invalid_state"

        def _generic(_sid: str) -> None:
            raise RuntimeError("unexpected boom")

        monkeypatch.setattr(service._proxy_backend, "status", _generic)
        internal = service.proxy_status(sid)
        assert not internal.ok
        assert internal.error is not None
        assert internal.error.code == "internal_error"

    def test_replay_goes_through_the_wrap(
        self, service: AnalysisService, monkeypatch: MP
    ) -> None:
        sid = _new_session(service)
        monkeypatch.setattr(
            service._proxy_backend,
            "replay",
            lambda sid, flow_id: {"replayed": True, "flow_id": flow_id},
        )
        result = service.proxy_replay(sid, "f1")
        assert result.ok, result.error
        assert result.data == {"replayed": True, "flow_id": "f1"}


class TestProxyFlowGet:
    def test_flow_get_registers_a_spilled_response_body(
        self, service: AnalysisService, monkeypatch: MP
    ) -> None:
        sid = _new_session(service)

        def _flow_get(session_id: str, flow_id: str, artifact_dir: Path) -> dict[str, Any]:
            artifact_dir.mkdir(parents=True, exist_ok=True)
            dest = artifact_dir / "body.bin"
            dest.write_bytes(bytes(range(64)))
            return {
                "id": flow_id,
                # A non-dict part must be skipped without blowing up.
                "request": None,
                "response": {
                    "status": 200,
                    "headers": {},
                    "size": 64,
                    "body_path": str(dest),
                    "spill_reason": "binary",
                },
            }

        monkeypatch.setattr(service._proxy_backend, "flow_get", _flow_get)
        result = service.proxy_flow_get(sid, "f1")
        assert result.ok, result.error
        assert result.data is not None
        assert "artifact_id" in result.data["response"]

    def test_flow_get_skips_a_part_without_a_body_path(
        self, service: AnalysisService, monkeypatch: MP
    ) -> None:
        sid = _new_session(service)

        def _flow_get(session_id: str, flow_id: str, artifact_dir: Path) -> dict[str, Any]:
            return {
                "id": flow_id,
                "request": {"method": "GET", "url": "http://x", "headers": {}, "body": ""},
                "response": {"status": 200, "headers": {}, "body": "ok"},
            }

        monkeypatch.setattr(service._proxy_backend, "flow_get", _flow_get)
        result = service.proxy_flow_get(sid, "f1")
        assert result.ok, result.error
        assert result.data is not None
        assert "artifact_id" not in result.data["request"]
        assert "artifact_id" not in result.data["response"]

    def test_flow_get_reports_a_registration_failure_in_the_part(
        self, service: AnalysisService, monkeypatch: MP
    ) -> None:
        sid = _new_session(service)

        def _flow_get(session_id: str, flow_id: str, artifact_dir: Path) -> dict[str, Any]:
            artifact_dir.mkdir(parents=True, exist_ok=True)
            dest = artifact_dir / "body.bin"
            dest.write_bytes(b"data")
            return {
                "id": flow_id,
                "request": {"method": "GET", "url": "http://x", "headers": {}, "body": ""},
                "response": {"status": 200, "headers": {}, "body_path": str(dest)},
            }

        monkeypatch.setattr(service._proxy_backend, "flow_get", _flow_get)
        monkeypatch.setattr(
            service_proxy,
            "_register_capture",
            lambda *a, **k: {"artifact_error": "store unavailable"},
        )
        result = service.proxy_flow_get(sid, "f1")
        assert result.ok, result.error
        assert result.data is not None
        assert result.data["response"]["artifact_error"] == "store unavailable"

    def test_flow_get_skips_a_body_path_that_no_longer_exists(
        self, service: AnalysisService, monkeypatch: MP, tmp_path: Path
    ) -> None:
        sid = _new_session(service)
        missing = tmp_path / "not-written.bin"

        def _flow_get(session_id: str, flow_id: str, artifact_dir: Path) -> dict[str, Any]:
            return {
                "id": flow_id,
                "request": {"method": "GET", "url": "http://x", "headers": {}, "body": ""},
                "response": {"status": 200, "headers": {}, "body_path": str(missing)},
            }

        monkeypatch.setattr(service._proxy_backend, "flow_get", _flow_get)
        result = service.proxy_flow_get(sid, "f1")
        assert result.ok, result.error
        assert result.data is not None
        # The file is gone, so registration is a no-op: neither key appears.
        assert "artifact_id" not in result.data["response"]
        assert "artifact_error" not in result.data["response"]

    def test_flow_get_rejects_an_unsafe_session_id(self, service: AnalysisService) -> None:
        result = service.proxy_flow_get("../../etc", "f1")
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "invalid_params"

    def test_flow_get_maps_a_proxy_error(
        self, service: AnalysisService, monkeypatch: MP
    ) -> None:
        sid = _new_session(service)

        def _boom(*_a: object, **_k: object) -> None:
            raise ProxyError("not_found", "unknown flow id")

        monkeypatch.setattr(service._proxy_backend, "flow_get", _boom)
        result = service.proxy_flow_get(sid, "gone")
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "not_found"

    def test_flow_get_maps_a_generic_failure(
        self, service: AnalysisService, monkeypatch: MP
    ) -> None:
        sid = _new_session(service)

        def _boom(*_a: object, **_k: object) -> None:
            raise RuntimeError("reader blew up")

        monkeypatch.setattr(service._proxy_backend, "flow_get", _boom)
        result = service.proxy_flow_get(sid, "f1")
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "internal_error"


class TestProxyExportHar:
    def test_export_har_registers_the_artifact(
        self, service: AnalysisService, monkeypatch: MP
    ) -> None:
        sid = _new_session(service)

        def _export(session_id: str, out_path: Path) -> dict[str, Any]:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text("{}", encoding="utf-8")
            return {"path": str(out_path), "entry_count": 0, "size": 2}

        monkeypatch.setattr(service._proxy_backend, "export_har", _export)
        result = service.proxy_export_har(sid)
        assert result.ok, result.error
        assert result.data is not None
        assert "artifact_id" in result.data

    def test_export_har_maps_a_proxy_error(
        self, service: AnalysisService, monkeypatch: MP
    ) -> None:
        sid = _new_session(service)

        def _boom(*_a: object, **_k: object) -> None:
            raise ProxyError("too_large", "HAR export exceeds capture cap")

        monkeypatch.setattr(service._proxy_backend, "export_har", _boom)
        result = service.proxy_export_har(sid)
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "too_large"

    def test_export_har_maps_a_generic_failure(
        self, service: AnalysisService, monkeypatch: MP
    ) -> None:
        sid = _new_session(service)

        def _boom(*_a: object, **_k: object) -> None:
            raise RuntimeError("serialize blew up")

        monkeypatch.setattr(service._proxy_backend, "export_har", _boom)
        result = service.proxy_export_har(sid)
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "internal_error"


class _FakeAdb:
    def __init__(self) -> None:
        self.pushed: list[tuple[str, str, str]] = []
        self.error: BaseException | None = None
        self.on_push: Any = None

    def push(self, serial: str, local: str, remote: str) -> dict[str, Any]:
        if self.on_push is not None:
            self.on_push()
        if self.error is not None:
            raise self.error
        self.pushed.append((serial, local, remote))
        return {"pushed": True}


class TestProxyCaInstall:
    def test_ca_install_pushes_the_cert(
        self, service: AnalysisService, monkeypatch: MP, tmp_path: Path
    ) -> None:
        sid = _new_session(service)
        cert = tmp_path / "mitmproxy-ca-cert.pem"
        cert.write_text("CERT")
        monkeypatch.setattr(service._proxy_backend, "ca_cert_path", lambda: cert)
        fake = _FakeAdb()
        service._adb_backend = fake  # type: ignore[attr-defined]
        result = service.proxy_ca_install_android(sid, "emulator-5554")
        assert result.ok, result.error
        assert result.data is not None
        assert result.data["pushed_to"].endswith("mitmproxy-ca-cert.pem")
        assert fake.pushed and fake.pushed[0][0] == "emulator-5554"

    def test_ca_install_refuses_a_closed_session(
        self, service: AnalysisService, monkeypatch: MP
    ) -> None:
        sid = _new_session(service)
        _force_state(service, sid, SessionState.FAILED)
        result = service.proxy_ca_install_android(sid, "emulator-5554")
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "invalid_request"

    def test_ca_install_is_not_found_without_a_cert(
        self, service: AnalysisService, monkeypatch: MP
    ) -> None:
        sid = _new_session(service)
        monkeypatch.setattr(service._proxy_backend, "ca_cert_path", lambda: None)
        result = service.proxy_ca_install_android(sid, "emulator-5554")
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "not_found"

    def test_ca_install_maps_an_adb_error(
        self, service: AnalysisService, monkeypatch: MP, tmp_path: Path
    ) -> None:
        sid = _new_session(service)
        cert = tmp_path / "mitmproxy-ca-cert.pem"
        cert.write_text("CERT")
        monkeypatch.setattr(service._proxy_backend, "ca_cert_path", lambda: cert)
        fake = _FakeAdb()
        fake.error = AdbError("not_found", "device offline")
        service._adb_backend = fake  # type: ignore[attr-defined]
        result = service.proxy_ca_install_android(sid, "emulator-5554")
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "not_found"

    def test_ca_install_stops_when_the_session_closes_after_push(
        self, service: AnalysisService, monkeypatch: MP, tmp_path: Path
    ) -> None:
        sid = _new_session(service)
        cert = tmp_path / "mitmproxy-ca-cert.pem"
        cert.write_text("CERT")
        monkeypatch.setattr(service._proxy_backend, "ca_cert_path", lambda: cert)
        fake = _FakeAdb()
        fake.on_push = lambda: _force_state(service, sid, SessionState.CLOSED)
        service._adb_backend = fake  # type: ignore[attr-defined]
        result = service.proxy_ca_install_android(sid, "emulator-5554")
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "invalid_request"

    def test_ca_install_maps_a_generic_failure(
        self, service: AnalysisService, monkeypatch: MP
    ) -> None:
        sid = _new_session(service)

        def _boom() -> None:
            raise RuntimeError("cert probe blew up")

        monkeypatch.setattr(service._proxy_backend, "ca_cert_path", _boom)
        result = service.proxy_ca_install_android(sid, "emulator-5554")
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "internal_error"
