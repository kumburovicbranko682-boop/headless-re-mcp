"""ProxyAnalysisMixin state guards and error envelopes.

The proxy backend's own behaviour (flow recording, body spill, port reservation)
is pinned elsewhere. This file drives the service seam: the CLOSING/CLOSED guards
that keep a late call from mutating a dead session, the rollback that stops a
proxy started against a session that closed mid-start, the ProxyError/AdbError to
envelope mapping, and the artifact registration around flow bodies and HAR
exports -- all reached with a fake proxy backend and no mitmproxy.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.adb import AdbError
from headless_re_mcp.backends.proxy import ProxyError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import SessionState
from headless_re_mcp.core.service import AnalysisService


def _service(tmp_path: Path) -> AnalysisService:
    return AnalysisService(replace(Settings.load(), artifact_root=tmp_path / "artifacts"))


def _web_session(service: AnalysisService) -> str:
    created = service.create_session("https://example.com/app", target="web")
    assert created.ok and created.data is not None, created.error
    return str(created.data["session"]["id"])


def _endpoint(session_id: str, host: str = "127.0.0.1", port: int = 8080) -> dict[str, Any]:
    return {"running": True, "host": host, "port": port, "endpoint": f"{host}:{port}"}


# --------------------------------------------------------------------------
# proxy.start
# --------------------------------------------------------------------------
def test_proxy_start_reports_the_endpoint(tmp_path: Path, monkeypatch: Any) -> None:
    service = _service(tmp_path)
    try:
        sid = _web_session(service)
        monkeypatch.setattr(
            service._proxy_backend,
            "start",
            lambda session_id, host="127.0.0.1", port=8080: _endpoint(session_id, host, port),
        )
        result = service.proxy_start(sid)
        assert result.ok, result.error
        assert result.data is not None
        assert result.data["endpoint"] == "127.0.0.1:8080"
    finally:
        service.close_all()


def test_proxy_start_refuses_a_closed_session(tmp_path: Path) -> None:
    service = _service(tmp_path)
    try:
        sid = _web_session(service)
        service.close_session(sid)
        result = service.proxy_start(sid)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
    finally:
        service.close_all()


def test_proxy_start_rolls_back_when_the_session_closes_mid_start(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A close arriving during start must stop the freshly bound proxy.

    Without the post-start re-check the proxy would keep a bound port that
    nothing can stop, because the session it belonged to is already gone. The
    session is moved to CLOSING directly (not via close_session, whose own
    teardown would also call stop) so the recorded stop is the rollback alone.
    """
    service = _service(tmp_path)
    try:
        sid = _web_session(service)
        stopped: list[str] = []

        def fake_start(session_id: str, host: str = "127.0.0.1", port: int = 8080) -> Any:
            service.registry.transition(session_id, SessionState.CLOSING)
            return _endpoint(session_id, host, port)

        def fake_stop(session_id: str) -> dict[str, Any]:
            stopped.append(session_id)
            return {"stopped": True}

        monkeypatch.setattr(service._proxy_backend, "start", fake_start)
        monkeypatch.setattr(service._proxy_backend, "stop", fake_stop)
        result = service.proxy_start(sid)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
        assert stopped == [sid]
    finally:
        service.close_all()


def test_proxy_start_maps_a_proxy_error(tmp_path: Path, monkeypatch: Any) -> None:
    service = _service(tmp_path)
    try:
        sid = _web_session(service)

        def boom(session_id: str, host: str = "127.0.0.1", port: int = 8080) -> Any:
            raise ProxyError("invalid_state", "port already reserved", port=port)

        monkeypatch.setattr(service._proxy_backend, "start", boom)
        result = service.proxy_start(sid)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_state"
    finally:
        service.close_all()


# --------------------------------------------------------------------------
# proxy.stop / proxy_wrap (status / flows / replay)
# --------------------------------------------------------------------------
def test_proxy_stop_reports_success(tmp_path: Path, monkeypatch: Any) -> None:
    service = _service(tmp_path)
    try:
        sid = _web_session(service)
        monkeypatch.setattr(service._proxy_backend, "stop", lambda session_id: {"stopped": True})
        result = service.proxy_stop(sid)
        assert result.ok, result.error
    finally:
        service.close_all()


def test_proxy_stop_maps_a_proxy_error(tmp_path: Path, monkeypatch: Any) -> None:
    service = _service(tmp_path)
    try:
        sid = _web_session(service)

        def boom(session_id: str) -> Any:
            raise ProxyError("backend_error", "stop failed")

        monkeypatch.setattr(service._proxy_backend, "stop", boom)
        result = service.proxy_stop(sid)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "backend_error"
    finally:
        service.close_all()


def test_proxy_stop_maps_a_generic_error(tmp_path: Path, monkeypatch: Any) -> None:
    service = _service(tmp_path)
    try:
        sid = _web_session(service)

        def boom(session_id: str) -> Any:
            raise ValueError("bad state")

        monkeypatch.setattr(service._proxy_backend, "stop", boom)
        result = service.proxy_stop(sid)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
    finally:
        service.close_all()


def test_proxy_status_passes_through(tmp_path: Path, monkeypatch: Any) -> None:
    service = _service(tmp_path)
    try:
        sid = _web_session(service)
        monkeypatch.setattr(
            service._proxy_backend, "status", lambda session_id: {"running": True}
        )
        result = service.proxy_status(sid)
        assert result.ok, result.error
        assert result.data == {"running": True}
    finally:
        service.close_all()


def test_proxy_flows_maps_a_proxy_error(tmp_path: Path, monkeypatch: Any) -> None:
    service = _service(tmp_path)
    try:
        sid = _web_session(service)

        def boom(session_id: str, offset: int = 0, limit: int = 100) -> Any:
            raise ProxyError("not_found", "no proxy for this session")

        monkeypatch.setattr(service._proxy_backend, "flows", boom)
        result = service.proxy_flows(sid)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "not_found"
    finally:
        service.close_all()


def test_proxy_replay_maps_a_generic_error(tmp_path: Path, monkeypatch: Any) -> None:
    service = _service(tmp_path)
    try:
        sid = _web_session(service)

        def boom(session_id: str, flow_id: str) -> Any:
            raise RuntimeError("replay exploded")

        monkeypatch.setattr(service._proxy_backend, "replay", boom)
        result = service.proxy_replay(sid, "f1")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "internal_error"
    finally:
        service.close_all()


# --------------------------------------------------------------------------
# proxy.flow.get
# --------------------------------------------------------------------------
def test_flow_get_skips_a_non_dict_part(tmp_path: Path, monkeypatch: Any) -> None:
    service = _service(tmp_path)
    try:
        sid = _web_session(service)

        def fake_flow_get(session_id: str, flow_id: str, artifact_dir: Path) -> dict[str, Any]:
            artifact_dir.mkdir(parents=True, exist_ok=True)
            dest = artifact_dir / "resp.bin"
            dest.write_bytes(b"\x00\x01\x02")
            return {
                "id": flow_id,
                "request": None,  # a part that is not a dict must be skipped
                "response": {"status": 200, "size": 3, "body_path": str(dest)},
            }

        monkeypatch.setattr(service._proxy_backend, "flow_get", fake_flow_get)
        result = service.proxy_flow_get(sid, "f1")
        assert result.ok, result.error
        assert result.data is not None
        assert result.data["request"] is None
        assert "artifact_id" in result.data["response"]
    finally:
        service.close_all()


def test_flow_get_reports_an_artifact_registration_failure(
    tmp_path: Path, monkeypatch: Any
) -> None:
    service = _service(tmp_path)
    try:
        sid = _web_session(service)

        def fake_flow_get(session_id: str, flow_id: str, artifact_dir: Path) -> dict[str, Any]:
            artifact_dir.mkdir(parents=True, exist_ok=True)
            dest = artifact_dir / "resp.bin"
            dest.write_bytes(b"\x00\x01\x02")
            return {
                "id": flow_id,
                "response": {"status": 200, "size": 3, "body_path": str(dest)},
            }

        def broken_record(*args: Any, **kwargs: Any) -> Any:
            raise RuntimeError("artifact store unavailable")

        monkeypatch.setattr(service._proxy_backend, "flow_get", fake_flow_get)
        monkeypatch.setattr(
            "headless_re_mcp.core.service_ext._record_artifact", broken_record
        )
        result = service.proxy_flow_get(sid, "f1")
        assert result.ok, result.error
        assert result.data is not None
        assert "artifact_error" in result.data["response"]
        assert "artifact_id" not in result.data["response"]
    finally:
        service.close_all()


def test_flow_get_skips_a_part_without_a_body_path(tmp_path: Path, monkeypatch: Any) -> None:
    service = _service(tmp_path)
    try:
        sid = _web_session(service)

        def fake_flow_get(session_id: str, flow_id: str, artifact_dir: Path) -> dict[str, Any]:
            return {
                "id": flow_id,
                # a dict part with no body_path must pass through untouched
                "response": {"status": 204, "size": 0},
            }

        monkeypatch.setattr(service._proxy_backend, "flow_get", fake_flow_get)
        result = service.proxy_flow_get(sid, "f1")
        assert result.ok, result.error
        assert result.data is not None
        assert "artifact_id" not in result.data["response"]
        assert "artifact_error" not in result.data["response"]
    finally:
        service.close_all()


def test_flow_get_leaves_a_part_when_the_body_file_is_missing(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A body_path that names a file that never landed is not an error here.

    _register_capture returns the payload untouched when the path is not a
    file, so neither an artifact id nor an artifact error is hung off the part.
    """
    service = _service(tmp_path)
    try:
        sid = _web_session(service)

        def fake_flow_get(session_id: str, flow_id: str, artifact_dir: Path) -> dict[str, Any]:
            missing = artifact_dir / "never-written.bin"
            return {
                "id": flow_id,
                "response": {"status": 200, "size": 3, "body_path": str(missing)},
            }

        monkeypatch.setattr(service._proxy_backend, "flow_get", fake_flow_get)
        result = service.proxy_flow_get(sid, "f1")
        assert result.ok, result.error
        assert result.data is not None
        assert "artifact_id" not in result.data["response"]
        assert "artifact_error" not in result.data["response"]
    finally:
        service.close_all()


def test_flow_get_rejects_an_unsafe_session_id(tmp_path: Path) -> None:
    """The artifact dir helper refuses a session id that is not a safe segment.

    A traversal-shaped id would otherwise steer the body/HAR files out of the
    session's artifact tree, so it fails before the backend is even called.
    """
    service = _service(tmp_path)
    try:
        result = service.proxy_flow_get("../escape", "f1")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_params"
    finally:
        service.close_all()


def test_flow_get_maps_a_proxy_error(tmp_path: Path, monkeypatch: Any) -> None:
    service = _service(tmp_path)
    try:
        sid = _web_session(service)

        def boom(session_id: str, flow_id: str, artifact_dir: Path) -> Any:
            raise ProxyError("not_found", "no such flow", flow_id=flow_id)

        monkeypatch.setattr(service._proxy_backend, "flow_get", boom)
        result = service.proxy_flow_get(sid, "missing")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "not_found"
    finally:
        service.close_all()


def test_flow_get_maps_a_generic_error(tmp_path: Path, monkeypatch: Any) -> None:
    service = _service(tmp_path)
    try:
        sid = _web_session(service)

        def boom(session_id: str, flow_id: str, artifact_dir: Path) -> Any:
            raise RuntimeError("decode blew up")

        monkeypatch.setattr(service._proxy_backend, "flow_get", boom)
        result = service.proxy_flow_get(sid, "f1")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "internal_error"
    finally:
        service.close_all()


# --------------------------------------------------------------------------
# proxy.export_har
# --------------------------------------------------------------------------
def test_export_har_registers_the_capture(tmp_path: Path, monkeypatch: Any) -> None:
    service = _service(tmp_path)
    try:
        sid = _web_session(service)

        def fake_export(session_id: str, out: Path) -> dict[str, Any]:
            out.write_text('{"log": {}}', encoding="utf-8")
            return {"flows": 3}

        monkeypatch.setattr(service._proxy_backend, "export_har", fake_export)
        result = service.proxy_export_har(sid)
        assert result.ok, result.error
        assert result.data is not None
        assert "artifact_id" in result.data
    finally:
        service.close_all()


def test_export_har_maps_a_proxy_error(tmp_path: Path, monkeypatch: Any) -> None:
    service = _service(tmp_path)
    try:
        sid = _web_session(service)

        def boom(session_id: str, out: Path) -> Any:
            raise ProxyError("backend_error", "no flows to export")

        monkeypatch.setattr(service._proxy_backend, "export_har", boom)
        result = service.proxy_export_har(sid)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "backend_error"
    finally:
        service.close_all()


def test_export_har_maps_a_generic_error(tmp_path: Path, monkeypatch: Any) -> None:
    service = _service(tmp_path)
    try:
        sid = _web_session(service)

        def boom(session_id: str, out: Path) -> Any:
            raise RuntimeError("har writer exploded")

        monkeypatch.setattr(service._proxy_backend, "export_har", boom)
        result = service.proxy_export_har(sid)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "internal_error"
    finally:
        service.close_all()


# --------------------------------------------------------------------------
# proxy.ca.install_android
# --------------------------------------------------------------------------
class _AdbFake:
    def __init__(self, *, on_push: Any = None, raises: BaseException | None = None) -> None:
        self._on_push = on_push
        self._raises = raises
        self.pushed: list[tuple[str, str, str]] = []

    def push(self, serial: str, local: str, remote: str) -> dict[str, Any]:
        if self._raises is not None:
            raise self._raises
        if self._on_push is not None:
            self._on_push()
        self.pushed.append((serial, local, remote))
        return {"size": 1}


def test_ca_install_pushes_the_cert(tmp_path: Path, monkeypatch: Any) -> None:
    service = _service(tmp_path)
    try:
        sid = _web_session(service)
        cert = tmp_path / "mitmproxy-ca-cert.pem"
        cert.write_text("-----BEGIN CERTIFICATE-----\n", encoding="utf-8")
        monkeypatch.setattr(service._proxy_backend, "ca_cert_path", lambda: cert)
        adb = _AdbFake()
        service._adb_backend = adb  # type: ignore[assignment]
        result = service.proxy_ca_install_android(sid, "emulator-5554")
        assert result.ok, result.error
        assert result.data is not None
        assert result.data["pushed_to"].endswith("mitmproxy-ca-cert.pem")
        assert adb.pushed and adb.pushed[0][0] == "emulator-5554"
    finally:
        service.close_all()


def test_ca_install_reports_a_missing_ca(tmp_path: Path, monkeypatch: Any) -> None:
    service = _service(tmp_path)
    try:
        sid = _web_session(service)
        monkeypatch.setattr(service._proxy_backend, "ca_cert_path", lambda: None)
        result = service.proxy_ca_install_android(sid, "emulator-5554")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "not_found"
    finally:
        service.close_all()


def test_ca_install_refuses_a_closed_session(tmp_path: Path) -> None:
    service = _service(tmp_path)
    try:
        sid = _web_session(service)
        service.close_session(sid)
        result = service.proxy_ca_install_android(sid, "emulator-5554")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
    finally:
        service.close_all()


def test_ca_install_refuses_a_session_that_closes_during_push(
    tmp_path: Path, monkeypatch: Any
) -> None:
    service = _service(tmp_path)
    try:
        sid = _web_session(service)
        cert = tmp_path / "mitmproxy-ca-cert.pem"
        cert.write_text("-----BEGIN CERTIFICATE-----\n", encoding="utf-8")
        monkeypatch.setattr(service._proxy_backend, "ca_cert_path", lambda: cert)
        service._adb_backend = _AdbFake(on_push=lambda: service.close_session(sid))  # type: ignore[assignment]
        result = service.proxy_ca_install_android(sid, "emulator-5554")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
    finally:
        service.close_all()


def test_ca_install_maps_an_adb_error(tmp_path: Path, monkeypatch: Any) -> None:
    service = _service(tmp_path)
    try:
        sid = _web_session(service)
        cert = tmp_path / "mitmproxy-ca-cert.pem"
        cert.write_text("-----BEGIN CERTIFICATE-----\n", encoding="utf-8")
        monkeypatch.setattr(service._proxy_backend, "ca_cert_path", lambda: cert)
        service._adb_backend = _AdbFake(raises=AdbError("not_found", "device offline"))  # type: ignore[assignment]
        result = service.proxy_ca_install_android(sid, "emulator-5554")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "not_found"
    finally:
        service.close_all()
