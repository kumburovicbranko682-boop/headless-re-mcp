"""Path coverage for the proxy service mixin (``core/service_proxy``).

Backend-level proxy tests exercise ``ProxyBackend`` directly, and one service
test pins the spilled-body artifact wiring. Left uncovered were the mixin's own
success and failure envelopes: ``proxy_start``'s happy path and its
start-then-refuse-if-the-session-closed rollback, the ``proxy_stop`` and
``_proxy_wrap`` error arcs, ``proxy_flow_get``'s non-dict-part skip and its
artifact_error branch, ``proxy_export_har`` publishing and its ProxyError arc,
and every guard of ``proxy_ca_install_android`` (state closed, missing CA, and
the post-push state re-check). These drive them on a real ``AnalysisService``
with a web session and a faked proxy/adb backend.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import headless_re_mcp.core.service_ext as service_ext
from headless_re_mcp.backends.adb import AdbError
from headless_re_mcp.backends.proxy import ProxyError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import SessionState
from headless_re_mcp.core.service import AnalysisService


def _service_with_web_session(tmp_path: Path) -> tuple[AnalysisService, str]:
    service = AnalysisService(replace(Settings.load(), artifact_root=tmp_path / "artifacts"))
    created = service.create_session("https://example.com/app", target="web")
    assert created.data is not None
    return service, created.data["session"]["id"]


def test_proxy_start_records_backend_and_timeline_on_success(
    tmp_path: Path, monkeypatch: Any
) -> None:
    service, session_id = _service_with_web_session(tmp_path)
    try:
        def fake_start(sid: str, *, host: str, port: int) -> dict[str, Any]:
            return {
                "running": True,
                "host": host,
                "port": port,
                "endpoint": f"http://{host}:{port}",
            }

        monkeypatch.setattr(service._proxy_backend, "start", fake_start)
        result = service.proxy_start(session_id, port=9091)
        assert result.ok, result.error
        assert result.data is not None
        assert result.data["endpoint"] == "http://127.0.0.1:9091"
    finally:
        service.close_all()


def test_proxy_start_rolls_back_when_the_session_closes_mid_start(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A session that closes between start and its re-check must be stopped.

    The proxy has bound a port by then; the rollback stops it and the call
    reports the invalid state rather than leaving an orphaned listener.
    """
    service, session_id = _service_with_web_session(tmp_path)
    try:
        stopped: list[str] = []

        def closing_start(sid: str, *, host: str, port: int) -> dict[str, Any]:
            service.registry.transition(sid, SessionState.FAILED)
            return {"running": True, "endpoint": f"http://{host}:{port}"}

        monkeypatch.setattr(service._proxy_backend, "start", closing_start)
        monkeypatch.setattr(
            service._proxy_backend, "stop", lambda sid: stopped.append(sid)
        )
        result = service.proxy_start(session_id)
        assert result.ok is False
        assert stopped == [session_id]
    finally:
        service.close_all()


def test_proxy_start_maps_a_proxy_error(tmp_path: Path, monkeypatch: Any) -> None:
    service, session_id = _service_with_web_session(tmp_path)
    try:
        def boom(sid: str, *, host: str, port: int) -> dict[str, Any]:
            raise ProxyError("bind_failed", "port already bound")

        monkeypatch.setattr(service._proxy_backend, "start", boom)
        result = service.proxy_start(session_id)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "bind_failed"
    finally:
        service.close_all()


def test_proxy_stop_maps_proxy_error_and_generic_error(
    tmp_path: Path, monkeypatch: Any
) -> None:
    service, session_id = _service_with_web_session(tmp_path)
    try:
        monkeypatch.setattr(
            service._proxy_backend,
            "stop",
            lambda sid: (_ for _ in ()).throw(ProxyError("not_running", "no proxy")),
        )
        mapped = service.proxy_stop(session_id)
        assert mapped.ok is False
        assert mapped.error is not None
        assert mapped.error.code == "not_running"

        monkeypatch.setattr(
            service._proxy_backend,
            "stop",
            lambda sid: (_ for _ in ()).throw(RuntimeError("kaboom")),
        )
        generic = service.proxy_stop(session_id)
        assert generic.ok is False
    finally:
        service.close_all()


def test_proxy_wrap_maps_a_generic_backend_error(
    tmp_path: Path, monkeypatch: Any
) -> None:
    service, session_id = _service_with_web_session(tmp_path)
    try:
        monkeypatch.setattr(
            service._proxy_backend,
            "status",
            lambda sid: (_ for _ in ()).throw(RuntimeError("status blew up")),
        )
        result = service.proxy_status(session_id)
        assert result.ok is False
    finally:
        service.close_all()


def test_proxy_flow_get_skips_non_dict_parts_and_unregisterable_bodies(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A non-dict part is skipped, and a body whose file is gone stays unregistered."""
    service, session_id = _service_with_web_session(tmp_path)
    try:
        def fake_flow_get(sid: str, fid: str, artifact_dir: Path) -> dict[str, Any]:
            missing = artifact_dir / "not-written.bin"
            return {
                "id": fid,
                "request": {"method": "GET", "body_path": str(missing)},
                "response": None,
            }

        monkeypatch.setattr(service._proxy_backend, "flow_get", fake_flow_get)
        result = service.proxy_flow_get(session_id, "f1")
        assert result.ok, result.error
        assert result.data is not None
        assert "artifact_id" not in result.data["request"]
        assert "artifact_error" not in result.data["request"]
    finally:
        service.close_all()


def test_proxy_flow_get_reports_an_artifact_registration_error(
    tmp_path: Path, monkeypatch: Any
) -> None:
    service, session_id = _service_with_web_session(tmp_path)
    try:
        def fake_flow_get(sid: str, fid: str, artifact_dir: Path) -> dict[str, Any]:
            artifact_dir.mkdir(parents=True, exist_ok=True)
            body = artifact_dir / "body.bin"
            body.write_bytes(b"payload")
            return {"id": fid, "request": {"body_path": str(body)}, "response": {}}

        def broken_record(*args: Any, **kwargs: Any) -> dict[str, Any]:
            raise RuntimeError("repository offline")

        monkeypatch.setattr(service._proxy_backend, "flow_get", fake_flow_get)
        monkeypatch.setattr(service_ext, "_record_artifact", broken_record)
        result = service.proxy_flow_get(session_id, "f2")
        assert result.ok, result.error
        assert result.data is not None
        assert "repository offline" in result.data["request"]["artifact_error"]
    finally:
        service.close_all()


def test_proxy_flow_get_maps_a_proxy_error(tmp_path: Path, monkeypatch: Any) -> None:
    service, session_id = _service_with_web_session(tmp_path)
    try:
        monkeypatch.setattr(
            service._proxy_backend,
            "flow_get",
            lambda sid, fid, adir: (_ for _ in ()).throw(ProxyError("no_flow", "gone")),
        )
        result = service.proxy_flow_get(session_id, "missing")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "no_flow"
    finally:
        service.close_all()


def test_proxy_export_har_publishes_and_maps_errors(
    tmp_path: Path, monkeypatch: Any
) -> None:
    service, session_id = _service_with_web_session(tmp_path)
    try:
        def fake_export(sid: str, out: Path) -> dict[str, Any]:
            out.write_text("{}", encoding="utf-8")
            return {"flows": 3}

        monkeypatch.setattr(service._proxy_backend, "export_har", fake_export)
        ok = service.proxy_export_har(session_id)
        assert ok.ok, ok.error
        assert ok.data is not None
        assert "artifact_id" in ok.data

        monkeypatch.setattr(
            service._proxy_backend,
            "export_har",
            lambda sid, out: (_ for _ in ()).throw(ProxyError("empty", "nothing captured")),
        )
        failed = service.proxy_export_har(session_id)
        assert failed.ok is False
        assert failed.error is not None
        assert failed.error.code == "empty"
    finally:
        service.close_all()


def test_proxy_ca_install_refuses_a_closed_session(tmp_path: Path) -> None:
    service, session_id = _service_with_web_session(tmp_path)
    try:
        service.registry.transition(session_id, SessionState.FAILED)
        result = service.proxy_ca_install_android(session_id, "emulator-5554")
        assert result.ok is False
    finally:
        service.close_all()


def test_proxy_ca_install_reports_a_missing_ca(
    tmp_path: Path, monkeypatch: Any
) -> None:
    service, session_id = _service_with_web_session(tmp_path)
    try:
        monkeypatch.setattr(service._proxy_backend, "ca_cert_path", lambda: None)
        result = service.proxy_ca_install_android(session_id, "emulator-5554")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "not_found"
    finally:
        service.close_all()


def test_proxy_ca_install_rechecks_state_after_the_push(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The push can take a while; a session that closed meanwhile is refused."""
    service, session_id = _service_with_web_session(tmp_path)
    try:
        cert = tmp_path / "mitmproxy-ca-cert.pem"
        cert.write_bytes(b"-----BEGIN CERTIFICATE-----")
        monkeypatch.setattr(service._proxy_backend, "ca_cert_path", lambda: cert)

        class _Adb:
            def push(self, serial: str, src: str, dst: str) -> None:
                service.registry.transition(session_id, SessionState.FAILED)

        monkeypatch.setattr(service, "_adb_backend", _Adb(), raising=False)
        result = service.proxy_ca_install_android(session_id, "emulator-5554")
        assert result.ok is False
    finally:
        service.close_all()


def test_proxy_ca_install_maps_an_adb_error(tmp_path: Path, monkeypatch: Any) -> None:
    service, session_id = _service_with_web_session(tmp_path)
    try:
        cert = tmp_path / "mitmproxy-ca-cert.pem"
        cert.write_bytes(b"-----BEGIN CERTIFICATE-----")
        monkeypatch.setattr(service._proxy_backend, "ca_cert_path", lambda: cert)

        class _Adb:
            def push(self, serial: str, src: str, dst: str) -> None:
                raise AdbError("device_offline", "no device")

        monkeypatch.setattr(service, "_adb_backend", _Adb(), raising=False)
        result = service.proxy_ca_install_android(session_id, "emulator-5554")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "device_offline"
    finally:
        service.close_all()
