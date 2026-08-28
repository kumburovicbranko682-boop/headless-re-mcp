"""Cover the proxy service arms: start reclaim, stop/flow/har error mapping,
body capture registration, and the Android CA push flow."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.core.service_proxy as sp
from headless_re_mcp.backends.adb import AdbError
from headless_re_mcp.backends.proxy import ProxyError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService


class _FakeProxy:
    def __init__(self) -> None:
        self.started: list[str] = []
        self.stopped: list[str] = []
        self.on_start: Any = None
        self.start_error: BaseException | None = None
        self.stop_error: BaseException | None = None
        self.status_error: BaseException | None = None
        self.flow_get_result: dict[str, Any] = {}
        self.flow_get_error: BaseException | None = None
        self.ca: Path | None = None

    def start(
        self, session_id: str, host: str = "127.0.0.1", port: int = 8080
    ) -> dict[str, Any]:
        if self.start_error is not None:
            raise self.start_error
        self.started.append(session_id)
        if self.on_start is not None:
            self.on_start(session_id)
        return {
            "running": True,
            "host": host,
            "port": port,
            "endpoint": f"{host}:{port}",
        }

    def stop(self, session_id: str) -> dict[str, Any]:
        if self.stop_error is not None:
            raise self.stop_error
        self.stopped.append(session_id)
        return {"stopped": True}

    def status(self, session_id: str) -> dict[str, Any]:
        if self.status_error is not None:
            raise self.status_error
        return {"running": True}

    def flows(self, session_id: str, offset: int = 0, limit: int = 100) -> dict[str, Any]:
        return {"flows": [], "offset": offset, "limit": limit}

    def replay(self, session_id: str, flow_id: str) -> dict[str, Any]:
        return {"replayed": flow_id}

    def flow_get(
        self, session_id: str, flow_id: str, artifact_dir: Path
    ) -> dict[str, Any]:
        if self.flow_get_error is not None:
            raise self.flow_get_error
        return self.flow_get_result

    def export_har(self, session_id: str, out: Path) -> dict[str, Any]:
        Path(out).write_text("[]", encoding="utf-8")
        return {"path": str(out)}

    def ca_cert_path(self) -> Path | None:
        return self.ca

    def close_all(self) -> None:
        pass


class _FakeAdb:
    def __init__(self) -> None:
        self.pushed: list[tuple[str, str, str]] = []
        self.on_push: Any = None
        self.push_error: BaseException | None = None

    def push(self, serial: str, local: str, remote: str) -> None:
        if self.push_error is not None:
            raise self.push_error
        self.pushed.append((serial, local, remote))
        if self.on_push is not None:
            self.on_push()


def _service(tmp_path: Path) -> tuple[AnalysisService, _FakeProxy]:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    proxy = _FakeProxy()
    service._proxy_backend = proxy  # type: ignore[assignment]
    return service, proxy


def _web_session(service: AnalysisService) -> str:
    created = service.create_session("https://example.com/app", target="web")
    assert created.data is not None
    return str(created.data["session"]["id"])


def test_proxy_start_records_backend_and_timeline(tmp_path: Path) -> None:
    service, proxy = _service(tmp_path)
    try:
        session_id = _web_session(service)
        result = service.proxy_start(session_id, port=19080)
        assert result.ok, result.error
        assert result.data is not None
        assert result.data["endpoint"] == "127.0.0.1:19080"
        assert proxy.started == [session_id]
    finally:
        service.close_all()


def test_proxy_start_maps_a_backend_error(tmp_path: Path) -> None:
    service, proxy = _service(tmp_path)
    try:
        session_id = _web_session(service)
        proxy.start_error = ProxyError("unavailable", "mitmproxy missing")
        result = service.proxy_start(session_id)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "unavailable"
    finally:
        service.close_all()


def test_proxy_start_reclaims_a_port_if_the_session_closes_mid_launch(
    tmp_path: Path,
) -> None:
    service, proxy = _service(tmp_path)
    try:
        session_id = _web_session(service)
        proxy.on_start = lambda sid: service.close_session(sid)
        result = service.proxy_start(session_id)
        assert result.ok is False
        # start bound a port, then the re-check tore it back down.
        assert proxy.started == [session_id]
        assert session_id in proxy.stopped
    finally:
        service.close_all()


def test_proxy_stop_maps_backend_and_unexpected_errors(tmp_path: Path) -> None:
    service, proxy = _service(tmp_path)
    try:
        session_id = _web_session(service)
        proxy.stop_error = ProxyError("not_found", "no proxy")
        mapped = service.proxy_stop(session_id)
        assert mapped.ok is False
        assert mapped.error is not None
        assert mapped.error.code == "not_found"

        proxy.stop_error = RuntimeError("kaboom")
        unexpected = service.proxy_stop(session_id)
        assert unexpected.ok is False
    finally:
        service.close_all()


def test_proxy_status_wraps_backend_and_unexpected_errors(tmp_path: Path) -> None:
    service, proxy = _service(tmp_path)
    try:
        session_id = _web_session(service)
        ok = service.proxy_status(session_id)
        assert ok.ok, ok.error

        proxy.status_error = ProxyError("unavailable", "down")
        mapped = service.proxy_status(session_id)
        assert mapped.ok is False
        assert mapped.error is not None
        assert mapped.error.code == "unavailable"

        proxy.status_error = RuntimeError("boom")
        unexpected = service.proxy_status(session_id)
        assert unexpected.ok is False
    finally:
        service.close_all()


def test_proxy_flow_get_registers_request_and_response_bodies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, proxy = _service(tmp_path)
    try:
        session_id = _web_session(service)
        proxy.flow_get_result = {
            "request": {"body_path": "/tmp/req.bin"},
            "response": {"body_path": "/tmp/resp.bin"},
        }

        outcomes: list[dict[str, str]] = [
            {"artifact_id": "art-1"},
            {"artifact_error": "spill lost"},
            {},  # neither id nor error -> body left as-is
            {},
        ]
        pending = iter(outcomes)

        def fake_register(_svc: Any, _sid: str, path: Path, **_kw: Any) -> dict[str, str]:
            return next(pending)

        monkeypatch.setattr(sp, "_register_capture", fake_register)
        first = service.proxy_flow_get(session_id, "flow-7")
        assert first.ok, first.error
        assert first.data is not None
        assert first.data["request"]["artifact_id"] == "art-1"
        assert first.data["response"]["artifact_error"] == "spill lost"

        # A registration that reports neither key leaves the body untouched.
        proxy.flow_get_result = {
            "request": {"body_path": "/tmp/a.bin"},
            "response": {"body_path": "/tmp/b.bin"},
        }
        second = service.proxy_flow_get(session_id, "flow-8")
        assert second.ok, second.error
        assert second.data is not None
        assert "artifact_id" not in second.data["request"]
        assert "artifact_error" not in second.data["request"]
    finally:
        service.close_all()


def test_proxy_flow_get_skips_non_dict_and_bodyless_parts(tmp_path: Path) -> None:
    service, proxy = _service(tmp_path)
    try:
        session_id = _web_session(service)
        proxy.flow_get_result = {
            "request": "not-a-dict",
            "response": {"headers": {}},
        }
        result = service.proxy_flow_get(session_id, "flow-8")
        assert result.ok, result.error
        assert result.data is not None
        assert "artifact_id" not in result.data["response"]
    finally:
        service.close_all()


def test_proxy_flow_get_maps_a_backend_error(tmp_path: Path) -> None:
    service, proxy = _service(tmp_path)
    try:
        session_id = _web_session(service)
        proxy.flow_get_error = ProxyError("not_found", "no such flow")
        result = service.proxy_flow_get(session_id, "missing")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "not_found"
    finally:
        service.close_all()


def test_proxy_export_har_registers_the_capture(tmp_path: Path) -> None:
    service, _proxy = _service(tmp_path)
    try:
        session_id = _web_session(service)
        result = service.proxy_export_har(session_id)
        assert result.ok, result.error
        assert result.data is not None
        assert "artifact_id" in result.data
    finally:
        service.close_all()


def test_proxy_export_har_maps_a_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, proxy = _service(tmp_path)
    try:
        session_id = _web_session(service)

        def boom(_sid: str, _out: Path) -> dict[str, Any]:
            raise ProxyError("unavailable", "proxy down")

        monkeypatch.setattr(proxy, "export_har", boom)
        result = service.proxy_export_har(session_id)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "unavailable"
    finally:
        service.close_all()


def test_proxy_ca_install_pushes_the_cert_to_the_device(tmp_path: Path) -> None:
    service, proxy = _service(tmp_path)
    try:
        session_id = _web_session(service)
        cert = tmp_path / "mitmproxy-ca-cert.pem"
        cert.write_text("cert", encoding="utf-8")
        proxy.ca = cert
        adb = _FakeAdb()
        service._adb_backend = adb  # type: ignore[assignment]
        result = service.proxy_ca_install_android(session_id, "emulator-5554")
        assert result.ok, result.error
        assert result.data is not None
        assert result.data["pushed_to"].endswith("mitmproxy-ca-cert.pem")
        assert adb.pushed and adb.pushed[0][0] == "emulator-5554"
    finally:
        service.close_all()


def test_proxy_ca_install_refuses_without_a_generated_ca(tmp_path: Path) -> None:
    service, proxy = _service(tmp_path)
    try:
        session_id = _web_session(service)
        proxy.ca = None
        service._adb_backend = _FakeAdb()  # type: ignore[assignment]
        result = service.proxy_ca_install_android(session_id, "emulator-5554")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "not_found"
    finally:
        service.close_all()


def test_proxy_ca_install_refuses_on_a_closed_session(tmp_path: Path) -> None:
    service, _proxy = _service(tmp_path)
    try:
        session_id = _web_session(service)
        service.close_session(session_id)
        service._adb_backend = _FakeAdb()  # type: ignore[assignment]
        result = service.proxy_ca_install_android(session_id, "emulator-5554")
        assert result.ok is False
    finally:
        service.close_all()


def test_proxy_ca_install_maps_an_adb_error(tmp_path: Path) -> None:
    service, proxy = _service(tmp_path)
    try:
        session_id = _web_session(service)
        cert = tmp_path / "ca.pem"
        cert.write_text("cert", encoding="utf-8")
        proxy.ca = cert
        adb = _FakeAdb()
        adb.push_error = AdbError("device_offline", "no device")
        service._adb_backend = adb  # type: ignore[assignment]
        result = service.proxy_ca_install_android(session_id, "emulator-5554")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "device_offline"
    finally:
        service.close_all()


def test_proxy_ca_install_reclaims_if_the_session_closes_after_push(
    tmp_path: Path,
) -> None:
    service, proxy = _service(tmp_path)
    try:
        session_id = _web_session(service)
        cert = tmp_path / "ca.pem"
        cert.write_text("cert", encoding="utf-8")
        proxy.ca = cert
        adb = _FakeAdb()
        adb.on_push = lambda: service.close_session(session_id)
        service._adb_backend = adb  # type: ignore[assignment]
        result = service.proxy_ca_install_android(session_id, "emulator-5554")
        assert result.ok is False
    finally:
        service.close_all()


def test_proxy_start_refuses_a_closed_session_up_front(tmp_path: Path) -> None:
    service, proxy = _service(tmp_path)
    try:
        session_id = _web_session(service)
        service.close_session(session_id)
        result = service.proxy_start(session_id)
        assert result.ok is False
        assert proxy.started == []
    finally:
        service.close_all()


def test_proxy_stop_reports_success(tmp_path: Path) -> None:
    service, _proxy = _service(tmp_path)
    try:
        session_id = _web_session(service)
        service.proxy_start(session_id)
        result = service.proxy_stop(session_id)
        assert result.ok, result.error
        assert result.data is not None
        assert result.data["stopped"] is True
    finally:
        service.close_all()


def test_proxy_flows_and_replay_wrap_the_backend(tmp_path: Path) -> None:
    service, _proxy = _service(tmp_path)
    try:
        session_id = _web_session(service)
        flows = service.proxy_flows(session_id, offset=5, limit=10)
        assert flows.ok, flows.error
        assert flows.data is not None
        assert flows.data["offset"] == 5

        replay = service.proxy_replay(session_id, "flow-2")
        assert replay.ok, replay.error
        assert replay.data is not None
        assert replay.data["replayed"] == "flow-2"
    finally:
        service.close_all()


def test_proxy_flow_get_refuses_a_traversal_session_id(tmp_path: Path) -> None:
    service, _proxy = _service(tmp_path)
    try:
        _web_session(service)
        result = service.proxy_flow_get("../escape", "flow-1")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_params"
    finally:
        service.close_all()


def test_proxy_flow_get_wraps_an_unexpected_error(tmp_path: Path) -> None:
    service, proxy = _service(tmp_path)
    try:
        session_id = _web_session(service)
        proxy.flow_get_error = RuntimeError("decode fell over")
        result = service.proxy_flow_get(session_id, "flow-1")
        assert result.ok is False
    finally:
        service.close_all()


def test_proxy_export_har_wraps_an_unexpected_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, proxy = _service(tmp_path)
    try:
        session_id = _web_session(service)

        def boom(_sid: str, _out: Path) -> dict[str, Any]:
            raise RuntimeError("disk full")

        monkeypatch.setattr(proxy, "export_har", boom)
        result = service.proxy_export_har(session_id)
        assert result.ok is False
    finally:
        service.close_all()
