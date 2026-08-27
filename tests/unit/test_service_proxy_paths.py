"""Guard, lifecycle and error-mapping paths of the proxy service mixin.

The proxy backend has its own suite; this file exercises the thin service layer
that sits on top of it -- the state gates that refuse a start against a closing
session, the rollback when a session is closed mid-start, the capture
registration on ``flow.get`` and ``export_har``, and the ``ProxyError`` /
``AdbError`` -> envelope mapping. A real ``AnalysisService`` is built with a web
session and the backend methods are stubbed, so no mitmproxy or device is
touched.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.core.service_proxy as service_proxy
from headless_re_mcp.backends.adb import AdbError
from headless_re_mcp.backends.proxy import ProxyError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import SessionState
from headless_re_mcp.core.service import AnalysisService


@pytest.fixture
def service(tmp_path: Path) -> Iterator[AnalysisService]:
    svc = AnalysisService(replace(Settings.load(), artifact_root=tmp_path / "artifacts"))
    try:
        yield svc
    finally:
        svc.close_all()


def _web_session(svc: AnalysisService) -> str:
    created = svc.create_session("https://example.com/app", target="web")
    assert created.ok and created.data is not None
    return str(created.data["session"]["id"])


def _make_ready(svc: AnalysisService, session_id: str) -> None:
    svc.registry.transition(session_id, SessionState.OPENING)
    svc.registry.transition(session_id, SessionState.READY)


# ---------------------------------------------------------------------------
# proxy_start


def test_proxy_start_records_the_backend_and_returns_the_endpoint(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)
    _make_ready(service, session_id)

    def fake_start(sid: str, host: str = "127.0.0.1", port: int = 8080) -> dict[str, Any]:
        return {"running": True, "host": host, "port": port, "endpoint": f"http://{host}:{port}"}

    monkeypatch.setattr(service._proxy_backend, "start", fake_start)

    result = service.proxy_start(session_id, port=9091)

    assert result.ok, result.error
    assert result.data is not None
    assert result.data["endpoint"] == "http://127.0.0.1:9091"


def test_proxy_start_is_refused_against_a_failed_session(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)
    service.registry.transition(session_id, SessionState.FAILED)
    calls: list[str] = []
    monkeypatch.setattr(
        service._proxy_backend, "start", lambda *a, **k: calls.append("started") or {}
    )

    result = service.proxy_start(session_id)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "invalid_request"
    assert calls == [], "a refused start must never reach the backend"


def test_proxy_start_rolls_back_when_the_session_closes_mid_start(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A start that wins the port but loses to a concurrent close must stop."""
    session_id = _web_session(service)
    _make_ready(service, session_id)
    stops: list[str] = []

    def racing_start(sid: str, host: str = "127.0.0.1", port: int = 8080) -> dict[str, Any]:
        service.registry.transition(sid, SessionState.CLOSING)
        return {"running": True, "endpoint": f"http://{host}:{port}"}

    monkeypatch.setattr(service._proxy_backend, "start", racing_start)
    monkeypatch.setattr(
        service._proxy_backend, "stop", lambda sid: stops.append(sid) or {"stopped": True}
    )

    result = service.proxy_start(session_id)

    assert not result.ok
    assert stops == [session_id], "the reserved proxy must be stopped on rollback"


def test_proxy_start_maps_a_backend_error(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)
    _make_ready(service, session_id)

    def boom(*_a: Any, **_k: Any) -> dict[str, Any]:
        raise ProxyError("invalid_state", "port already bound", port=8080)

    monkeypatch.setattr(service._proxy_backend, "start", boom)

    result = service.proxy_start(session_id)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "invalid_state"


# ---------------------------------------------------------------------------
# proxy_stop


def test_proxy_stop_reports_the_backend_payload(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)
    monkeypatch.setattr(service._proxy_backend, "stop", lambda sid: {"stopped": True})

    result = service.proxy_stop(session_id)

    assert result.ok, result.error
    assert result.data == {"stopped": True}


def test_proxy_stop_maps_a_proxy_error(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)

    def boom(_sid: str) -> dict[str, Any]:
        raise ProxyError("backend_error", "worker gone")

    monkeypatch.setattr(service._proxy_backend, "stop", boom)

    result = service.proxy_stop(session_id)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "backend_error"


def test_proxy_stop_maps_an_unexpected_error(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)

    def boom(_sid: str) -> dict[str, Any]:
        raise ValueError("bad state")

    monkeypatch.setattr(service._proxy_backend, "stop", boom)

    result = service.proxy_stop(session_id)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "invalid_request"


# ---------------------------------------------------------------------------
# _proxy_wrap: status / flows / replay


def test_proxy_status_delegates_to_the_backend(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)
    monkeypatch.setattr(service._proxy_backend, "status", lambda sid: {"running": False})

    result = service.proxy_status(session_id)

    assert result.ok, result.error
    assert result.data == {"running": False}


def test_proxy_flows_passes_paging_through(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)
    seen: dict[str, Any] = {}

    def fake_flows(sid: str, offset: int = 0, limit: int = 100) -> dict[str, Any]:
        seen.update(sid=sid, offset=offset, limit=limit)
        return {"flows": [], "total": 0}

    monkeypatch.setattr(service._proxy_backend, "flows", fake_flows)

    result = service.proxy_flows(session_id, offset=5, limit=10)

    assert result.ok, result.error
    assert seen == {"sid": session_id, "offset": 5, "limit": 10}


def test_proxy_replay_delegates_to_the_backend(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)
    monkeypatch.setattr(
        service._proxy_backend, "replay", lambda sid, fid: {"replayed": fid}
    )

    result = service.proxy_replay(session_id, "flow-1")

    assert result.ok, result.error
    assert result.data == {"replayed": "flow-1"}


def test_proxy_wrap_maps_a_proxy_error(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)

    def boom(_sid: str) -> dict[str, Any]:
        raise ProxyError("not_found", "no such session")

    monkeypatch.setattr(service._proxy_backend, "status", boom)

    result = service.proxy_status(session_id)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "not_found"


def test_proxy_wrap_maps_an_unexpected_error(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)

    def boom(_sid: str, offset: int = 0, limit: int = 100) -> dict[str, Any]:
        raise ValueError("bad offset")

    monkeypatch.setattr(service._proxy_backend, "flows", boom)

    result = service.proxy_flows(session_id)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "invalid_request"


# ---------------------------------------------------------------------------
# proxy_flow_get


def test_flow_get_ignores_a_part_that_is_not_an_object(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)

    def fake_flow_get(sid: str, fid: str, artifact_dir: Path) -> dict[str, Any]:
        return {"id": fid, "request": None, "response": "unexpected"}

    monkeypatch.setattr(service._proxy_backend, "flow_get", fake_flow_get)

    result = service.proxy_flow_get(session_id, "f1")

    assert result.ok, result.error
    assert result.data == {"id": "f1", "request": None, "response": "unexpected"}


def test_flow_get_surfaces_a_capture_registration_failure_on_the_part(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)

    def fake_flow_get(sid: str, fid: str, artifact_dir: Path) -> dict[str, Any]:
        artifact_dir.mkdir(parents=True, exist_ok=True)
        body = artifact_dir / "resp.bin"
        body.write_bytes(b"\x00\x01")
        return {"id": fid, "response": {"status": 200, "body_path": str(body)}}

    monkeypatch.setattr(service._proxy_backend, "flow_get", fake_flow_get)
    monkeypatch.setattr(
        service_proxy,
        "_register_capture",
        lambda *a, **k: {"artifact_error": "artifact store is read-only"},
    )

    result = service.proxy_flow_get(session_id, "f2")

    assert result.ok, result.error
    assert result.data is not None
    assert result.data["response"]["artifact_error"] == "artifact store is read-only"


def test_flow_get_leaves_a_part_untouched_when_registration_says_nothing(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A registration that returns neither an id nor an error adds no fields."""
    session_id = _web_session(service)

    def fake_flow_get(sid: str, fid: str, artifact_dir: Path) -> dict[str, Any]:
        artifact_dir.mkdir(parents=True, exist_ok=True)
        body = artifact_dir / "req.bin"
        body.write_bytes(b"\x00")
        return {"id": fid, "request": {"method": "GET", "body_path": str(body)}}

    monkeypatch.setattr(service._proxy_backend, "flow_get", fake_flow_get)
    monkeypatch.setattr(service_proxy, "_register_capture", lambda *a, **k: {})

    result = service.proxy_flow_get(session_id, "f3")

    assert result.ok, result.error
    assert result.data is not None
    part = result.data["request"]
    assert "artifact_id" not in part
    assert "artifact_error" not in part


def test_flow_get_maps_a_proxy_error(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)

    def boom(sid: str, fid: str, artifact_dir: Path) -> dict[str, Any]:
        raise ProxyError("not_found", "unknown flow", flow_id=fid)

    monkeypatch.setattr(service._proxy_backend, "flow_get", boom)

    result = service.proxy_flow_get(session_id, "missing")

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "not_found"


# ---------------------------------------------------------------------------
# proxy_export_har


def test_export_har_registers_the_capture(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)

    def fake_export(sid: str, out: Path) -> dict[str, Any]:
        out.write_text("[]", encoding="utf-8")
        return {"path": str(out), "flow_count": 0}

    monkeypatch.setattr(service._proxy_backend, "export_har", fake_export)

    result = service.proxy_export_har(session_id)

    assert result.ok, result.error
    assert result.data is not None
    assert "artifact_id" in result.data


def test_export_har_maps_a_proxy_error(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)

    def boom(sid: str, out: Path) -> dict[str, Any]:
        raise ProxyError("backend_error", "no flows to export")

    monkeypatch.setattr(service._proxy_backend, "export_har", boom)

    result = service.proxy_export_har(session_id)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "backend_error"


# ---------------------------------------------------------------------------
# proxy_ca_install_android


class _FakeAdb:
    def __init__(self) -> None:
        self.pushed: list[tuple[str, str, str]] = []

    def push(self, serial: str, local: str, remote: str) -> dict[str, Any]:
        self.pushed.append((serial, local, remote))
        return {"pushed": True}


def test_ca_install_pushes_the_generated_ca_to_the_device(
    service: AnalysisService, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)
    _make_ready(service, session_id)
    cert = tmp_path / "mitmproxy-ca-cert.pem"
    cert.write_text("-----BEGIN CERTIFICATE-----", encoding="utf-8")
    fake_adb = _FakeAdb()
    monkeypatch.setattr(service._proxy_backend, "ca_cert_path", lambda: cert)
    monkeypatch.setattr(service, "_adb_backend", fake_adb, raising=False)

    result = service.proxy_ca_install_android(session_id, "emulator-5554")

    assert result.ok, result.error
    assert result.data is not None
    assert result.data["pushed_to"] == "/data/local/tmp/mitmproxy-ca-cert.pem"
    assert fake_adb.pushed == [
        ("emulator-5554", str(cert), "/data/local/tmp/mitmproxy-ca-cert.pem")
    ]


def test_ca_install_reports_a_missing_ca(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)
    _make_ready(service, session_id)
    monkeypatch.setattr(service._proxy_backend, "ca_cert_path", lambda: None)

    result = service.proxy_ca_install_android(session_id, "emulator-5554")

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "not_found"


def test_ca_install_maps_an_adb_failure(
    service: AnalysisService, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)
    _make_ready(service, session_id)
    cert = tmp_path / "mitmproxy-ca-cert.pem"
    cert.write_text("pem", encoding="utf-8")

    class _OfflineAdb:
        def push(self, *_a: Any, **_k: Any) -> dict[str, Any]:
            raise AdbError("device_offline", "device not connected", serial="emulator-5554")

    monkeypatch.setattr(service._proxy_backend, "ca_cert_path", lambda: cert)
    monkeypatch.setattr(service, "_adb_backend", _OfflineAdb(), raising=False)

    result = service.proxy_ca_install_android(session_id, "emulator-5554")

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "device_offline"


def test_ca_install_refuses_to_report_success_if_the_session_closes_mid_push(
    service: AnalysisService, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A push that lands after a concurrent close must not read as installed."""
    session_id = _web_session(service)
    _make_ready(service, session_id)
    cert = tmp_path / "mitmproxy-ca-cert.pem"
    cert.write_text("pem", encoding="utf-8")

    class _RacingAdb:
        def push(self, *_a: Any, **_k: Any) -> dict[str, Any]:
            service.registry.transition(session_id, SessionState.CLOSING)
            return {"pushed": True}

    monkeypatch.setattr(service._proxy_backend, "ca_cert_path", lambda: cert)
    monkeypatch.setattr(service, "_adb_backend", _RacingAdb(), raising=False)

    result = service.proxy_ca_install_android(session_id, "emulator-5554")

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "invalid_request"


def test_ca_install_is_refused_against_a_failed_session(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)
    service.registry.transition(session_id, SessionState.FAILED)
    calls: list[str] = []
    monkeypatch.setattr(
        service._proxy_backend, "ca_cert_path", lambda: calls.append("checked") or None
    )

    result = service.proxy_ca_install_android(session_id, "emulator-5554")

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "invalid_request"
    assert calls == [], "a refused install must never reach the CA lookup"
