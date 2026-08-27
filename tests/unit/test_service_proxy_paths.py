"""ProxyAnalysisMixin: state gates, error mapping, capture registration.

The backend-level proxy tests pin what mitmproxy returns; what is covered here
is the service seam above it -- the layer that decides success vs failure for a
tool caller:

* the ``Result`` contract -- a ProxyError/AdbError becomes a structured failure
  and a clean call becomes a success carrying ``backend="proxy"``;
* the state gate -- proxy.start / ca.install refuse a closing/closed/failed
  session, and a start that succeeds only to find the session gone rolls the
  proxy back;
* capture registration -- a spilled flow body and an exported HAR are handed to
  the repository so they are reclaimable and re-openable.

A fake proxy/adb backend stands in for mitmproxy and adb; the real
AnalysisService, registry and repository run underneath.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb import AdbError
from headless_re_mcp.backends.proxy import ProxyError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import SessionState
from headless_re_mcp.core.service import AnalysisService


class _FakeProxy:
    def __init__(self, *, cert: Path | None = None) -> None:
        self.started: list[str] = []
        self.stopped: list[str] = []
        self._cert = cert
        self.raise_on_start: ProxyError | None = None

    def start(self, session_id: str, *, host: str, port: int) -> dict[str, Any]:
        if self.raise_on_start is not None:
            raise self.raise_on_start
        self.started.append(session_id)
        return {"running": True, "host": host, "port": port, "endpoint": f"{host}:{port}"}

    def stop(self, session_id: str) -> dict[str, Any]:
        self.stopped.append(session_id)
        return {"stopped": True}

    def status(self, session_id: str) -> dict[str, Any]:
        return {"running": True, "session_id": session_id}

    def flows(self, session_id: str, *, offset: int = 0, limit: int = 100) -> dict[str, Any]:
        return {"flows": [], "offset": offset, "limit": limit}

    def replay(self, session_id: str, flow_id: str) -> dict[str, Any]:
        return {"replayed": flow_id}

    def flow_get(self, session_id: str, flow_id: str, artifact_dir: Path) -> dict[str, Any]:
        artifact_dir.mkdir(parents=True, exist_ok=True)
        req_body = artifact_dir / f"req-{flow_id}.bin"
        req_body.write_bytes(b"request-body")
        return {
            "id": flow_id,
            "request": {"body_path": str(req_body)},
            "response": {"body": "inline", "body_path": None},
        }

    def export_har(self, session_id: str, out_path: Path) -> dict[str, Any]:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text('{"log":{"entries":[]}}', encoding="utf-8")
        return {"path": str(out_path), "entry_count": 0}

    def ca_cert_path(self) -> Path | None:
        return self._cert

    def close_all(self) -> None:
        return None


class _FakeAdb:
    def __init__(self) -> None:
        self.pushed: list[tuple[str, str, str]] = []
        self.raise_on_push: AdbError | None = None

    def push(self, serial: str, local: str, remote: str) -> dict[str, Any]:
        if self.raise_on_push is not None:
            raise self.raise_on_push
        self.pushed.append((serial, local, remote))
        return {"size": 1}


def _service(tmp_path: Path, proxy: _FakeProxy, adb: _FakeAdb | None = None) -> AnalysisService:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    service._proxy_backend = proxy  # type: ignore[assignment]
    if adb is not None:
        service._adb_backend = adb  # type: ignore[assignment]
    return service


def _web_session(service: AnalysisService) -> str:
    created = service.create_session("https://example.test/app", target="web")
    assert created.ok, created.error
    return created.data["session"]["id"]


# --------------------------------------------------------------------------
# start / stop
# --------------------------------------------------------------------------
def test_proxy_start_and_stop_round_trip(tmp_path: Path) -> None:
    proxy = _FakeProxy()
    service = _service(tmp_path, proxy)
    try:
        session_id = _web_session(service)
        started = service.proxy_start(session_id, port=8081)
        assert started.ok and started.data["endpoint"] == "127.0.0.1:8081"
        assert proxy.started == [session_id]

        stopped = service.proxy_stop(session_id)
        assert stopped.ok and proxy.stopped == [session_id]
    finally:
        service.close_all()


def test_proxy_start_refuses_a_closed_session(tmp_path: Path) -> None:
    proxy = _FakeProxy()
    service = _service(tmp_path, proxy)
    try:
        session_id = _web_session(service)
        service.registry.transition(session_id, SessionState.FAILED)
        result = service.proxy_start(session_id)
        assert result.ok is False
        # The backend was never touched because the gate fired first.
        assert proxy.started == []
    finally:
        service.close_all()


def test_proxy_start_rolls_back_when_session_closes_mid_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    proxy = _FakeProxy()
    service = _service(tmp_path, proxy)
    try:
        session_id = _web_session(service)

        # start() succeeds, but by the time it returns the session has been
        # flipped closed; the post-check must stop the proxy it just started.
        real_start = proxy.start

        def _start_then_close(sid: str, *, host: str, port: int) -> dict[str, Any]:
            data = real_start(sid, host=host, port=port)
            service.registry.transition(sid, SessionState.FAILED)
            return data

        monkeypatch.setattr(proxy, "start", _start_then_close)
        result = service.proxy_start(session_id)
        assert result.ok is False
        assert proxy.stopped == [session_id]
    finally:
        service.close_all()


def test_proxy_start_maps_a_backend_error(tmp_path: Path) -> None:
    proxy = _FakeProxy()
    proxy.raise_on_start = ProxyError("backend_error", "mitmproxy failed to bind")
    service = _service(tmp_path, proxy)
    try:
        session_id = _web_session(service)
        result = service.proxy_start(session_id)
        assert result.ok is False and result.error is not None
        assert result.error.code == "backend_error"
    finally:
        service.close_all()


# --------------------------------------------------------------------------
# status / flows / replay wrappers
# --------------------------------------------------------------------------
def test_proxy_status_flows_replay_wrap_success(tmp_path: Path) -> None:
    proxy = _FakeProxy()
    service = _service(tmp_path, proxy)
    try:
        session_id = _web_session(service)
        assert service.proxy_status(session_id).ok
        flows = service.proxy_flows(session_id, offset=2, limit=5)
        assert flows.ok and flows.data["offset"] == 2
        assert service.proxy_replay(session_id, "f1").data["replayed"] == "f1"
    finally:
        service.close_all()


def test_proxy_wrap_maps_a_proxy_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    proxy = _FakeProxy()
    service = _service(tmp_path, proxy)
    try:
        session_id = _web_session(service)

        def _boom(session_id: str) -> dict[str, Any]:
            raise ProxyError("invalid_state", "proxy not started")

        monkeypatch.setattr(proxy, "status", _boom)
        result = service.proxy_status(session_id)
        assert result.ok is False and result.error is not None
        assert result.error.code == "invalid_state"
    finally:
        service.close_all()


# --------------------------------------------------------------------------
# flow_get / export_har capture registration
# --------------------------------------------------------------------------
def test_proxy_flow_get_registers_a_spilled_body(tmp_path: Path) -> None:
    proxy = _FakeProxy()
    service = _service(tmp_path, proxy)
    try:
        session_id = _web_session(service)
        result = service.proxy_flow_get(session_id, "flow-1")
        assert result.ok and result.data is not None
        # The request body spill was registered and its artifact id folded back
        # into the request part.
        assert result.data["request"]["artifact_id"]
    finally:
        service.close_all()


def test_proxy_flow_get_maps_a_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    proxy = _FakeProxy()
    service = _service(tmp_path, proxy)
    try:
        session_id = _web_session(service)

        def _boom(session_id: str, flow_id: str, artifact_dir: Path) -> dict[str, Any]:
            raise ProxyError("not_found", "unknown flow")

        monkeypatch.setattr(proxy, "flow_get", _boom)
        result = service.proxy_flow_get(session_id, "ghost")
        assert result.ok is False and result.error is not None
        assert result.error.code == "not_found"
    finally:
        service.close_all()


def test_proxy_export_har_registers_the_capture(tmp_path: Path) -> None:
    proxy = _FakeProxy()
    service = _service(tmp_path, proxy)
    try:
        session_id = _web_session(service)
        result = service.proxy_export_har(session_id)
        assert result.ok and result.data is not None
        assert result.data["artifact_id"]
        listed = service.repository.list_artifacts(session_id)["artifacts"]
        assert any(a["kind"] == "proxy_har" for a in listed)
    finally:
        service.close_all()


# --------------------------------------------------------------------------
# ca.install_android
# --------------------------------------------------------------------------
def test_ca_install_pushes_the_cert(tmp_path: Path) -> None:
    cert = tmp_path / "mitmproxy-ca-cert.pem"
    cert.write_text("-----CERT-----")
    proxy = _FakeProxy(cert=cert)
    adb = _FakeAdb()
    service = _service(tmp_path, proxy, adb)
    try:
        session_id = _web_session(service)
        result = service.proxy_ca_install_android(session_id, "emulator-5554")
        assert result.ok and result.data is not None
        assert result.data["pushed_to"].endswith("mitmproxy-ca-cert.pem")
        assert adb.pushed and adb.pushed[0][0] == "emulator-5554"
    finally:
        service.close_all()


def test_ca_install_reports_a_missing_ca(tmp_path: Path) -> None:
    proxy = _FakeProxy(cert=None)
    service = _service(tmp_path, proxy, _FakeAdb())
    try:
        session_id = _web_session(service)
        result = service.proxy_ca_install_android(session_id, "emulator-5554")
        assert result.ok is False and result.error is not None
        assert result.error.code == "not_found"
    finally:
        service.close_all()


def test_ca_install_maps_an_adb_push_failure(tmp_path: Path) -> None:
    cert = tmp_path / "mitmproxy-ca-cert.pem"
    cert.write_text("-----CERT-----")
    proxy = _FakeProxy(cert=cert)
    adb = _FakeAdb()
    adb.raise_on_push = AdbError("backend_error", "push failed")
    service = _service(tmp_path, proxy, adb)
    try:
        session_id = _web_session(service)
        result = service.proxy_ca_install_android(session_id, "emulator-5554")
        assert result.ok is False and result.error is not None
        assert result.error.code == "backend_error"
    finally:
        service.close_all()


def test_ca_install_refuses_a_closed_session(tmp_path: Path) -> None:
    cert = tmp_path / "mitmproxy-ca-cert.pem"
    cert.write_text("-----CERT-----")
    proxy = _FakeProxy(cert=cert)
    service = _service(tmp_path, proxy, _FakeAdb())
    try:
        session_id = _web_session(service)
        service.registry.transition(session_id, SessionState.FAILED)
        result = service.proxy_ca_install_android(session_id, "emulator-5554")
        assert result.ok is False
    finally:
        service.close_all()
