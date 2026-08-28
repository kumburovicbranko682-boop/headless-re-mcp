"""Device-free coverage for the proxy (mitmproxy) service contract.

``service_proxy`` is the boundary between the mitmproxy backend (and, for CA
install, adb) and the RPC envelope. The mid-start reclaim and the closed
ca.install guard are pinned in test_proxy_service_state_guards, but the
success bookkeeping, the ProxyError/AdbError -> code mapping on every method,
the flow-body spill/no-spill split, and the CA-not-found and adb-push-failed
branches of ca.install had no device-free coverage.

These use fakes whose signatures match the real backends (notably
``start(..., ssl_insecure=...)`` and an adb backend exposing ``push``), so
the mapping and wiring are pinned without mitmproxy or a device.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb import AdbError
from headless_re_mcp.backends.proxy import ProxyError
from headless_re_mcp.config import Settings
from headless_re_mcp.core import service_proxy
from headless_re_mcp.core.service import AnalysisService

JsonObject = dict[str, Any]


class _FakeProxy:
    def __init__(
        self,
        *,
        raises: dict[str, BaseException] | None = None,
        spill: bool = True,
        cert: Path | None = None,
    ) -> None:
        self.raises = raises or {}
        self.spill = spill
        self.cert = cert
        self.started: list[str] = []
        self.stopped: list[str] = []

    def _maybe(self, name: str) -> None:
        exc = self.raises.get(name)
        if exc is not None:
            raise exc

    def start(
        self,
        session_id: str,
        host: str = "127.0.0.1",
        port: int = 8080,
        *,
        ssl_insecure: bool = False,
    ) -> JsonObject:
        self._maybe("start")
        self.started.append(session_id)
        return {"running": True, "host": host, "port": port, "endpoint": f"{host}:{port}"}

    def stop(self, session_id: str) -> JsonObject:
        self._maybe("stop")
        self.stopped.append(session_id)
        return {"stopped": True}

    def status(self, session_id: str) -> JsonObject:
        self._maybe("status")
        return {"running": True}

    def flows(self, session_id: str, offset: int = 0, limit: int = 100) -> JsonObject:
        self._maybe("flows")
        return {"flows": [], "count": 0, "has_more": False}

    def replay(self, session_id: str, flow_id: str) -> JsonObject:
        self._maybe("replay")
        return {"replayed": flow_id}

    def flow_get(self, session_id: str, flow_id: str, artifact_dir: Path) -> JsonObject:
        self._maybe("flow_get")
        if not self.spill:
            return {"id": flow_id, "response": {"body": "inline"}}
        artifact_dir.mkdir(parents=True, exist_ok=True)
        body = artifact_dir / f"flow-{flow_id}.bin"
        body.write_bytes(b"flow-bytes" * 16)
        return {"id": flow_id, "response": {"body_path": str(body)}}

    def export_har(self, session_id: str, out_path: Path) -> JsonObject:
        self._maybe("export_har")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text('{"log":{"entries":[]}}', encoding="utf-8")
        return {"path": str(out_path), "entry_count": 0}

    def ca_cert_path(self) -> Path | None:
        self._maybe("ca_cert_path")
        return self.cert

    def close_all(self) -> None:
        return None


class _FakeAdb:
    def __init__(self, *, push_raises: BaseException | None = None) -> None:
        self.push_raises = push_raises
        self.pushes: list[tuple[str, str, str]] = []

    def push(self, serial: str, local: str, remote: str) -> JsonObject:
        if self.push_raises is not None:
            raise self.push_raises
        self.pushes.append((serial, local, remote))
        return {"pushed": True}


def _service(tmp_path: Path, proxy: _FakeProxy, adb: _FakeAdb | None = None) -> AnalysisService:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    service._proxy_backend = proxy  # type: ignore[assignment]
    if adb is not None:
        service._adb_backend = adb  # type: ignore[assignment]
    return service


def _session(service: AnalysisService) -> str:
    created = service.create_session("https://example.com/app", target="web")
    assert created.data is not None
    return str(created.data["session"]["id"])


# --- proxy.start ------------------------------------------------------------


def test_start_reports_success_and_the_endpoint(tmp_path: Path) -> None:
    proxy = _FakeProxy()
    service = _service(tmp_path, proxy)
    try:
        sid = _session(service)
        res = service.proxy_start(sid, port=18099)
        assert res.ok, res.error
        assert res.data is not None
        assert res.data["endpoint"].endswith(":18099")
        assert proxy.started == [sid]
    finally:
        service.close_all()


def test_start_maps_a_proxy_error(tmp_path: Path) -> None:
    proxy = _FakeProxy(raises={"start": ProxyError("invalid_params", "port out of range")})
    service = _service(tmp_path, proxy)
    try:
        sid = _session(service)
        res = service.proxy_start(sid, port=18099)
        assert res.ok is False
        assert res.error is not None
        assert res.error.code == "invalid_params"
    finally:
        service.close_all()


# --- proxy.stop -------------------------------------------------------------


def test_stop_reports_success(tmp_path: Path) -> None:
    proxy = _FakeProxy()
    service = _service(tmp_path, proxy)
    try:
        sid = _session(service)
        res = service.proxy_stop(sid)
        assert res.ok, res.error
        assert proxy.stopped == [sid]
    finally:
        service.close_all()


def test_stop_maps_a_proxy_error(tmp_path: Path) -> None:
    proxy = _FakeProxy(raises={"stop": ProxyError("backend_error", "shutdown failed")})
    service = _service(tmp_path, proxy)
    try:
        sid = _session(service)
        res = service.proxy_stop(sid)
        assert res.ok is False
        assert res.error is not None
        assert res.error.code == "backend_error"
    finally:
        service.close_all()


# --- proxy.flow.get ---------------------------------------------------------


def test_flow_get_registers_a_spilled_body(tmp_path: Path) -> None:
    proxy = _FakeProxy(spill=True)
    service = _service(tmp_path, proxy)
    try:
        sid = _session(service)
        res = service.proxy_flow_get(sid, "f1")
        assert res.ok, res.error
        assert res.data is not None
        assert res.data["artifact_id"]
        listed = service.repository.list_artifacts(sid)
        kinds = {item["kind"] for item in listed["artifacts"]}
        assert "proxy_flow_body" in kinds
    finally:
        service.close_all()


def test_flow_get_leaves_an_inline_body_unregistered(tmp_path: Path) -> None:
    proxy = _FakeProxy(spill=False)
    service = _service(tmp_path, proxy)
    try:
        sid = _session(service)
        res = service.proxy_flow_get(sid, "f2")
        assert res.ok, res.error
        assert res.data is not None
        assert "artifact_id" not in res.data
    finally:
        service.close_all()


def test_flow_get_maps_a_proxy_error(tmp_path: Path) -> None:
    proxy = _FakeProxy(raises={"flow_get": ProxyError("not_found", "no such flow")})
    service = _service(tmp_path, proxy)
    try:
        sid = _session(service)
        res = service.proxy_flow_get(sid, "gone")
        assert res.ok is False
        assert res.error is not None
        assert res.error.code == "not_found"
    finally:
        service.close_all()


# --- proxy.export_har -------------------------------------------------------


def test_export_har_registers_the_capture(tmp_path: Path) -> None:
    proxy = _FakeProxy()
    service = _service(tmp_path, proxy)
    try:
        sid = _session(service)
        res = service.proxy_export_har(sid)
        assert res.ok, res.error
        assert res.data is not None
        assert res.data["artifact_id"]
        listed = service.repository.list_artifacts(sid)
        kinds = {item["kind"] for item in listed["artifacts"]}
        assert "proxy_har" in kinds
    finally:
        service.close_all()


def test_export_har_maps_a_proxy_error(tmp_path: Path) -> None:
    proxy = _FakeProxy(raises={"export_har": ProxyError("invalid_state", "proxy not running")})
    service = _service(tmp_path, proxy)
    try:
        sid = _session(service)
        res = service.proxy_export_har(sid)
        assert res.ok is False
        assert res.error is not None
        assert res.error.code == "invalid_state"
    finally:
        service.close_all()


# --- proxy.ca.install_android -----------------------------------------------


def test_ca_install_reports_not_found_when_no_cert_exists(tmp_path: Path) -> None:
    # No proxy has run, so ~/.mitmproxy has no CA yet; the guidance is a
    # structured not_found rather than a push of a nonexistent file.
    proxy = _FakeProxy(cert=None)
    adb = _FakeAdb()
    service = _service(tmp_path, proxy, adb)
    try:
        sid = _session(service)
        res = service.proxy_ca_install_android(sid, "emulator-5554")
        assert res.ok is False
        assert res.error is not None
        assert res.error.code == "not_found"
        assert adb.pushes == []
    finally:
        service.close_all()


def test_ca_install_pushes_the_cert_and_reports_guidance(tmp_path: Path) -> None:
    cert = tmp_path / "mitmproxy-ca-cert.pem"
    cert.write_text("cert", encoding="utf-8")
    proxy = _FakeProxy(cert=cert)
    adb = _FakeAdb()
    service = _service(tmp_path, proxy, adb)
    try:
        sid = _session(service)
        res = service.proxy_ca_install_android(sid, "emulator-5554")
        assert res.ok, res.error
        assert res.data is not None
        assert res.data["pushed_to"].endswith("mitmproxy-ca-cert.pem")
        assert adb.pushes and adb.pushes[0][0] == "emulator-5554"
    finally:
        service.close_all()


def test_ca_install_maps_an_adb_error(tmp_path: Path) -> None:
    cert = tmp_path / "mitmproxy-ca-cert.pem"
    cert.write_text("cert", encoding="utf-8")
    proxy = _FakeProxy(cert=cert)
    adb = _FakeAdb(push_raises=AdbError("not_found", "device unavailable"))
    service = _service(tmp_path, proxy, adb)
    try:
        sid = _session(service)
        res = service.proxy_ca_install_android(sid, "emulator-5554")
        assert res.ok is False
        assert res.error is not None
        assert res.error.code == "not_found"
    finally:
        service.close_all()


class _ClosingAdb:
    """An adb backend that closes the session mid-push to trip the recheck."""

    def __init__(self, service: AnalysisService, session_id: str) -> None:
        self._service = service
        self._session_id = session_id
        self.pushes: list[tuple[str, str, str]] = []

    def push(self, serial: str, local: str, remote: str) -> JsonObject:
        self.pushes.append((serial, local, remote))
        # The cert is already on the device; a close landing now must still be
        # noticed so the caller learns the session it targeted is gone.
        self._service.close_session(self._session_id)
        return {"pushed": True}


def test_ca_install_rechecks_after_the_push(tmp_path: Path) -> None:
    cert = tmp_path / "mitmproxy-ca-cert.pem"
    cert.write_text("cert", encoding="utf-8")
    proxy = _FakeProxy(cert=cert)
    service = _service(tmp_path, proxy)
    try:
        sid = _session(service)
        adb = _ClosingAdb(service, sid)
        service._adb_backend = adb  # type: ignore[assignment]
        res = service.proxy_ca_install_android(sid, "emulator-5554")
        assert res.ok is False
        assert res.error is not None
        # The push happened, then the post-push recheck refused a dead session.
        assert adb.pushes and "closed" in res.error.message
    finally:
        service.close_all()


# --- _proxy_wrap (status / flows / replay) ----------------------------------


def test_wrap_success_shapes_the_envelope(tmp_path: Path) -> None:
    proxy = _FakeProxy()
    service = _service(tmp_path, proxy)
    try:
        sid = _session(service)
        res = service.proxy_status(sid)
        assert res.ok, res.error
        assert res.data is not None
        assert res.data["running"] is True
        assert res.meta["backend"] == "proxy"
    finally:
        service.close_all()


def test_wrap_maps_a_proxy_error(tmp_path: Path) -> None:
    proxy = _FakeProxy(raises={"flows": ProxyError("invalid_state", "proxy not running")})
    service = _service(tmp_path, proxy)
    try:
        sid = _session(service)
        res = service.proxy_flows(sid)
        assert res.ok is False
        assert res.error is not None
        assert res.error.code == "invalid_state"
    finally:
        service.close_all()


def test_wrap_maps_an_unexpected_error_to_an_incident(tmp_path: Path) -> None:
    proxy = _FakeProxy(raises={"replay": RuntimeError("addon crashed")})
    service = _service(tmp_path, proxy)
    try:
        sid = _session(service)
        res = service.proxy_replay(sid, "f1")
        assert res.ok is False
        assert res.error is not None
        assert res.error.code == "internal_error"
    finally:
        service.close_all()


@pytest.mark.parametrize(
    ("method", "backend_op", "args"),
    [
        ("proxy_stop", "stop", ()),
        ("proxy_flow_get", "flow_get", ("f1",)),
        ("proxy_export_har", "export_har", ()),
    ],
)
def test_each_method_maps_an_unexpected_error_to_an_incident(
    tmp_path: Path, method: str, backend_op: str, args: tuple[Any, ...]
) -> None:
    proxy = _FakeProxy(raises={backend_op: RuntimeError("addon died")})
    service = _service(tmp_path, proxy)
    try:
        sid = _session(service)
        res = getattr(service, method)(sid, *args)
        assert res.ok is False
        assert res.error is not None
        assert res.error.code == "internal_error"
    finally:
        service.close_all()


def test_as_rpc_copies_details() -> None:
    err = ProxyError("too_large", "flow body too big", flow_id="f9")
    rpc = service_proxy._as_rpc(err)
    assert rpc.code == "too_large"
    assert str(rpc) == "flow body too big"
    assert rpc.details == {"flow_id": "f9"}
    err.details["flow_id"] = "mutated"
    assert rpc.details["flow_id"] == "f9"
