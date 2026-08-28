"""Proxy service-layer paths (ProxyAnalysisMixin) the backend suites do not reach.

The proxy backend client is exercised directly elsewhere; here the orchestration
around it is pinned: start/stop recording and timeline, the flow-body artifact
registration in proxy.flow.get, HAR export registration, the Android CA push,
and the ProxyError/AdbError -> structured-envelope mapping every method funnels
failures through. A web session stands in for any device/web session (the proxy
is session-scoped and target-agnostic).
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.adb import AdbError
from headless_re_mcp.backends.proxy import ProxyError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService


def _service(tmp_path: Path) -> AnalysisService:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    return AnalysisService(settings)


def _web_session(service: AnalysisService) -> str:
    created = service.create_session("https://example.com/app", target="web")
    assert created.ok and created.data is not None, created.error
    return str(created.data["session"]["id"])


class _FakeProxy:
    """A proxy backend whose every op returns canned data or raises on demand."""

    def __init__(self) -> None:
        self.raise_on: dict[str, BaseException] = {}
        self.started: list[tuple[str, str, int]] = []
        self.stopped: list[str] = []
        self.cert: Path | None = None
        self.flow_get_result: dict[str, Any] | None = None

    def _maybe(self, op: str) -> None:
        exc = self.raise_on.get(op)
        if exc is not None:
            raise exc

    def start(self, session_id: str, host: str = "127.0.0.1", port: int = 8080) -> dict[str, Any]:
        self._maybe("start")
        self.started.append((session_id, host, port))
        return {"endpoint": f"{host}:{port}", "pid": 4242}

    def stop(self, session_id: str) -> dict[str, Any]:
        self._maybe("stop")
        self.stopped.append(session_id)
        return {"stopped": True}

    def status(self, session_id: str) -> dict[str, Any]:
        self._maybe("status")
        return {"running": True}

    def flows(self, session_id: str, offset: int = 0, limit: int = 100) -> dict[str, Any]:
        self._maybe("flows")
        return {"flows": [], "count": 0, "offset": offset, "has_more": False}

    def replay(self, session_id: str, flow_id: str) -> dict[str, Any]:
        self._maybe("replay")
        return {"replayed": flow_id}

    def flow_get(self, session_id: str, flow_id: str, artifact_dir: Path) -> dict[str, Any]:
        self._maybe("flow_get")
        if self.flow_get_result is not None:
            return self.flow_get_result
        Path(artifact_dir).mkdir(parents=True, exist_ok=True)
        req = Path(artifact_dir) / "req.bin"
        req.write_bytes(b"request body")
        resp = Path(artifact_dir) / "resp.bin"
        resp.write_bytes(b"response body")
        return {
            "flow_id": flow_id,
            "request": {"method": "GET", "body_path": str(req)},
            "response": {"status": 200, "body_path": str(resp)},
        }

    def export_har(self, session_id: str, out: Path) -> dict[str, Any]:
        self._maybe("export_har")
        Path(out).write_text('{"log":{"entries":[]}}', encoding="utf-8")
        return {"path": str(out), "entry_count": 0, "truncated": False}

    def ca_cert_path(self) -> Path | None:
        return self.cert

    def close_all(self) -> None:
        return None


class _FakeAdb:
    def __init__(self) -> None:
        self.pushed: list[tuple[str, str, str]] = []
        self.raise_on_push: BaseException | None = None

    def push(self, serial: str, local: str, remote: str) -> dict[str, Any]:
        if self.raise_on_push is not None:
            raise self.raise_on_push
        self.pushed.append((serial, local, remote))
        return {"remote": remote, "size": 1}


# ---------------------------------------------------------------------------
# proxy_start / proxy_stop
# ---------------------------------------------------------------------------
def test_proxy_start_records_backend_and_reports_endpoint(tmp_path: Path) -> None:
    service = _service(tmp_path)
    fake = _FakeProxy()
    service._proxy_backend = fake  # type: ignore[assignment]
    try:
        sid = _web_session(service)
        result = service.proxy_start(sid, port=9090)
        assert result.ok, result.error
        assert result.data is not None
        assert result.data["endpoint"] == "127.0.0.1:9090"
        assert result.meta["backend"] == "proxy"
        assert fake.started and fake.started[0][2] == 9090
    finally:
        service.close_all()


def test_proxy_start_maps_proxy_error(tmp_path: Path) -> None:
    service = _service(tmp_path)
    fake = _FakeProxy()
    fake.raise_on["start"] = ProxyError("backend_error", "port already bound")
    service._proxy_backend = fake  # type: ignore[assignment]
    try:
        sid = _web_session(service)
        result = service.proxy_start(sid)
        assert result.ok is False
        assert result.error is not None and result.error.code == "backend_error"
    finally:
        service.close_all()


def test_proxy_start_refused_on_a_closed_session(tmp_path: Path) -> None:
    service = _service(tmp_path)
    service._proxy_backend = _FakeProxy()  # type: ignore[assignment]
    try:
        sid = _web_session(service)
        assert service.close_session(sid).ok
        result = service.proxy_start(sid)
        assert result.ok is False
        assert result.error is not None and result.error.code == "invalid_request"
    finally:
        service.close_all()


def test_proxy_stop_maps_proxy_error_and_unexpected(tmp_path: Path) -> None:
    service = _service(tmp_path)
    fake = _FakeProxy()
    service._proxy_backend = fake  # type: ignore[assignment]
    try:
        sid = _web_session(service)
        fake.raise_on["stop"] = ProxyError("not_found", "no proxy for session")
        proxy_err = service.proxy_stop(sid)
        assert proxy_err.ok is False
        assert proxy_err.error is not None and proxy_err.error.code == "not_found"

        fake.raise_on["stop"] = RuntimeError("thread join blew up")
        unexpected = service.proxy_stop(sid)
        assert unexpected.ok is False
        assert unexpected.error is not None and unexpected.error.code == "internal_error"
    finally:
        service.close_all()


# ---------------------------------------------------------------------------
# _proxy_wrap (status / flows / replay)
# ---------------------------------------------------------------------------
def test_proxy_status_flows_replay_wrap_success(tmp_path: Path) -> None:
    service = _service(tmp_path)
    service._proxy_backend = _FakeProxy()  # type: ignore[assignment]
    try:
        sid = _web_session(service)
        assert service.proxy_status(sid).ok
        assert service.proxy_flows(sid, offset=0, limit=10).ok
        assert service.proxy_replay(sid, "flow-1").ok
    finally:
        service.close_all()


def test_proxy_wrap_maps_proxy_error_and_unexpected(tmp_path: Path) -> None:
    service = _service(tmp_path)
    fake = _FakeProxy()
    service._proxy_backend = fake  # type: ignore[assignment]
    try:
        sid = _web_session(service)
        fake.raise_on["status"] = ProxyError("capability_unavailable", "mitmproxy missing")
        mapped = service.proxy_status(sid)
        assert mapped.ok is False
        assert mapped.error is not None and mapped.error.code == "capability_unavailable"

        fake.raise_on["flows"] = RuntimeError("recorder corrupt")
        unexpected = service.proxy_flows(sid)
        assert unexpected.ok is False
        assert unexpected.error is not None and unexpected.error.code == "internal_error"
    finally:
        service.close_all()


# ---------------------------------------------------------------------------
# proxy_flow_get body-artifact registration
# ---------------------------------------------------------------------------
def test_proxy_flow_get_registers_both_body_artifacts(tmp_path: Path) -> None:
    service = _service(tmp_path)
    service._proxy_backend = _FakeProxy()  # type: ignore[assignment]
    try:
        sid = _web_session(service)
        result = service.proxy_flow_get(sid, "flow-9")
        assert result.ok, result.error
        assert result.data is not None
        assert result.data["request"]["artifact_id"]
        assert result.data["response"]["artifact_id"]
    finally:
        service.close_all()


def test_proxy_flow_get_skips_non_dict_parts_and_bodyless_parts(tmp_path: Path) -> None:
    service = _service(tmp_path)
    fake = _FakeProxy()
    # request is not a dict (skipped); response is a dict but carries no body_path.
    fake.flow_get_result = {"flow_id": "f", "request": None, "response": {"status": 204}}
    service._proxy_backend = fake  # type: ignore[assignment]
    try:
        sid = _web_session(service)
        result = service.proxy_flow_get(sid, "f")
        assert result.ok, result.error
        assert result.data is not None
        assert "artifact_id" not in result.data["response"]
    finally:
        service.close_all()


def test_proxy_flow_get_reports_artifact_error_without_failing(tmp_path: Path) -> None:
    service = _service(tmp_path)
    service._proxy_backend = _FakeProxy()  # type: ignore[assignment]
    try:
        sid = _web_session(service)

        def explode(**_: object) -> dict[str, Any]:
            raise RuntimeError("repository is down")

        service.record_artifact = explode  # type: ignore[assignment]
        result = service.proxy_flow_get(sid, "flow-x")
        assert result.ok, result.error
        assert result.data is not None
        assert "repository is down" in result.data["request"]["artifact_error"]
    finally:
        service.close_all()


def test_proxy_flow_get_maps_proxy_error(tmp_path: Path) -> None:
    service = _service(tmp_path)
    fake = _FakeProxy()
    fake.raise_on["flow_get"] = ProxyError("not_found", "unknown flow id")
    service._proxy_backend = fake  # type: ignore[assignment]
    try:
        sid = _web_session(service)
        result = service.proxy_flow_get(sid, "missing")
        assert result.ok is False
        assert result.error is not None and result.error.code == "not_found"
    finally:
        service.close_all()


# ---------------------------------------------------------------------------
# proxy_export_har
# ---------------------------------------------------------------------------
def test_proxy_export_har_registers_the_artifact(tmp_path: Path) -> None:
    service = _service(tmp_path)
    service._proxy_backend = _FakeProxy()  # type: ignore[assignment]
    try:
        sid = _web_session(service)
        result = service.proxy_export_har(sid)
        assert result.ok, result.error
        assert result.data is not None
        assert result.data["artifact_id"]
        listed = service.repository.list_artifacts(sid)
        assert any(item["kind"] == "proxy_har" for item in listed["artifacts"])
    finally:
        service.close_all()


def test_proxy_export_har_maps_proxy_error(tmp_path: Path) -> None:
    service = _service(tmp_path)
    fake = _FakeProxy()
    fake.raise_on["export_har"] = ProxyError("backend_error", "no capture to export")
    service._proxy_backend = fake  # type: ignore[assignment]
    try:
        sid = _web_session(service)
        result = service.proxy_export_har(sid)
        assert result.ok is False
        assert result.error is not None and result.error.code == "backend_error"
    finally:
        service.close_all()


# ---------------------------------------------------------------------------
# proxy_ca_install_android
# ---------------------------------------------------------------------------
def test_proxy_ca_install_android_pushes_the_cert(tmp_path: Path) -> None:
    service = _service(tmp_path)
    fake = _FakeProxy()
    cert = tmp_path / "mitmproxy-ca-cert.pem"
    cert.write_text("-----BEGIN CERTIFICATE-----\n", encoding="utf-8")
    fake.cert = cert
    service._proxy_backend = fake  # type: ignore[assignment]
    adb = _FakeAdb()
    service._adb_backend = adb  # type: ignore[attr-defined]
    try:
        sid = _web_session(service)
        result = service.proxy_ca_install_android(sid, "emulator-5554")
        assert result.ok, result.error
        assert result.data is not None
        assert result.data["pushed_to"] == "/data/local/tmp/mitmproxy-ca-cert.pem"
        assert adb.pushed and adb.pushed[0][0] == "emulator-5554"
    finally:
        service.close_all()


def test_proxy_ca_install_android_reports_missing_ca(tmp_path: Path) -> None:
    service = _service(tmp_path)
    fake = _FakeProxy()
    fake.cert = None  # proxy never started -> no ~/.mitmproxy CA
    service._proxy_backend = fake  # type: ignore[assignment]
    try:
        sid = _web_session(service)
        result = service.proxy_ca_install_android(sid, "emulator-5554")
        assert result.ok is False
        assert result.error is not None and result.error.code == "not_found"
    finally:
        service.close_all()


def test_proxy_ca_install_android_maps_adb_error(tmp_path: Path) -> None:
    service = _service(tmp_path)
    fake = _FakeProxy()
    cert = tmp_path / "ca.pem"
    cert.write_text("x", encoding="utf-8")
    fake.cert = cert
    service._proxy_backend = fake  # type: ignore[assignment]
    adb = _FakeAdb()
    adb.raise_on_push = AdbError("not_found", "device offline")
    service._adb_backend = adb  # type: ignore[attr-defined]
    try:
        sid = _web_session(service)
        result = service.proxy_ca_install_android(sid, "emulator-5554")
        assert result.ok is False
        assert result.error is not None and result.error.code == "not_found"
    finally:
        service.close_all()


def test_proxy_ca_install_android_refused_on_a_closed_session(tmp_path: Path) -> None:
    service = _service(tmp_path)
    service._proxy_backend = _FakeProxy()  # type: ignore[assignment]
    try:
        sid = _web_session(service)
        assert service.close_session(sid).ok
        result = service.proxy_ca_install_android(sid, "emulator-5554")
        assert result.ok is False
        assert result.error is not None and result.error.code == "invalid_request"
    finally:
        service.close_all()
