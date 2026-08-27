"""Proxy service methods: start rollback, error mapping and CA-install states.

The proxy interception service is shared by Web and Android. Its methods add
session-state re-checks around the backend and register spilled bodies / HAR
files as artifacts. The live gate covers the happy lifecycle; these drive the
branches it does not: a start that races a close, a flow body registered under
its own part, and the CA-install guardrails on a closed session or a missing CA.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from headless_re_mcp.backends.adb import AdbError
from headless_re_mcp.backends.proxy.client import ProxyError
from headless_re_mcp.core.service_proxy import ProxyAnalysisMixin
from headless_re_mcp.core.session import SessionRegistry


class _Repo:
    def __init__(self) -> None:
        self.backends: list[Any] = []
        self.timeline: list[Any] = []

    def record_backend(self, session_id: str, kind: str, **fields: Any) -> None:
        self.backends.append((session_id, kind, fields))

    def append_timeline(self, session_id: str, event: str, message: str, **details: Any) -> None:
        self.timeline.append((session_id, event, message, details))

    def register_artifact(self, **fields: Any) -> dict[str, Any]:
        return {"id": "artifact-1", **fields}


class _Settings:
    def __init__(self, artifact_root: Path) -> None:
        self.artifact_root = artifact_root
        self.adb = None


class _Service(ProxyAnalysisMixin):
    def __init__(self, proxy: Any, artifact_root: Path) -> None:
        self.registry = SessionRegistry()
        self.repository = _Repo()
        self.settings = _Settings(artifact_root)  # type: ignore[assignment]
        self._proxy_backend = proxy


def _session(service: _Service) -> str:
    return service.registry.create("https://example.invalid").id


# ----------------------------------------------------------------------
# proxy_start.
# ----------------------------------------------------------------------
def test_proxy_start_success_records_backend_and_timeline(tmp_path: Path) -> None:
    class _Proxy:
        def start(self, session_id: str, host: str, port: int) -> dict[str, Any]:
            return {"running": True, "host": host, "port": port, "endpoint": f"{host}:{port}"}

    service = _Service(_Proxy(), tmp_path)
    session_id = _session(service)
    result = service.proxy_start(session_id, port=8080)
    assert result.ok is True
    assert service.repository.backends[0][1] == "proxy"
    assert any(entry[1] == "proxy.start" for entry in service.repository.timeline)


def test_proxy_start_on_a_closed_session_fails_without_touching_the_backend(
    tmp_path: Path,
) -> None:
    started: list[str] = []

    class _Proxy:
        def start(  # pragma: no cover - must not be reached
            self, session_id: str, host: str, port: int
        ) -> dict[str, Any]:
            started.append(session_id)
            return {"running": True}

    from headless_re_mcp.core.models import SessionState

    service = _Service(_Proxy(), tmp_path)
    session_id = _session(service)
    service.registry.transition(session_id, SessionState.CLOSING)
    service.registry.transition(session_id, SessionState.CLOSED)
    result = service.proxy_start(session_id, port=8080)
    assert result.ok is False
    assert started == []


def test_proxy_start_stops_the_backend_when_the_session_closes_mid_start(
    tmp_path: Path,
) -> None:
    """A close arriving after the port bound must not report a live proxy.

    The port really did bind, so leaving it up would strand a listener nothing
    can stop; the service stops it and reports the close instead of ok=True.
    """
    from headless_re_mcp.core.models import SessionState

    stopped: list[str] = []
    service_ref: dict[str, Any] = {}

    class _Proxy:
        def start(self, session_id: str, host: str, port: int) -> dict[str, Any]:
            service = service_ref["service"]
            service.registry.transition(session_id, SessionState.CLOSING)
            service.registry.transition(session_id, SessionState.CLOSED)
            return {"running": True, "host": host, "port": port, "endpoint": f"{host}:{port}"}

        def stop(self, session_id: str) -> dict[str, Any]:
            stopped.append(session_id)
            return {"stopped": True}

    service = _Service(_Proxy(), tmp_path)
    service_ref["service"] = service
    session_id = _session(service)
    result = service.proxy_start(session_id, port=8080)
    assert result.ok is False
    assert stopped == [session_id]


def test_proxy_start_maps_a_backend_error_to_the_envelope(tmp_path: Path) -> None:
    class _Proxy:
        def start(self, session_id: str, host: str, port: int) -> dict[str, Any]:
            raise ProxyError("invalid_state", "port is already in use")

    service = _Service(_Proxy(), tmp_path)
    session_id = _session(service)
    result = service.proxy_start(session_id, port=8080)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "invalid_state"


# ----------------------------------------------------------------------
# proxy_stop and _proxy_wrap-backed reads.
# ----------------------------------------------------------------------
def test_proxy_stop_maps_error_and_success(tmp_path: Path) -> None:
    class _OkProxy:
        def stop(self, session_id: str) -> dict[str, Any]:
            return {"stopped": True}

    class _BadProxy:
        def stop(self, session_id: str) -> dict[str, Any]:
            raise ProxyError("backend_error", "shutdown failed")

    service = _Service(_OkProxy(), tmp_path)
    session_id = _session(service)
    assert service.proxy_stop(session_id).ok is True

    service_bad = _Service(_BadProxy(), tmp_path)
    bad_id = _session(service_bad)
    result = service_bad.proxy_stop(bad_id)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "backend_error"


def test_proxy_stop_reports_an_unexpected_exception(tmp_path: Path) -> None:
    class _Proxy:
        def stop(self, session_id: str) -> dict[str, Any]:
            raise RuntimeError("thread join blew up")

    service = _Service(_Proxy(), tmp_path)
    session_id = _session(service)
    result = service.proxy_stop(session_id)
    assert result.ok is False
    assert result.error is not None


def test_proxy_status_wraps_success_and_error(tmp_path: Path) -> None:
    class _Proxy:
        def __init__(self, fail: bool) -> None:
            self.fail = fail

        def status(self, session_id: str) -> dict[str, Any]:
            if self.fail:
                raise ProxyError("invalid_state", "no proxy running")
            return {"running": True}

    service = _Service(_Proxy(fail=False), tmp_path)
    session_id = _session(service)
    assert service.proxy_status(session_id).ok is True

    service_fail = _Service(_Proxy(fail=True), tmp_path)
    fail_id = _session(service_fail)
    result = service_fail.proxy_status(fail_id)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "invalid_state"


def test_proxy_wrap_reports_an_unexpected_exception_as_failure(tmp_path: Path) -> None:
    class _Proxy:
        def replay(self, session_id: str, flow_id: str) -> dict[str, Any]:
            raise RuntimeError("mitmproxy loop gone")

    service = _Service(_Proxy(), tmp_path)
    session_id = _session(service)
    result = service.proxy_replay(session_id, "f1")
    assert result.ok is False
    assert result.error is not None


# ----------------------------------------------------------------------
# proxy_flow_get registers spilled bodies under their own part.
# ----------------------------------------------------------------------
def test_flow_get_registers_a_spilled_body_under_its_part(tmp_path: Path) -> None:
    body = tmp_path / "spilled.bin"
    body.write_bytes(b"\x00\x01\x02")

    class _Proxy:
        def flow_get(self, session_id: str, flow_id: str, artifact_dir: Path) -> dict[str, Any]:
            return {
                "id": flow_id,
                "request": {"method": "POST", "url": "http://x", "body_path": str(body)},
                "response": {"status": 200},
            }

    service = _Service(_Proxy(), tmp_path)
    session_id = _session(service)
    result = service.proxy_flow_get(session_id, "f1")
    assert result.ok is True
    assert result.data is not None
    assert result.data["request"]["artifact_id"] == "artifact-1"


def test_flow_get_carries_an_artifact_error_when_registration_fails(tmp_path: Path) -> None:
    """Registration must never fail the fetch; the failure travels in the part."""
    body = tmp_path / "spilled.bin"
    body.write_bytes(b"\x00")

    class _FailingRepo(_Repo):
        def register_artifact(self, **fields: Any) -> dict[str, Any]:
            raise RuntimeError("artifact store offline")

    class _Proxy:
        def flow_get(self, session_id: str, flow_id: str, artifact_dir: Path) -> dict[str, Any]:
            return {
                "id": flow_id,
                "request": {"method": "POST", "url": "http://x", "body_path": str(body)},
                "response": {"status": 200},
            }

    service = _Service(_Proxy(), tmp_path)
    service.repository = _FailingRepo()
    session_id = _session(service)
    result = service.proxy_flow_get(session_id, "f1")
    assert result.ok is True
    assert result.data is not None
    assert "artifact_error" in result.data["request"]
    assert "artifact_id" not in result.data["request"]


def test_flow_get_reports_an_unexpected_exception(tmp_path: Path) -> None:
    class _Proxy:
        def flow_get(self, session_id: str, flow_id: str, artifact_dir: Path) -> dict[str, Any]:
            raise RuntimeError("recorder corrupted")

    service = _Service(_Proxy(), tmp_path)
    session_id = _session(service)
    result = service.proxy_flow_get(session_id, "f1")
    assert result.ok is False
    assert result.error is not None


def test_flow_get_rejects_an_unsafe_session_id(tmp_path: Path) -> None:
    class _Proxy:
        def flow_get(  # pragma: no cover - must not be reached
            self, session_id: str, flow_id: str, artifact_dir: Path
        ) -> dict[str, Any]:
            return {}

    service = _Service(_Proxy(), tmp_path)
    result = service.proxy_flow_get("../escape", "f1")
    assert result.ok is False
    assert result.error is not None


def test_flow_get_maps_a_backend_error(tmp_path: Path) -> None:
    class _Proxy:
        def flow_get(self, session_id: str, flow_id: str, artifact_dir: Path) -> dict[str, Any]:
            raise ProxyError("not_found", "unknown flow id", flow_id=flow_id)

    service = _Service(_Proxy(), tmp_path)
    session_id = _session(service)
    result = service.proxy_flow_get(session_id, "missing")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "not_found"


# ----------------------------------------------------------------------
# proxy_export_har.
# ----------------------------------------------------------------------
def test_export_har_registers_the_artifact(tmp_path: Path) -> None:
    class _Proxy:
        def export_har(self, session_id: str, out_path: Path) -> dict[str, Any]:
            out_path.write_text("{}")
            return {"path": str(out_path), "entry_count": 0}

    service = _Service(_Proxy(), tmp_path)
    session_id = _session(service)
    result = service.proxy_export_har(session_id)
    assert result.ok is True
    assert result.data is not None
    assert result.data["artifact_id"] == "artifact-1"


def test_export_har_reports_an_unexpected_exception(tmp_path: Path) -> None:
    class _Proxy:
        def export_har(self, session_id: str, out_path: Path) -> dict[str, Any]:
            raise RuntimeError("serializer crashed")

    service = _Service(_Proxy(), tmp_path)
    session_id = _session(service)
    result = service.proxy_export_har(session_id)
    assert result.ok is False
    assert result.error is not None


def test_export_har_maps_a_too_large_error(tmp_path: Path) -> None:
    class _Proxy:
        def export_har(self, session_id: str, out_path: Path) -> dict[str, Any]:
            raise ProxyError("too_large", "HAR export exceeds capture cap")

    service = _Service(_Proxy(), tmp_path)
    session_id = _session(service)
    result = service.proxy_export_har(session_id)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "too_large"


# ----------------------------------------------------------------------
# proxy_ca_install_android.
# ----------------------------------------------------------------------
class _CaProxy:
    def __init__(self, cert: Path | None) -> None:
        self._cert = cert

    def ca_cert_path(self) -> Path | None:
        return self._cert


def test_ca_install_pushes_the_cert_and_names_the_remote_path(tmp_path: Path) -> None:
    cert = tmp_path / "mitmproxy-ca-cert.pem"
    cert.write_text("cert")
    pushed: list[tuple[str, str, str]] = []

    class _Adb:
        def push(self, serial: str, local: str, remote: str) -> None:
            pushed.append((serial, local, remote))

    service = _Service(_CaProxy(cert), tmp_path)
    service._adb_backend = _Adb()  # type: ignore[attr-defined]
    session_id = _session(service)
    result = service.proxy_ca_install_android(session_id, serial="emulator-5554")
    assert result.ok is True
    assert result.data is not None
    assert result.data["pushed_to"].endswith("mitmproxy-ca-cert.pem")
    assert pushed and pushed[0][0] == "emulator-5554"


def test_ca_install_without_a_generated_ca_reports_not_found(tmp_path: Path) -> None:
    service = _Service(_CaProxy(None), tmp_path)
    session_id = _session(service)
    result = service.proxy_ca_install_android(session_id, serial="emulator-5554")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "not_found"


def test_ca_install_on_a_closed_session_fails(tmp_path: Path) -> None:
    from headless_re_mcp.core.models import SessionState

    cert = tmp_path / "mitmproxy-ca-cert.pem"
    cert.write_text("cert")
    service = _Service(_CaProxy(cert), tmp_path)
    session_id = _session(service)
    service.registry.transition(session_id, SessionState.CLOSING)
    service.registry.transition(session_id, SessionState.CLOSED)
    result = service.proxy_ca_install_android(session_id, serial="emulator-5554")
    assert result.ok is False


def test_ca_install_stops_when_the_session_closes_after_the_push(tmp_path: Path) -> None:
    """A close arriving after the push must be reported, not swallowed as ok."""
    from headless_re_mcp.core.models import SessionState

    cert = tmp_path / "mitmproxy-ca-cert.pem"
    cert.write_text("cert")
    service_ref: dict[str, Any] = {}

    class _Adb:
        def push(self, serial: str, local: str, remote: str) -> None:
            service = service_ref["service"]
            sid = service_ref["session_id"]
            service.registry.transition(sid, SessionState.CLOSING)
            service.registry.transition(sid, SessionState.CLOSED)

    service = _Service(_CaProxy(cert), tmp_path)
    service._adb_backend = _Adb()  # type: ignore[attr-defined]
    session_id = _session(service)
    service_ref["service"] = service
    service_ref["session_id"] = session_id
    result = service.proxy_ca_install_android(session_id, serial="emulator-5554")
    assert result.ok is False


def test_ca_install_maps_an_adb_error(tmp_path: Path) -> None:
    cert = tmp_path / "mitmproxy-ca-cert.pem"
    cert.write_text("cert")

    class _Adb:
        def push(self, serial: str, local: str, remote: str) -> None:
            raise AdbError("device_offline", "device not found")

    service = _Service(_CaProxy(cert), tmp_path)
    service._adb_backend = _Adb()  # type: ignore[attr-defined]
    session_id = _session(service)
    result = service.proxy_ca_install_android(session_id, serial="emulator-5554")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "device_offline"
