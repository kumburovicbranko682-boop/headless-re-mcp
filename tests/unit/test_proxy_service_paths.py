"""Result-envelope paths of the shared proxy (mitmproxy) service mixin.

mitmproxy cannot run in CI, so these drive ``ProxyAnalysisMixin`` on a real
``AnalysisService`` with the proxy/adb backends swapped for fakes. They lock in
the envelope contract around interception: start succeeds and records the
backend, a close that lands mid-start still stops the port it bound, backend
errors come back as typed failures rather than tracebacks, flow bodies are
registered as reclaimable artifacts (and a registration failure is surfaced on
the part, not raised), HAR export is captured, and the Android CA push refuses a
closed session and a missing CA honestly.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb import AdbBackend, AdbError
from headless_re_mcp.backends.proxy import ProxyBackend, ProxyError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import SessionState
from headless_re_mcp.core.service import AnalysisService


@pytest.fixture
def service(tmp_path: Path) -> Any:
    svc = AnalysisService(replace(Settings.load(), artifact_root=tmp_path / "artifacts"))
    try:
        yield svc
    finally:
        # Tests swap in fake backends; restore real ones so close_all's
        # per-backend teardown (which is not suppressed) has the methods it
        # expects.
        svc._proxy_backend = ProxyBackend()
        svc._adb_backend = AdbBackend(getattr(svc.settings, "adb", None))
        svc.close_all()


def _web_session(service: AnalysisService) -> str:
    return service.registry.create("https://example.invalid").id


# ----------------------------------------------------------------------------
# proxy_start
# ----------------------------------------------------------------------------
def test_proxy_start_succeeds_and_records_the_backend(service: AnalysisService) -> None:
    class _Proxy:
        def start(self, session_id: str, *, host: str, port: int) -> dict[str, Any]:
            del session_id
            return {"endpoint": f"{host}:{port}", "pid": 4242}

    service._proxy_backend = _Proxy()
    sid = _web_session(service)
    result = service.proxy_start(sid, port=9091)
    assert result.ok is True
    assert result.data is not None
    assert result.data["endpoint"] == "127.0.0.1:9091"
    assert result.meta["backend"] == "proxy"


def test_proxy_start_maps_a_backend_error(service: AnalysisService) -> None:
    class _Proxy:
        def start(self, session_id: str, *, host: str, port: int) -> dict[str, Any]:
            del session_id, host, port
            raise ProxyError("port_in_use", "8080 already bound")

    service._proxy_backend = _Proxy()
    result = service.proxy_start(_web_session(service))
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "port_in_use"


def test_proxy_start_stops_the_port_when_the_session_closes_mid_start(
    service: AnalysisService,
) -> None:
    # The bind succeeds, but a concurrent close arrives before the state
    # recheck. The port it just bound must be released, not orphaned.
    class _Proxy:
        def __init__(self, svc: AnalysisService, sid: str) -> None:
            self._svc = svc
            self._sid = sid
            self.stopped = False

        def start(self, session_id: str, *, host: str, port: int) -> dict[str, Any]:
            del session_id, host, port
            self._svc.registry.transition(self._sid, SessionState.FAILED)
            return {"endpoint": "127.0.0.1:8080"}

        def stop(self, session_id: str) -> dict[str, Any]:
            del session_id
            self.stopped = True
            return {}

    sid = _web_session(service)
    proxy = _Proxy(service, sid)
    service._proxy_backend = proxy
    result = service.proxy_start(sid)
    assert result.ok is False
    assert proxy.stopped is True


# ----------------------------------------------------------------------------
# proxy_stop
# ----------------------------------------------------------------------------
def test_proxy_stop_succeeds(service: AnalysisService) -> None:
    class _Proxy:
        def stop(self, session_id: str) -> dict[str, Any]:
            del session_id
            return {"stopped": True}

    service._proxy_backend = _Proxy()
    result = service.proxy_stop(_web_session(service))
    assert result.ok is True
    assert result.data == {"stopped": True}


def test_proxy_stop_maps_a_backend_error(service: AnalysisService) -> None:
    class _Proxy:
        def stop(self, session_id: str) -> dict[str, Any]:
            del session_id
            raise ProxyError("not_running", "no proxy for session")

    service._proxy_backend = _Proxy()
    result = service.proxy_stop(_web_session(service))
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "not_running"


def test_proxy_stop_wraps_an_unexpected_error(service: AnalysisService) -> None:
    class _Proxy:
        def stop(self, session_id: str) -> dict[str, Any]:
            del session_id
            raise RuntimeError("driver crash")

    service._proxy_backend = _Proxy()
    result = service.proxy_stop(_web_session(service))
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "internal_error"


# ----------------------------------------------------------------------------
# _proxy_wrap (status/flows/replay share it)
# ----------------------------------------------------------------------------
def test_proxy_status_wraps_an_unexpected_error(service: AnalysisService) -> None:
    class _Proxy:
        def status(self, session_id: str) -> dict[str, Any]:
            del session_id
            raise RuntimeError("bus error")

    service._proxy_backend = _Proxy()
    result = service.proxy_status(_web_session(service))
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "internal_error"


def test_proxy_status_maps_a_backend_error(service: AnalysisService) -> None:
    class _Proxy:
        def status(self, session_id: str) -> dict[str, Any]:
            del session_id
            raise ProxyError("not_running", "no proxy for session")

    service._proxy_backend = _Proxy()
    result = service.proxy_status(_web_session(service))
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "not_running"


def test_proxy_flows_and_replay_pass_through(service: AnalysisService) -> None:
    class _Proxy:
        def flows(self, session_id: str, offset: int, limit: int) -> dict[str, Any]:
            del session_id
            return {"flows": [], "count": 0, "offset": offset, "limit": limit}

        def replay(self, session_id: str, flow_id: str) -> dict[str, Any]:
            del session_id
            return {"replayed": flow_id}

    service._proxy_backend = _Proxy()
    sid = _web_session(service)
    flows = service.proxy_flows(sid, offset=5, limit=20)
    assert flows.ok is True
    assert flows.data == {"flows": [], "count": 0, "offset": 5, "limit": 20}
    replay = service.proxy_replay(sid, "flow-9")
    assert replay.ok is True
    assert replay.data == {"replayed": "flow-9"}


# ----------------------------------------------------------------------------
# proxy_flow_get
# ----------------------------------------------------------------------------
def test_proxy_flow_get_registers_a_body_and_skips_non_dict_parts(
    service: AnalysisService,
) -> None:
    class _Proxy:
        def flow_get(self, session_id: str, flow_id: str, out_dir: Path) -> dict[str, Any]:
            del session_id
            body = Path(out_dir) / "request-body.bin"
            body.write_bytes(b"hello")
            return {
                "id": flow_id,
                "request": {"body_path": str(body)},
                # A flow with no response yet: the response part is not a dict,
                # so the loop must skip it rather than choke.
                "response": None,
            }

    service._proxy_backend = _Proxy()
    result = service.proxy_flow_get(_web_session(service), "flow-1")
    assert result.ok is True
    assert result.data is not None
    assert "artifact_id" in result.data["request"]
    assert result.data["response"] is None


def test_proxy_flow_get_surfaces_a_registration_failure_on_the_part(
    service: AnalysisService, monkeypatch: Any
) -> None:
    def _boom(*args: Any, **kwargs: Any) -> None:
        del args, kwargs
        raise OSError("artifact store unavailable")

    monkeypatch.setattr("headless_re_mcp.core.service_ext._record_artifact", _boom)

    class _Proxy:
        def flow_get(self, session_id: str, flow_id: str, out_dir: Path) -> dict[str, Any]:
            del session_id
            body = Path(out_dir) / "response-body.bin"
            body.write_bytes(b"data")
            return {"id": flow_id, "request": None, "response": {"body_path": str(body)}}

    service._proxy_backend = _Proxy()
    result = service.proxy_flow_get(_web_session(service), "flow-2")
    assert result.ok is True
    assert result.data is not None
    # Registration failed, so the part carries the reason instead of an id and
    # the call still succeeds -- the body file is on disk either way.
    assert "artifact_error" in result.data["response"]
    assert "artifact_id" not in result.data["response"]


def test_proxy_flow_get_skips_a_part_without_a_body_path(service: AnalysisService) -> None:
    class _Proxy:
        def flow_get(self, session_id: str, flow_id: str, out_dir: Path) -> dict[str, Any]:
            del session_id, out_dir
            # A dict part that never spilled a body: no body_path to register.
            return {"id": flow_id, "request": {"headers": {}}, "response": {"body_path": ""}}

    service._proxy_backend = _Proxy()
    result = service.proxy_flow_get(_web_session(service), "flow-3")
    assert result.ok is True
    assert result.data is not None
    assert "artifact_id" not in result.data["request"]
    assert "artifact_id" not in result.data["response"]


def test_proxy_flow_get_maps_a_backend_error(service: AnalysisService) -> None:
    class _Proxy:
        def flow_get(self, session_id: str, flow_id: str, out_dir: Path) -> dict[str, Any]:
            del session_id, flow_id, out_dir
            raise ProxyError("not_found", "no such flow")

    service._proxy_backend = _Proxy()
    result = service.proxy_flow_get(_web_session(service), "missing")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "not_found"


def test_proxy_flow_get_wraps_an_unexpected_error(service: AnalysisService) -> None:
    class _Proxy:
        def flow_get(self, session_id: str, flow_id: str, out_dir: Path) -> dict[str, Any]:
            del session_id, flow_id, out_dir
            raise RuntimeError("decode crash")

    service._proxy_backend = _Proxy()
    result = service.proxy_flow_get(_web_session(service), "flow-4")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "internal_error"


# ----------------------------------------------------------------------------
# proxy_export_har
# ----------------------------------------------------------------------------
def test_proxy_export_har_captures_the_file(service: AnalysisService) -> None:
    class _Proxy:
        def export_har(self, session_id: str, out: Path) -> dict[str, Any]:
            del session_id
            Path(out).write_text("{}", encoding="utf-8")
            return {"flows": 3}

    service._proxy_backend = _Proxy()
    result = service.proxy_export_har(_web_session(service))
    assert result.ok is True
    assert result.data is not None
    assert result.data["flows"] == 3
    assert "artifact_id" in result.data


def test_proxy_export_har_maps_a_backend_error(service: AnalysisService) -> None:
    class _Proxy:
        def export_har(self, session_id: str, out: Path) -> dict[str, Any]:
            del session_id, out
            raise ProxyError("not_running", "start the proxy first")

    service._proxy_backend = _Proxy()
    result = service.proxy_export_har(_web_session(service))
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "not_running"


def test_proxy_export_har_wraps_an_unexpected_error(service: AnalysisService) -> None:
    class _Proxy:
        def export_har(self, session_id: str, out: Path) -> dict[str, Any]:
            del session_id, out
            raise RuntimeError("writer crash")

    service._proxy_backend = _Proxy()
    result = service.proxy_export_har(_web_session(service))
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "internal_error"


# ----------------------------------------------------------------------------
# proxy_ca_install_android
# ----------------------------------------------------------------------------
def test_ca_install_refuses_a_closed_session(service: AnalysisService) -> None:
    sid = _web_session(service)
    service.registry.transition(sid, SessionState.FAILED)
    result = service.proxy_ca_install_android(sid, "emulator-5554")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "invalid_request"


def test_ca_install_reports_a_missing_ca(service: AnalysisService) -> None:
    class _Proxy:
        def ca_cert_path(self) -> Path | None:
            return None

    service._proxy_backend = _Proxy()
    result = service.proxy_ca_install_android(_web_session(service), "emulator-5554")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "not_found"


def test_ca_install_pushes_then_refuses_a_session_that_closed_mid_push(
    service: AnalysisService, tmp_path: Path
) -> None:
    cert = tmp_path / "mitmproxy-ca-cert.pem"
    cert.write_text("-----BEGIN CERTIFICATE-----", encoding="utf-8")
    sid = _web_session(service)

    class _Proxy:
        def ca_cert_path(self) -> Path:
            return cert

    class _Adb:
        def __init__(self, svc: AnalysisService, target: str) -> None:
            self._svc = svc
            self._target = target
            self.pushed = False

        def push(self, serial: str, local: str, remote: str) -> None:
            del serial, local, remote
            self.pushed = True
            self._svc.registry.transition(self._target, SessionState.FAILED)

    adb = _Adb(service, sid)
    service._proxy_backend = _Proxy()
    service._adb_backend = adb
    result = service.proxy_ca_install_android(sid, "emulator-5554")
    assert adb.pushed is True
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "invalid_request"


def test_ca_install_pushes_the_ca_and_names_the_push(
    service: AnalysisService, tmp_path: Path
) -> None:
    cert = tmp_path / "mitmproxy-ca-cert.pem"
    cert.write_text("-----BEGIN CERTIFICATE-----", encoding="utf-8")

    class _Proxy:
        def ca_cert_path(self) -> Path:
            return cert

    class _Adb:
        def __init__(self) -> None:
            self.args: tuple[str, str, str] | None = None

        def push(self, serial: str, local: str, remote: str) -> None:
            self.args = (serial, local, remote)

    adb = _Adb()
    service._proxy_backend = _Proxy()
    service._adb_backend = adb
    result = service.proxy_ca_install_android(_web_session(service), "emulator-5554")
    assert result.ok is True
    assert result.data is not None
    # The contract is a push, not a system-trust install.
    assert result.data["pushed_to"] == "/data/local/tmp/mitmproxy-ca-cert.pem"
    assert "installed" not in result.data
    assert adb.args == ("emulator-5554", str(cert), "/data/local/tmp/mitmproxy-ca-cert.pem")


def test_ca_install_maps_an_adb_error(service: AnalysisService, tmp_path: Path) -> None:
    cert = tmp_path / "mitmproxy-ca-cert.pem"
    cert.write_text("-----BEGIN CERTIFICATE-----", encoding="utf-8")

    class _Proxy:
        def ca_cert_path(self) -> Path:
            return cert

    class _Adb:
        def push(self, serial: str, local: str, remote: str) -> None:
            del serial, local, remote
            raise AdbError("device_offline", "adb: device offline")

    service._proxy_backend = _Proxy()
    service._adb_backend = _Adb()
    result = service.proxy_ca_install_android(_web_session(service), "emulator-5554")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "device_offline"
