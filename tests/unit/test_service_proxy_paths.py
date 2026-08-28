"""ProxyAnalysisMixin: success, mid-flight rollback and error envelopes.

These drive the service-level proxy methods through a real AnalysisService with
the mitmproxy (and, for the CA push, adb) backend faked out, so the parts the
backend-only tests never reach -- the state re-checks that run *after* the
backend call, the artifact registration of a spilled body / HAR, and each
except arm -- are exercised without a live proxy.

The re-checks matter for an unattended run: a session that another thread closes
while proxy.start is binding a port, or while proxy.ca.install pushes a cert,
must roll the half-done work back (stop the just-started proxy) and answer with
a state error, not report a proxy running against a session that is gone.
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


@pytest.fixture
def service(tmp_path: Path) -> Any:
    svc = AnalysisService(replace(Settings.load(), artifact_root=tmp_path / "artifacts"))
    try:
        yield svc
    finally:
        svc.close_all()


def _web_session(service: Any) -> str:
    created = service.create_session("https://example.com/app", target="web")
    assert created.data is not None
    return str(created.data["session"]["id"])


def test_proxy_start_success_records_the_endpoint(service: Any, monkeypatch: Any) -> None:
    """A clean start returns the backend payload and records the backend/timeline."""
    session_id = _web_session(service)
    monkeypatch.setattr(
        service._proxy_backend,
        "start",
        lambda sid, host="127.0.0.1", port=8080: {
            "running": True,
            "host": host,
            "port": port,
            "endpoint": f"{host}:{port}",
        },
    )

    result = service.proxy_start(session_id, port=8081)

    assert result.ok, result.error
    assert result.data is not None
    assert result.data["endpoint"] == "127.0.0.1:8081"


def test_proxy_start_rolls_back_when_the_session_closes_mid_start(
    service: Any, monkeypatch: Any
) -> None:
    """A session closed between the guard and the bind stops the proxy and fails.

    The port was bound before the second state check saw CLOSED, so leaving it
    would leak a listener nothing can ever stop -- the mixin stops it and returns
    a state error instead of a running proxy.
    """
    session_id = _web_session(service)
    stopped: list[str] = []

    def fake_start(sid: str, host: str = "127.0.0.1", port: int = 8080) -> dict[str, Any]:
        service.registry.transition(sid, SessionState.FAILED)
        return {"running": True, "host": host, "port": port, "endpoint": f"{host}:{port}"}

    def fake_stop(sid: str) -> dict[str, Any]:
        stopped.append(sid)
        return {}

    monkeypatch.setattr(service._proxy_backend, "start", fake_start)
    monkeypatch.setattr(service._proxy_backend, "stop", fake_stop)

    result = service.proxy_start(session_id)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "invalid_request"
    assert stopped == [session_id]


def test_proxy_start_maps_a_proxy_error(service: Any, monkeypatch: Any) -> None:
    """A backend refusal (port already bound) comes back with its own code."""
    session_id = _web_session(service)

    def boom(sid: str, host: str = "127.0.0.1", port: int = 8080) -> dict[str, Any]:
        raise ProxyError("invalid_state", "port is already in use", host=host, port=port)

    monkeypatch.setattr(service._proxy_backend, "start", boom)

    result = service.proxy_start(session_id)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "invalid_state"


def test_proxy_stop_success(service: Any, monkeypatch: Any) -> None:
    session_id = _web_session(service)
    monkeypatch.setattr(service._proxy_backend, "stop", lambda sid: {"stopped": True})

    result = service.proxy_stop(session_id)

    assert result.ok, result.error
    assert result.data == {"stopped": True}


def test_proxy_stop_maps_a_proxy_error(service: Any, monkeypatch: Any) -> None:
    session_id = _web_session(service)

    def boom(sid: str) -> dict[str, Any]:
        raise ProxyError("invalid_state", "no proxy running")

    monkeypatch.setattr(service._proxy_backend, "stop", boom)

    result = service.proxy_stop(session_id)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "invalid_state"


def test_proxy_stop_maps_an_unexpected_error(service: Any, monkeypatch: Any) -> None:
    session_id = _web_session(service)

    def boom(sid: str) -> dict[str, Any]:
        raise ValueError("wat")

    monkeypatch.setattr(service._proxy_backend, "stop", boom)

    result = service.proxy_stop(session_id)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "invalid_request"


def test_proxy_flow_get_skips_a_non_dict_part_and_registers_a_spilled_body(
    service: Any, monkeypatch: Any, tmp_path: Path
) -> None:
    """A None request part is skipped; a response with a spilled body is registered.

    The artifact id hangs off the response part, never the top level, so a
    request body and a response body can never overwrite one another's id.
    """
    session_id = _web_session(service)

    def fake_flow_get(sid: str, fid: str, artifact_dir: Path) -> dict[str, Any]:
        artifact_dir.mkdir(parents=True, exist_ok=True)
        dest = artifact_dir / "flow-body.bin"
        dest.write_bytes(bytes(range(64)))
        return {
            "id": fid,
            "request": None,
            "response": {
                "status": 200,
                "headers": {},
                "size": 64,
                "body_path": str(dest),
                "spill_reason": "binary",
            },
        }

    monkeypatch.setattr(service._proxy_backend, "flow_get", fake_flow_get)

    result = service.proxy_flow_get(session_id, "f1")

    assert result.ok, result.error
    assert result.data is not None
    assert "artifact_id" not in result.data
    assert result.data["response"]["artifact_id"]


def test_proxy_flow_get_reports_an_artifact_error_without_failing(
    service: Any, monkeypatch: Any
) -> None:
    """Registration failing must not fail the fetch; the file exists either way."""
    session_id = _web_session(service)

    def fake_flow_get(sid: str, fid: str, artifact_dir: Path) -> dict[str, Any]:
        artifact_dir.mkdir(parents=True, exist_ok=True)
        dest = artifact_dir / "flow-body.bin"
        dest.write_bytes(b"\x00\x01")
        return {
            "id": fid,
            "request": {"method": "GET", "url": "http://x/i", "headers": {}, "size": 0, "body": ""},
            "response": {"status": 200, "headers": {}, "size": 2, "body_path": str(dest)},
        }

    def boom(**fields: Any) -> dict[str, Any]:
        raise RuntimeError("store offline")

    monkeypatch.setattr(service._proxy_backend, "flow_get", fake_flow_get)
    monkeypatch.setattr(service, "record_artifact", boom)

    result = service.proxy_flow_get(session_id, "f1")

    assert result.ok, result.error
    assert result.data is not None
    assert "store offline" in result.data["response"]["artifact_error"]


def test_proxy_flow_get_leaves_a_body_path_that_is_not_on_disk_untouched(
    service: Any, monkeypatch: Any
) -> None:
    """A body_path the backend named but never wrote registers as neither.

    _register_capture no-ops on a missing file (the capture must not fail over
    bookkeeping), so the part keeps its body_path and gains no artifact id or
    error -- the defensive path opposite the successful and errored ones.
    """
    session_id = _web_session(service)

    def fake_flow_get(sid: str, fid: str, artifact_dir: Path) -> dict[str, Any]:
        return {
            "id": fid,
            "request": {"method": "GET", "url": "http://x/i", "headers": {}, "size": 0, "body": ""},
            "response": {
                "status": 200,
                "headers": {},
                "size": 7,
                "body_path": str(artifact_dir / "never-written.bin"),
            },
        }

    monkeypatch.setattr(service._proxy_backend, "flow_get", fake_flow_get)

    result = service.proxy_flow_get(session_id, "f1")

    assert result.ok, result.error
    assert result.data is not None
    resp = result.data["response"]
    assert "artifact_id" not in resp
    assert "artifact_error" not in resp


def test_proxy_flow_get_maps_a_proxy_error(service: Any, monkeypatch: Any) -> None:
    session_id = _web_session(service)

    def boom(sid: str, fid: str, artifact_dir: Path) -> dict[str, Any]:
        raise ProxyError("not_found", "unknown flow id", flow_id=fid)

    monkeypatch.setattr(service._proxy_backend, "flow_get", boom)

    result = service.proxy_flow_get(session_id, "missing")

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "not_found"


def test_proxy_flow_get_maps_an_unexpected_error(service: Any, monkeypatch: Any) -> None:
    session_id = _web_session(service)

    def boom(sid: str, fid: str, artifact_dir: Path) -> dict[str, Any]:
        raise ValueError("wat")

    monkeypatch.setattr(service._proxy_backend, "flow_get", boom)

    result = service.proxy_flow_get(session_id, "f1")

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "invalid_request"


def test_proxy_export_har_registers_the_artifact(service: Any, monkeypatch: Any) -> None:
    session_id = _web_session(service)

    def fake_export(sid: str, out: Path) -> dict[str, Any]:
        out.write_text("{}", encoding="utf-8")
        return {"path": str(out), "entry_count": 0, "truncated": False, "size": 2}

    monkeypatch.setattr(service._proxy_backend, "export_har", fake_export)

    result = service.proxy_export_har(session_id)

    assert result.ok, result.error
    assert result.data is not None
    assert result.data["artifact_id"]


def test_proxy_export_har_maps_a_proxy_error(service: Any, monkeypatch: Any) -> None:
    session_id = _web_session(service)

    def boom(sid: str, out: Path) -> dict[str, Any]:
        raise ProxyError("too_large", "HAR export exceeds capture cap")

    monkeypatch.setattr(service._proxy_backend, "export_har", boom)

    result = service.proxy_export_har(session_id)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "too_large"


def test_proxy_export_har_maps_an_unexpected_error(service: Any, monkeypatch: Any) -> None:
    session_id = _web_session(service)

    def boom(sid: str, out: Path) -> dict[str, Any]:
        raise ValueError("wat")

    monkeypatch.setattr(service._proxy_backend, "export_har", boom)

    result = service.proxy_export_har(session_id)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "invalid_request"


def test_proxy_replay_records_the_flow_id_in_the_timeline(
    service: Any, monkeypatch: Any
) -> None:
    """Replay re-sends a request to the target, so it must leave a timeline row.

    Replay is an active network intervention -- it hits the target server again
    -- not a passive read, yet it went through the generic _proxy_wrap and
    recorded nothing while proxy.start/stop/export_har (even a read-to-artifact)
    all did. The row names the flow_id so the audit trail shows what was re-sent.
    """
    from headless_re_mcp.core import service_proxy

    session_id = _web_session(service)
    monkeypatch.setattr(
        service._proxy_backend,
        "replay",
        lambda sid, flow_id: {"replayed": True, "flow_id": flow_id},
    )
    rows: list[tuple[str, dict[str, object]]] = []
    real_append = service_proxy._timeline_append

    def _capture(svc: object, sid: str, event: str, message: str, **d: object) -> None:
        rows.append((event, d))
        real_append(svc, sid, event, message, **d)

    monkeypatch.setattr(service_proxy, "_timeline_append", _capture)

    result = service.proxy_replay(session_id, "flow-7")

    assert result.ok, result.error
    assert result.data == {"replayed": True, "flow_id": "flow-7"}
    assert ("proxy.replay", {"flow_id": "flow-7"}) in rows


def test_proxy_replay_maps_a_proxy_error(service: Any, monkeypatch: Any) -> None:
    session_id = _web_session(service)

    def boom(sid: str, flow_id: str) -> dict[str, Any]:
        raise ProxyError("not_found", "unknown flow id", flow_id=flow_id)

    monkeypatch.setattr(service._proxy_backend, "replay", boom)

    result = service.proxy_replay(session_id, "missing")

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "not_found"


def test_proxy_replay_maps_an_unexpected_error(service: Any, monkeypatch: Any) -> None:
    session_id = _web_session(service)

    def boom(sid: str, flow_id: str) -> dict[str, Any]:
        raise ValueError("wat")

    monkeypatch.setattr(service._proxy_backend, "replay", boom)

    result = service.proxy_replay(session_id, "flow-1")

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "invalid_request"


def test_proxy_ca_install_refuses_a_closed_session(service: Any) -> None:
    session_id = _web_session(service)
    service.registry.transition(session_id, SessionState.FAILED)

    result = service.proxy_ca_install_android(session_id, "emulator-5554")

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "invalid_request"


def test_proxy_ca_install_reports_a_missing_ca(service: Any, monkeypatch: Any) -> None:
    session_id = _web_session(service)
    monkeypatch.setattr(service._proxy_backend, "ca_cert_path", lambda: None)

    result = service.proxy_ca_install_android(session_id, "emulator-5554")

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "not_found"


def test_proxy_ca_install_pushes_the_cert(service: Any, monkeypatch: Any, tmp_path: Path) -> None:
    session_id = _web_session(service)
    cert = tmp_path / "mitmproxy-ca-cert.pem"
    cert.write_text("cert", encoding="utf-8")
    monkeypatch.setattr(service._proxy_backend, "ca_cert_path", lambda: cert)
    pushed: list[tuple[str, str, str]] = []

    class _Adb:
        def push(self, serial: str, local: str, remote: str) -> dict[str, Any]:
            pushed.append((serial, local, remote))
            return {"local": local, "remote": remote, "size": 4}

    service._adb_backend = _Adb()

    result = service.proxy_ca_install_android(session_id, "emulator-5554")

    assert result.ok, result.error
    assert result.data is not None
    assert result.data["pushed_to"] == "/data/local/tmp/mitmproxy-ca-cert.pem"
    assert pushed and pushed[0][0] == "emulator-5554"


def test_proxy_ca_install_rolls_back_when_session_closes_mid_push(
    service: Any, monkeypatch: Any, tmp_path: Path
) -> None:
    """A session closed while the cert pushes must answer with a state error."""
    session_id = _web_session(service)
    cert = tmp_path / "mitmproxy-ca-cert.pem"
    cert.write_text("cert", encoding="utf-8")
    monkeypatch.setattr(service._proxy_backend, "ca_cert_path", lambda: cert)

    class _Adb:
        def push(self, serial: str, local: str, remote: str) -> dict[str, Any]:
            service.registry.transition(session_id, SessionState.FAILED)
            return {"local": local, "remote": remote, "size": 4}

    service._adb_backend = _Adb()

    result = service.proxy_ca_install_android(session_id, "emulator-5554")

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "invalid_request"


def test_proxy_ca_install_maps_an_adb_error(service: Any, monkeypatch: Any, tmp_path: Path) -> None:
    session_id = _web_session(service)
    cert = tmp_path / "mitmproxy-ca-cert.pem"
    cert.write_text("cert", encoding="utf-8")
    monkeypatch.setattr(service._proxy_backend, "ca_cert_path", lambda: cert)

    class _Adb:
        def push(self, serial: str, local: str, remote: str) -> dict[str, Any]:
            raise AdbError("backend_error", "push failed", remote=remote)

    service._adb_backend = _Adb()

    result = service.proxy_ca_install_android(session_id, "emulator-5554")

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "backend_error"


def test_proxy_status_maps_an_unexpected_error(service: Any, monkeypatch: Any) -> None:
    """_proxy_wrap's catch-all arm turns a stray backend error into an envelope."""
    session_id = _web_session(service)

    def boom(sid: str) -> dict[str, Any]:
        raise ValueError("wat")

    monkeypatch.setattr(service._proxy_backend, "status", boom)

    result = service.proxy_status(session_id)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "invalid_request"
