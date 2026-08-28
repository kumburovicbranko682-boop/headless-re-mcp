"""frida.spawn / frida.server.ensure must land in the durable audit log.

These two are device-state mutations of the same class as device.launch /
device.install: spawn launches a process under instrumentation, server.ensure
pushes and starts a frida-server binary on the device. The device.* mutations
already audit; the frida path did not, so the device-mutation audit trail was
incomplete. Unlike device.* these run inside a session, so they also own a
timeline entry -- but the timeline is trimmed with the session while the audit
log survives cross-session, which is exactly why ui.drive audits alongside its
timeline entry. These pin that each mutation records a session-scoped audit
entry (visible both when the listing is filtered to its session and unfiltered),
that a failure is recorded with its error code, that pure enumerations are not
audited, and that an audit-write failure never fails the mutation itself.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.frida.client import FridaError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

JsonObject = dict[str, Any]


def _write_minimal_pe(path: Path) -> None:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = (0x8664).to_bytes(2, "little")
    path.write_bytes(image)


def _open_session(tmp_path: Path) -> tuple[AnalysisService, str]:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None, created.error
    session_id = created.data["session"]["id"]
    return service, session_id


def _authorize_device(service: AnalysisService, session_id: str) -> None:
    service.registry.update_metadata(
        session_id,
        {"frida_authorized": {"device_id": "usb", "pids": [], "packages": []}},
    )


def _entries(service: AnalysisService) -> list[JsonObject]:
    result = service.audit_list(None)
    assert result.ok and result.data is not None
    return list(result.data["entries"])


def _by_action(service: AnalysisService, action: str) -> list[JsonObject]:
    return [e for e in _entries(service) if e["action"] == action]


class _FakeClient:
    """A FridaClient stand-in for the device-scoped calls the service makes."""

    def spawn(self, device_id: Any, package: str) -> JsonObject:
        del device_id
        return {"package": package, "pid": 4242, "device": "usb"}

    def applications(self, device_id: Any, offset: int = 0, limit: int = 256) -> JsonObject:
        del device_id, offset, limit
        return {"applications": [], "count": 0}


class _FakeAdbServer:
    """Minimal adb backend exposing only ensure_frida_server."""

    def ensure_frida_server(
        self,
        serial: str,
        server_binary: str | None = None,
        port: int = 27042,
        bind_host: str = "127.0.0.1",
    ) -> JsonObject:
        del serial, server_binary, bind_host
        return {"running": True, "pushed": True, "port": port}


def test_frida_spawn_audits_the_launch(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.core.service_frida.FridaClient",
        lambda *a, **k: _FakeClient(),
    )
    service, session_id = _open_session(tmp_path)
    try:
        _authorize_device(service, session_id)
        result = service.frida_spawn(session_id, "com.example.app")
        assert result.ok is True, result.error

        entry = _by_action(service, "frida.spawn")[0]
        # Session-scoped, unlike the serial-keyed device.* rows.
        assert entry["session_id"] == session_id
        assert entry["ok"] == 1
        assert entry["params_summary"] == {"package": "com.example.app"}
        assert entry["result_summary"] == {"pid": 4242}
    finally:
        service.close_all()


def test_frida_server_ensure_audits_the_push_and_start(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.core.service_frida.FridaClient",
        lambda *a, **k: _FakeClient(),
    )
    service, session_id = _open_session(tmp_path)
    try:
        service._adb_backend = _FakeAdbServer()  # type: ignore[attr-defined]
        result = service.frida_server_ensure(session_id, "emulator-5554", port=27042)
        assert result.ok is True, result.error

        entry = _by_action(service, "frida.server.ensure")[0]
        assert entry["session_id"] == session_id
        assert entry["ok"] == 1
        assert entry["params_summary"] == {"serial": "emulator-5554", "port": 27042}
        assert entry["result_summary"] == {"running": True, "pushed": True, "port": 27042}
    finally:
        service.close_all()


def test_frida_spawn_writes_a_session_timeline_entry(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """spawn records to BOTH the durable audit and the session timeline.

    The two are deliberately distinct: the audit line survives cross-session (it
    is the device-mutation trail), while the timeline entry is the session's own
    record and is trimmed with it -- which is exactly why the mutation writes both
    rather than one. Every audit assertion above would still pass if the
    ``_timeline_append`` call were dropped, silently losing the session-scoped
    spawn record; this pins the timeline half, with the package and resulting pid
    in its details, so the dual-write cannot quietly become a single write.
    """
    monkeypatch.setattr(
        "headless_re_mcp.core.service_frida.FridaClient",
        lambda *a, **k: _FakeClient(),
    )
    service, session_id = _open_session(tmp_path)
    try:
        _authorize_device(service, session_id)
        result = service.frida_spawn(session_id, "com.example.app")
        assert result.ok is True, result.error

        timeline = service.timeline_list(session_id)
        assert timeline.ok and timeline.data is not None
        spawn_events = [
            event for event in timeline.data["events"] if event["event"] == "frida.spawn"
        ]
        assert len(spawn_events) == 1, "spawn must own exactly one timeline entry"
        details = spawn_events[0]["details"]
        assert details["package"] == "com.example.app"
        assert details["pid"] == 4242
    finally:
        service.close_all()


def test_a_failed_frida_mutation_is_audited_with_its_code(
    tmp_path: Path, monkeypatch: Any
) -> None:
    class _Boom(_FakeClient):
        def spawn(self, device_id: Any, package: str) -> JsonObject:
            raise FridaError("backend_error", "spawn failed", package=package)

    monkeypatch.setattr(
        "headless_re_mcp.core.service_frida.FridaClient",
        lambda *a, **k: _Boom(),
    )
    service, session_id = _open_session(tmp_path)
    try:
        _authorize_device(service, session_id)
        result = service.frida_spawn(session_id, "com.example.app")
        assert result.ok is False

        entry = _by_action(service, "frida.spawn")[0]
        assert entry["ok"] == 0
        assert entry["result_summary"] == {"code": "backend_error"}
    finally:
        service.close_all()


def test_frida_enumerations_are_not_audited(tmp_path: Path, monkeypatch: Any) -> None:
    """applications reads and mutates nothing, so it leaves no audit entry."""
    monkeypatch.setattr(
        "headless_re_mcp.core.service_frida.FridaClient",
        lambda *a, **k: _FakeClient(),
    )
    service, session_id = _open_session(tmp_path)
    try:
        _authorize_device(service, session_id)
        service.frida_applications(session_id)
        assert [e for e in _entries(service) if str(e["action"]).startswith("frida.")] == []
    finally:
        service.close_all()


def test_frida_mutation_audit_is_visible_filtered_to_its_session(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The entry carries the real session_id, so a session-filtered listing --
    the durable record that outlives the session's own trimmed timeline -- shows
    it, distinguishing it from the serial-keyed, session-less device.* rows."""
    monkeypatch.setattr(
        "headless_re_mcp.core.service_frida.FridaClient",
        lambda *a, **k: _FakeClient(),
    )
    service, session_id = _open_session(tmp_path)
    try:
        _authorize_device(service, session_id)
        service.frida_spawn(session_id, "com.example.app")

        scoped = service.audit_list(session_id)
        assert scoped.ok and scoped.data is not None
        assert any(e["action"] == "frida.spawn" for e in scoped.data["entries"])
    finally:
        service.close_all()


def test_an_audit_write_failure_does_not_fail_the_frida_spawn(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The process is already spawned on the device; a bookkeeping failure in
    the audit write must not turn that into a failed tool call."""
    monkeypatch.setattr(
        "headless_re_mcp.core.service_frida.FridaClient",
        lambda *a, **k: _FakeClient(),
    )
    service, session_id = _open_session(tmp_path)
    try:
        _authorize_device(service, session_id)

        def _boom(**kwargs: Any) -> None:
            raise RuntimeError("audit store is down")

        # Only append_audit raises; append_timeline stays intact so the spawn's
        # own timeline entry (and the success path) still runs.
        monkeypatch.setattr(service.repository, "append_audit", _boom)
        result = service.frida_spawn(session_id, "com.example.app")
        assert result.ok is True
        assert result.data is not None
        assert result.data["pid"] == 4242
    finally:
        service.close_all()
