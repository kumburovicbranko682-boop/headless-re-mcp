"""proxy.start's service wrapper: success, mid-start rollback, and error mapping.

proxy.start carries a resource-leak guard that nothing exercised: after
mitmproxy binds its port it re-checks the session, and if a close raced in
during the bind it stops the just-started proxy before failing, so a session
that died mid-start cannot leave a bound port that nothing tracks and nothing
can ever stop. That block (and the ProxyError->envelope mapping around it) was
the largest untested span on the proxy line. These pin the guard end to end,
the backend-error envelope for start and stop, and the CA-not-found path -- all
at the service layer, where the timeline/backend bookkeeping and the fail-closed
envelope live, rather than in the backend the other proxy tests drive.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.proxy import ProxyError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import SessionState
from headless_re_mcp.core.service import AnalysisService

JsonObject = dict[str, Any]


def _write_minimal_pe(path: Path) -> None:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = (0x8664).to_bytes(2, "little")
    path.write_bytes(image)


class _FakeProxy:
    """A ProxyBackend stand-in for the start/stop/CA calls the service makes."""

    def __init__(self) -> None:
        self.started = False
        self.stopped = False
        self.start_fail = False
        self.stop_fail = False
        self.cert: Path | None = None
        # Fires between the bind and the service's post-bind session re-check, so
        # a test can make a close race in exactly where the guard must catch it.
        self.on_start: Callable[[], None] | None = None

    def start(self, session_id: str, host: str = "127.0.0.1", port: int = 8080) -> JsonObject:
        if self.start_fail:
            raise ProxyError("backend_error", "bind failed", port=port)
        self.started = True
        if self.on_start is not None:
            self.on_start()
        return {"endpoint": f"{host}:{port}", "port": port}

    def stop(self, session_id: str) -> JsonObject:
        self.stopped = True
        if self.stop_fail:
            raise ProxyError("backend_error", "stop failed")
        return {"stopped": True}

    def ca_cert_path(self) -> Path | None:
        return self.cert

    def close_all(self) -> None:  # close_all() calls this unguarded
        pass


class _FakeAdb:
    """Minimal adb backend: records the CA push and can fire a hook mid-push."""

    def __init__(self) -> None:
        self.pushed = False
        # Fires during the push, between it and the service's post-push session
        # re-check, to model a close racing in after the cert is already on-device.
        self.on_push: Callable[[], None] | None = None

    def push(self, serial: str, local: str, remote: str) -> None:
        self.pushed = True
        if self.on_push is not None:
            self.on_push()


def _open(tmp_path: Path) -> tuple[AnalysisService, str, _FakeProxy]:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    fake = _FakeProxy()
    service._proxy_backend = fake  # type: ignore[attr-defined]
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None, created.error
    return service, created.data["session"]["id"], fake


def _timeline(service: AnalysisService, session_id: str) -> list[JsonObject]:
    result = service.timeline_list(session_id)
    assert result.ok and result.data is not None, result.error
    return list(result.data["events"])


def test_proxy_start_records_backend_and_timeline(tmp_path: Path) -> None:
    service, session_id, fake = _open(tmp_path)
    try:
        result = service.proxy_start(session_id, port=8081)
        assert result.ok is True, result.error
        assert fake.started is True and fake.stopped is False

        events = [e for e in _timeline(service, session_id) if e["event"] == "proxy.start"]
        assert len(events) == 1
        assert events[0]["details"] == {"port": 8081}
    finally:
        service.close_all()


def test_proxy_start_rolls_back_when_session_dies_mid_start(tmp_path: Path) -> None:
    service, session_id, fake = _open(tmp_path)
    try:
        # The bind "succeeds", but a close races in before the post-bind re-check.
        fake.on_start = lambda: service.registry.transition(session_id, SessionState.FAILED)
        result = service.proxy_start(session_id, port=8081)

        assert result.ok is False
        assert result.error is not None
        # The just-started proxy must be stopped so no bound port leaks onto a
        # session that no longer exists.
        assert fake.started is True and fake.stopped is True
        # ...and no misleading "started" mark for a start that was rolled back.
        assert [e for e in _timeline(service, session_id) if e["event"] == "proxy.start"] == []
    finally:
        service.close_all()


def test_proxy_start_maps_backend_error_to_envelope(tmp_path: Path) -> None:
    service, session_id, fake = _open(tmp_path)
    try:
        fake.start_fail = True
        result = service.proxy_start(session_id)

        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "backend_error"
        # A failed bind never reached the re-check, so stop must not be called.
        assert fake.stopped is False
    finally:
        service.close_all()


def test_proxy_stop_success_and_error_both_answer_with_an_envelope(tmp_path: Path) -> None:
    service, session_id, fake = _open(tmp_path)
    try:
        ok = service.proxy_stop(session_id)
        assert ok.ok is True, ok.error
        assert fake.stopped is True
        stops = [e for e in _timeline(service, session_id) if e["event"] == "proxy.stop"]
        assert len(stops) == 1

        fake.stop_fail = True
        bad = service.proxy_stop(session_id)
        assert bad.ok is False
        assert bad.error is not None
        assert bad.error.code == "backend_error"
    finally:
        service.close_all()


def test_ca_install_reports_missing_ca(tmp_path: Path) -> None:
    service, session_id, fake = _open(tmp_path)
    try:
        fake.cert = None  # ~/.mitmproxy CA has not been generated yet
        result = service.proxy_ca_install_android(session_id, "emulator-5554")

        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "not_found"
    finally:
        service.close_all()


def test_ca_install_refuses_on_an_already_closed_session(tmp_path: Path) -> None:
    """The entry guard fails closed before touching the CA or the device."""
    service, session_id, fake = _open(tmp_path)
    try:
        fake.cert = tmp_path / "ca.pem"
        fake.cert.write_text("cert")
        service.registry.transition(session_id, SessionState.FAILED)

        result = service.proxy_ca_install_android(session_id, "emulator-5554")
        assert result.ok is False
        assert result.error is not None
        # It bailed at the entry check, so the CA path was never consulted.
        assert fake.cert is not None  # ca_cert_path never reached to matter
    finally:
        service.close_all()


def test_ca_install_refuses_to_record_when_session_dies_mid_push(tmp_path: Path) -> None:
    """The cert is already on-device, but a close that raced in during the push
    must stop the tool from recording the install onto a session that is gone --
    and must leave no misleading 'CA pushed' timeline entry."""
    service, session_id, fake = _open(tmp_path)
    try:
        fake.cert = tmp_path / "ca.pem"
        fake.cert.write_text("cert")
        fake_adb = _FakeAdb()
        fake_adb.on_push = lambda: service.registry.transition(session_id, SessionState.FAILED)
        service._adb_backend = fake_adb  # type: ignore[attr-defined]

        result = service.proxy_ca_install_android(session_id, "emulator-5554")
        assert result.ok is False
        assert result.error is not None
        assert fake_adb.pushed is True
        assert [
            e
            for e in _timeline(service, session_id)
            if e["event"] == "proxy.ca.install_android"
        ] == []
    finally:
        service.close_all()
