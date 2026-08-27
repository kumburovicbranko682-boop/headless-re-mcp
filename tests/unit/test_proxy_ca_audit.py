"""proxy.ca.install_android must land in the durable audit log.

Pushing the mitmproxy root certificate onto a device over adb is the same class
of session-scoped device mutation as frida.server.ensure, which adb-pushes and
starts a frida-server binary -- and arguably more sensitive, since a trusted CA
is exactly what lets the proxy read the device's TLS. frida.server.ensure and
the device.* mutations already write a durable audit row that outlives the
session; the CA push had only a session timeline entry, trimmed with the
session, so the fact that a MITM cert reached a given serial did not survive
cross-session the way its sibling frida push does. Like the frida mutations it
runs inside a session, so it keeps its timeline entry and also carries the
session_id on the audit row. These pin that a successful push records a
session-scoped audit entry naming the serial and pushed path (and still keeps
its timeline entry), that a failure is recorded with its error code, and that an
audit-write failure never fails the push -- the cert is already on the device.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.adb import AdbError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

JsonObject = dict[str, Any]

_REMOTE_TMP = "/data/local/tmp/mitmproxy-ca-cert.pem"


def _write_minimal_pe(path: Path) -> None:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = (0x8664).to_bytes(2, "little")
    path.write_bytes(image)


class _FakeProxy:
    """A ProxyBackend stand-in exposing only what the CA push touches."""

    def __init__(self, cert: Path) -> None:
        self._cert = cert

    def ca_cert_path(self) -> Path:
        return self._cert

    def close_all(self) -> None:  # close_all() calls this unguarded
        pass


class _FakeAdb:
    """Minimal adb backend recording the CA push instead of shelling out."""

    def __init__(self) -> None:
        self.pushes: list[tuple[str, str, str]] = []
        self.fail = False

    def push(self, serial: str, local: str, remote: str) -> None:
        self.pushes.append((serial, local, remote))
        if self.fail:
            raise AdbError("backend_error", "adb push failed", serial=serial)


def _open_session(tmp_path: Path) -> tuple[AnalysisService, str, _FakeAdb]:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    cert = tmp_path / "mitmproxy-ca-cert.pem"
    cert.write_text("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n")
    service._proxy_backend = _FakeProxy(cert)  # type: ignore[attr-defined]
    fake_adb = _FakeAdb()
    service._adb_backend = fake_adb  # type: ignore[attr-defined]
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None, created.error
    return service, created.data["session"]["id"], fake_adb


def _entries(service: AnalysisService) -> list[JsonObject]:
    result = service.audit_list(None)
    assert result.ok and result.data is not None
    return list(result.data["entries"])


def _by_action(service: AnalysisService, action: str) -> list[JsonObject]:
    return [e for e in _entries(service) if e["action"] == action]


def _timeline_events(service: AnalysisService, session_id: str) -> list[JsonObject]:
    result = service.timeline_list(session_id)
    assert result.ok and result.data is not None, result.error
    return list(result.data["events"])


def test_ca_install_audits_the_push(tmp_path: Path) -> None:
    service, session_id, fake_adb = _open_session(tmp_path)
    try:
        result = service.proxy_ca_install_android(session_id, "emulator-5554")
        assert result.ok is True, result.error
        assert fake_adb.pushes == [(
            "emulator-5554",
            str(tmp_path / "mitmproxy-ca-cert.pem"),
            _REMOTE_TMP,
        )]

        entry = _by_action(service, "proxy.ca.install_android")[0]
        # Session-scoped, like the frida device mutations, not serial-keyed.
        assert entry["session_id"] == session_id
        assert entry["ok"] == 1
        assert entry["params_summary"] == {"serial": "emulator-5554"}
        assert entry["result_summary"] == {"pushed_to": _REMOTE_TMP}

        # The durable audit row is added alongside, not instead of, the timeline
        # entry the tool already wrote.
        pushed = [
            e
            for e in _timeline_events(service, session_id)
            if e["event"] == "proxy.ca.install_android"
        ]
        assert len(pushed) == 1
        assert pushed[0]["details"] == {"serial": "emulator-5554"}
    finally:
        service.close_all()


def test_a_failed_ca_install_is_audited_with_its_code(tmp_path: Path) -> None:
    service, session_id, fake_adb = _open_session(tmp_path)
    try:
        fake_adb.fail = True
        result = service.proxy_ca_install_android(session_id, "emulator-5554")
        assert result.ok is False
        assert result.error is not None

        entry = _by_action(service, "proxy.ca.install_android")[0]
        assert entry["ok"] == 0
        assert entry["result_summary"] == {"code": "backend_error"}
        # A failed push must not leave a misleading "pushed" timeline entry.
        assert [
            e
            for e in _timeline_events(service, session_id)
            if e["event"] == "proxy.ca.install_android"
        ] == []
    finally:
        service.close_all()


def test_ca_install_audit_visible_filtered_to_its_session(tmp_path: Path) -> None:
    """The entry carries the real session_id, so a session-filtered listing --
    the durable record that outlives the session's trimmed timeline -- shows it."""
    service, session_id, _fake_adb = _open_session(tmp_path)
    try:
        service.proxy_ca_install_android(session_id, "emulator-5554")

        scoped = service.audit_list(session_id)
        assert scoped.ok and scoped.data is not None
        assert any(e["action"] == "proxy.ca.install_android" for e in scoped.data["entries"])
    finally:
        service.close_all()


def test_an_audit_write_failure_does_not_fail_the_ca_install(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The cert is already on the device; a bookkeeping failure in the audit
    write must not turn that into a failed tool call."""
    service, session_id, _fake_adb = _open_session(tmp_path)
    try:

        def _boom(**kwargs: Any) -> None:
            raise RuntimeError("audit store is down")

        # Only append_audit raises; the timeline write stays intact so the
        # success path (and the tool's own timeline entry) still runs.
        monkeypatch.setattr(service.repository, "append_audit", _boom)
        result = service.proxy_ca_install_android(session_id, "emulator-5554")
        assert result.ok is True
        assert result.data is not None
        assert result.data["pushed_to"] == _REMOTE_TMP
    finally:
        service.close_all()
