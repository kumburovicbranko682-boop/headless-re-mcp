"""A retained CLOSED session must not mutate a Frida device."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService


def _write_minimal_pe(path: Path) -> None:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = (0x8664).to_bytes(2, "little")
    path.write_bytes(image)


class _TrackingFrida:
    connects = 0

    def _resolve_device(self, device_id: str) -> Any:
        _TrackingFrida.connects += 1

        class _Device:
            id = device_id
            name = "usb"
            type = "usb"

        return _Device()


class _TrackingAdb:
    ensures = 0

    def ensure_frida_server(
        self, serial: str, server_binary: str | None = None, port: int = 27042
    ) -> dict[str, Any]:
        del serial, server_binary
        _TrackingAdb.ensures += 1
        return {"ensured": True, "running": True, "pushed": False, "port": port}


def test_frida_device_connect_on_a_closed_session_does_not_bind(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A retained CLOSED session still resolved, so a late connect bound Frida.

    Measured: after close_session, frida.device.connect returned ok=True with
    connected=True, resolved the device once, and wrote frida_authorized on
    the closed session. The model then treats the dead session as holding a
    device and follows with spawn/ensure.
    """
    _TrackingFrida.connects = 0
    monkeypatch.setattr(
        "headless_re_mcp.core.service_frida.FridaClient",
        lambda *args, **kwargs: _TrackingFrida(),
    )
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        closed = service.close_session(session_id)
        assert closed.ok, closed.error

        result = service.frida_device_connect(session_id, device_id="usb")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
        assert "closed" in result.error.message
        assert _TrackingFrida.connects == 0
        assert "frida_authorized" not in service.registry.get(session_id).metadata
    finally:
        service.close_all()


def test_frida_server_ensure_on_a_closed_session_does_not_start_server(
    tmp_path: Path,
) -> None:
    """A late ensure would push/start frida-server on a device nobody owns.

    Measured: after close_session, frida.server.ensure returned ok=True and
    the owned ADB backend ran once. session.close cannot undo a server that
    started after it returned.
    """
    _TrackingAdb.ensures = 0
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    service._adb_backend = _TrackingAdb()  # type: ignore[assignment]
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        closed = service.close_session(session_id)
        assert closed.ok, closed.error

        result = service.frida_server_ensure(session_id, serial="emulator-5554")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
        assert "closed" in result.error.message
        assert _TrackingAdb.ensures == 0
    finally:
        service.close_all()


def test_frida_server_ensure_does_not_report_success_if_the_session_closes_during_run(
    tmp_path: Path,
) -> None:
    """A close mid-ensure used to return ok=True after mutating the device."""
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)

    class _CloseThenEnsure:
        def ensure_frida_server(
            self, serial: str, server_binary: str | None = None, port: int = 27042
        ) -> dict[str, Any]:
            del serial, server_binary
            service.close_session(session_id)
            return {"ensured": True, "running": True, "pushed": False, "port": port}

    service._adb_backend = _CloseThenEnsure()  # type: ignore[assignment]
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        result = service.frida_server_ensure(session_id, serial="emulator-5554")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
        assert "closed" in result.error.message
    finally:
        service.close_all()