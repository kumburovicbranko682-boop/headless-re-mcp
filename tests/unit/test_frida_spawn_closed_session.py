"""A close arriving mid-spawn must not report success or mutate the session."""

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


def _authorize_device(service: AnalysisService, session_id: str) -> None:
    service.registry.update_metadata(
        session_id,
        {"frida_authorized": {"device_id": "usb", "pids": [], "packages": []}},
    )


def test_frida_spawn_does_not_report_success_if_the_session_closes_during_run(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """frida.spawn had no post-spawn state re-check.

    Every other device frida mutation (frida.device.connect, frida.server.ensure)
    re-reads the session state after touching the device, so a close arriving
    mid-call is reported as invalid_state rather than ok=True. spawn wrote the
    freshly spawned pid onto the (now closed) session and returned success,
    leaving a dead session recorded as owning a live device process.
    """
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)

    class _CloseThenSpawn:
        def spawn(self, device_id: Any, package: str) -> dict[str, Any]:
            del device_id
            service.close_session(session_id)
            return {"package": package, "pid": 9999, "device": "usb"}

    monkeypatch.setattr(
        "headless_re_mcp.core.service_frida.FridaClient",
        lambda *args, **kwargs: _CloseThenSpawn(),
    )
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        _authorize_device(service, session_id)

        result = service.frida_spawn(session_id, "com.example.app")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
        assert "closed" in result.error.message
        auth = service.registry.get(session_id).metadata.get("frida_authorized")
        assert isinstance(auth, dict)
        assert 9999 not in (auth.get("pids") or [])
    finally:
        service.close_all()


def test_frida_spawn_on_an_open_session_records_the_spawned_pid(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The post-spawn guard must not break the normal path: an open session
    still authorizes and records the freshly spawned pid."""
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)

    class _Spawn:
        def spawn(self, device_id: Any, package: str) -> dict[str, Any]:
            del device_id
            return {"package": package, "pid": 4242, "device": "usb"}

    monkeypatch.setattr(
        "headless_re_mcp.core.service_frida.FridaClient",
        lambda *args, **kwargs: _Spawn(),
    )
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        _authorize_device(service, session_id)

        result = service.frida_spawn(session_id, "com.example.app")
        assert result.ok is True, result.error
        auth = service.registry.get(session_id).metadata.get("frida_authorized")
        assert isinstance(auth, dict)
        assert 4242 in (auth.get("pids") or [])
    finally:
        service.close_all()
