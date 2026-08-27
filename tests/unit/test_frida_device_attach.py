"""frida.device.attach is the attach door into a session's Frida allow-set.

spawn authorizes the pid it launches; before this, that was the only way a
device pid entered the allow-set, so an app the caller did not spawn -- one
seen via frida.applications -- could never be enumerated or hooked. These
pin the two properties that make the door safe: a pid is authorized only when
the probe attach actually reached it, and a failed attach leaves the set
untouched.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.frida.client import FridaError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService


def _write_minimal_pe(path: Path) -> None:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = (0x8664).to_bytes(2, "little")
    path.write_bytes(image)


class _FakeDevice:
    id = "usb"
    name = "usb"
    type = "usb"


class _AttachingFrida:
    """A FridaClient stand-in: connect resolves, attach echoes the pid."""

    def _resolve_device(self, device_id: str) -> _FakeDevice:
        del device_id
        return _FakeDevice()

    def attach_device(self, device_id: str | None, pid: int) -> dict[str, Any]:
        del device_id
        return {
            "pid": pid,
            "attached": True,
            "device": "usb",
            "note": "probe attach; detached immediately",
        }


class _RefusingFrida(_AttachingFrida):
    def attach_device(self, device_id: str | None, pid: int) -> dict[str, Any]:
        raise FridaError("backend_error", "attach failed: no such process", pid=pid)


def _authorized_pids(service: AnalysisService, session_id: str) -> list[int]:
    auth = service.registry.get(session_id).metadata.get("frida_authorized")
    assert isinstance(auth, dict)
    return list(auth.get("pids") or [])


def _connected_session(service: AnalysisService, tmp_path: Path) -> str:
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None, created.error
    session_id = created.data["session"]["id"]
    connected = service.frida_device_connect(session_id, device_id="usb")
    assert connected.ok, connected.error
    return session_id


def test_device_attach_authorizes_the_running_pid(tmp_path: Path, monkeypatch: Any) -> None:
    fake = _AttachingFrida()
    monkeypatch.setattr(
        "headless_re_mcp.core.service_frida.FridaClient",
        lambda *args, **kwargs: fake,
    )
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    try:
        session_id = _connected_session(service, tmp_path)
        assert _authorized_pids(service, session_id) == []

        result = service.frida_device_attach(session_id, 7788)
        assert result.ok, result.error
        assert result.data is not None
        assert result.data["pid"] == 7788
        assert result.data["attached"] is True
        # The pid a caller can now enumerate/hook is exactly the one it attached.
        assert 7788 in _authorized_pids(service, session_id)
    finally:
        service.close_all()


def test_a_failed_attach_does_not_authorize_the_pid(tmp_path: Path, monkeypatch: Any) -> None:
    """A pid the probe could not reach must not silently gain access.

    The service authorizes only after the backend attach returns, so an attach
    that raises leaves the allow-set as it was -- otherwise a dead or wrong pid
    would be admitted on a call that failed, and a later hook would target it.
    """
    fake = _RefusingFrida()
    monkeypatch.setattr(
        "headless_re_mcp.core.service_frida.FridaClient",
        lambda *args, **kwargs: fake,
    )
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    try:
        session_id = _connected_session(service, tmp_path)

        result = service.frida_device_attach(session_id, 9999)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "backend_error"
        assert _authorized_pids(service, session_id) == []
    finally:
        service.close_all()


def test_device_attach_requires_a_connected_device(tmp_path: Path, monkeypatch: Any) -> None:
    """Without a connected device there is no allow-set to add to.

    _frida_auth refuses until frida.device.connect has run, so attach on a
    session that never connected is invalid_state, not a silent no-op.
    """
    monkeypatch.setattr(
        "headless_re_mcp.core.service_frida.FridaClient",
        lambda *args, **kwargs: _AttachingFrida(),
    )
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    try:
        binary = tmp_path / "sample.exe"
        _write_minimal_pe(binary)
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]

        result = service.frida_device_attach(session_id, 4242)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_state"
    finally:
        service.close_all()
