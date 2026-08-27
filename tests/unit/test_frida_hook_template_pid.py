"""frida.hook.template can target any authorized device pid, not only the last.

The device backend already authorizes an explicit pid (hook_template_device takes
pid + allowed_pids), and the sibling frida.java.* tools already expose pid with a
0-means-last convention. The hook tool used to hardcode the most recently spawned
pid, so a session that spawned several packages could enumerate Java on any of
them but hook only the last. These tests pin the parity at the service layer.
"""

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


class _RecordingFrida:
    """Records the pid each hook path is asked to touch."""

    def __init__(self) -> None:
        self.device_calls: list[dict[str, Any]] = []
        self.local_calls: list[dict[str, Any]] = []

    def hook_template_device(
        self,
        device_id: str | None,
        pid: int,
        template: str,
        *,
        allowed_pids: Any,
        timeout: float = 0.0,
    ) -> dict[str, Any]:
        self.device_calls.append(
            {"device_id": device_id, "pid": pid, "allowed": list(allowed_pids)}
        )
        return {
            "pid": pid,
            "template": template,
            "loaded": True,
            "device": str(device_id or "local"),
            "persisted": False,
            "note": "probe detached",
        }

    def hook_template(
        self, pid: int, template: str, *, allowed_pid: int, timeout: float = 0.0
    ) -> dict[str, Any]:
        self.local_calls.append({"pid": pid, "allowed_pid": allowed_pid})
        return {
            "pid": pid,
            "template": template,
            "loaded": True,
            "device": "local",
            "persisted": False,
            "note": "probe detached",
        }


def _service_with_authorized_device(
    tmp_path: Path, monkeypatch: Any, pids: list[int]
) -> tuple[AnalysisService, str, _RecordingFrida]:
    fake = _RecordingFrida()
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.FridaClient", lambda *a, **k: fake
    )
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None, created.error
    session_id = created.data["session"]["id"]
    service.registry.update_metadata(
        session_id, {"frida_authorized": {"device_id": "usb", "pids": list(pids)}}
    )
    return service, session_id, fake


def test_explicit_pid_is_forwarded_to_the_device_hook(
    tmp_path: Path, monkeypatch: Any
) -> None:
    service, session_id, fake = _service_with_authorized_device(
        tmp_path, monkeypatch, [111, 222]
    )
    try:
        result = service.frida_hook_template(session_id, template="noop", pid=111)
        assert result.ok, result.error
        assert fake.device_calls == [
            {"device_id": "usb", "pid": 111, "allowed": [111, 222]}
        ]
        assert not fake.local_calls
        assert result.data is not None and result.data["pid"] == 111
    finally:
        service.close_all()


def test_pid_zero_uses_the_most_recent_authorized_pid(
    tmp_path: Path, monkeypatch: Any
) -> None:
    service, session_id, fake = _service_with_authorized_device(
        tmp_path, monkeypatch, [111, 222]
    )
    try:
        result = service.frida_hook_template(session_id, template="noop")
        assert result.ok, result.error
        assert fake.device_calls[0]["pid"] == 222
        # The full authorized set still gates the backend re-check.
        assert fake.device_calls[0]["allowed"] == [111, 222]
    finally:
        service.close_all()


def test_connected_but_unspawned_session_is_told_to_spawn(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A device is connected but nothing has been spawned yet.

    This used to fall through to the PE debuggee path and fail with "no active
    debuggee for optional backend" -- a debugger-shaped error for an APK/web
    session. frida.java.* already answers "call frida.spawn first" here, so the
    hook tool must match rather than reach for a debuggee that cannot exist.
    """
    service, session_id, fake = _service_with_authorized_device(
        tmp_path, monkeypatch, []
    )
    try:
        result = service.frida_hook_template(session_id, template="noop")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_state"
        assert "frida.spawn" in result.error.message
        assert "debuggee" not in result.error.message
        # Neither hook path was reached: the guidance comes before any client call.
        assert not fake.device_calls
        assert not fake.local_calls
    finally:
        service.close_all()
