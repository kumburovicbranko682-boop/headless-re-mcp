"""frida.hook.template must not inject into a retained CLOSED device session.

close transitions state but never clears session metadata, so a closed session
still carries frida_authorized and still resolves. Every other device frida op
is gated by _frida_auth's open-session check; hook.template read the pid
straight from metadata, so a late call injected a script into a device process
for a session that was already gone. The device branch now refuses
CLOSING/CLOSED/FAILED (the PE branch is already gated by _require_debuggee_pid).
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


class _HookTrackingFrida:
    device_hooks = 0
    local_hooks = 0

    def hook_template_device(
        self, device_id: Any, pid: int, template: str, *, allowed_pids: Any
    ) -> dict[str, Any]:
        del device_id, allowed_pids
        _HookTrackingFrida.device_hooks += 1
        return {"pid": pid, "template": template, "loaded": True, "persisted": False}

    def hook_template(self, pid: int, template: str, *, allowed_pid: int) -> dict[str, Any]:
        del allowed_pid
        _HookTrackingFrida.local_hooks += 1
        return {"pid": pid, "template": template, "loaded": True, "persisted": False}


def _authorize_device(service: AnalysisService, session_id: str, pid: int = 4321) -> None:
    service.registry.update_metadata(
        session_id,
        {"frida_authorized": {"device_id": "usb", "pids": [pid], "packages": []}},
    )


def test_frida_hook_template_on_a_closed_device_session_is_refused(
    tmp_path: Path, monkeypatch: Any
) -> None:
    _HookTrackingFrida.device_hooks = 0
    _HookTrackingFrida.local_hooks = 0
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.FridaClient",
        lambda *args, **kwargs: _HookTrackingFrida(),
    )
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        _authorize_device(service, session_id)
        closed = service.close_session(session_id)
        assert closed.ok, closed.error

        result = service.frida_hook_template(session_id, template="noop")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
        assert "closed" in result.error.message
        assert _HookTrackingFrida.device_hooks == 0
    finally:
        service.close_all()


def test_frida_hook_template_on_an_open_device_session_still_hooks(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The state guard must not break the normal path: an open, authorized
    device session still routes through hook_template_device once."""
    _HookTrackingFrida.device_hooks = 0
    _HookTrackingFrida.local_hooks = 0
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.FridaClient",
        lambda *args, **kwargs: _HookTrackingFrida(),
    )
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        _authorize_device(service, session_id)

        result = service.frida_hook_template(session_id, template="noop")
        assert result.ok is True, result.error
        assert _HookTrackingFrida.device_hooks == 1
        assert _HookTrackingFrida.local_hooks == 0
    finally:
        service.close_all()
