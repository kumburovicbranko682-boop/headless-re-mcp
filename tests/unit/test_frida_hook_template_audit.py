"""frida.hook.template must land in the durable audit log.

hook.template compiles a template and loads it inside the target process -- on a
device session that is code running inside a device app, the most privileged
thing the frida surface does, even though the probe detaches straight after
(persisted false). Its high-stakes siblings frida.spawn / frida.server.ensure
already audit; hook.template only owned a timeline entry, which is trimmed with
the session, so a cross-session auditor asking "what did the agent inject, and
where" had no durable record. These pin the success and failure audit, the
structural (secret-free) summary, and that a broken audit write never fails an
injection that already ran in the target.
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
    return service, created.data["session"]["id"]


def _authorize_device(service: AnalysisService, session_id: str, *, pids: list[int]) -> None:
    service.registry.update_metadata(
        session_id,
        {"frida_authorized": {"device_id": "usb", "pids": pids, "packages": []}},
    )


def _by_action(service: AnalysisService, action: str) -> list[JsonObject]:
    result = service.audit_list(None)
    assert result.ok and result.data is not None
    return [e for e in result.data["entries"] if e["action"] == action]


class _FakeClient:
    """A FridaClient stand-in for the device-path hook the service makes."""

    def hook_template_device(
        self, device_id: Any, pid: int, template: str, *, allowed_pids: Any
    ) -> JsonObject:
        del allowed_pids
        return {
            "pid": pid,
            "template": template,
            "loaded": True,
            "device": str(device_id or "local"),
            "persisted": False,
            "note": "probe injection: nothing stays hooked in the target",
        }


def test_frida_hook_template_device_injection_is_audited(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.FridaClient", lambda *a, **k: _FakeClient()
    )
    service, session_id = _open_session(tmp_path)
    try:
        _authorize_device(service, session_id, pids=[4242])
        result = service.frida_hook_template(session_id, template="noop")
        assert result.ok is True, result.error

        entry = _by_action(service, "frida.hook.template")[0]
        assert entry["session_id"] == session_id
        assert entry["ok"] == 1
        assert entry["params_summary"] == {"template": "noop"}
        # Structural fields only -- pid, whether it persisted, the device.
        assert entry["result_summary"] == {"pid": 4242, "persisted": False, "device": "usb"}
    finally:
        service.close_all()


def test_a_failed_hook_template_is_audited_with_its_code(
    tmp_path: Path, monkeypatch: Any
) -> None:
    class _Boom(_FakeClient):
        def hook_template_device(
            self, device_id: Any, pid: int, template: str, *, allowed_pids: Any
        ) -> JsonObject:
            raise FridaError("backend_error", "attach failed", pid=pid)

    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.FridaClient", lambda *a, **k: _Boom()
    )
    service, session_id = _open_session(tmp_path)
    try:
        _authorize_device(service, session_id, pids=[4242])
        result = service.frida_hook_template(session_id, template="noop")
        assert result.ok is False

        entry = _by_action(service, "frida.hook.template")[0]
        assert entry["ok"] == 0
        assert entry["result_summary"] == {"code": "backend_error"}
    finally:
        service.close_all()


def test_hook_template_audit_is_visible_filtered_to_its_session(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The entry carries the real session_id, so the session-filtered listing --
    the durable record that outlives the session's trimmed timeline -- shows it."""
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.FridaClient", lambda *a, **k: _FakeClient()
    )
    service, session_id = _open_session(tmp_path)
    try:
        _authorize_device(service, session_id, pids=[4242])
        service.frida_hook_template(session_id, template="noop")

        scoped = service.audit_list(session_id)
        assert scoped.ok and scoped.data is not None
        assert any(e["action"] == "frida.hook.template" for e in scoped.data["entries"])
    finally:
        service.close_all()


def test_an_audit_write_failure_does_not_fail_the_injection(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The template already loaded and ran in the target; a bookkeeping failure
    in the audit write must not turn that into a failed tool call."""
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.FridaClient", lambda *a, **k: _FakeClient()
    )
    service, session_id = _open_session(tmp_path)
    try:
        _authorize_device(service, session_id, pids=[4242])

        def _boom(**kwargs: Any) -> None:
            raise RuntimeError("audit store is down")

        monkeypatch.setattr(service.repository, "append_audit", _boom)
        result = service.frida_hook_template(session_id, template="noop")
        assert result.ok is True
        assert result.data is not None
        assert result.data["pid"] == 4242
    finally:
        service.close_all()
