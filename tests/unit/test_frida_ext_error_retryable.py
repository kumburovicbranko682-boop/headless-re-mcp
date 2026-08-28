"""The service_ext Frida paths must honor the same retryable contract.

``test_non_pe_error_retryable`` pins the six ``_as_rpc`` converters, but the
optional-backend Frida methods live in ``service_ext`` and do *not* go through
``_as_rpc`` -- each has its own ``except FridaError`` block that built the error
envelope inline. Those blocks used ``XdbgRpcError(exc.code, exc.message, ...)``
with the constructor default ``retryable=False``, so a ``frida.attach`` /
``frida.modules`` / ``frida.exports`` / ``frida.memory.read`` / ``frida.hook``
that timed out surfaced as a permanent failure -- the exact bug the ``_as_rpc``
fix closed for the Android line, still open on this second Frida surface.

These drive the real service methods end-to-end so a timeout reaches the caller
retryable and a deterministic failure does not, at every one of the five sites.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.frida.client import FridaError
from headless_re_mcp.config import Settings
from headless_re_mcp.core import service_ext
from headless_re_mcp.core.service import AnalysisService


def _write_minimal_pe(path: Path) -> None:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = (0x8664).to_bytes(2, "little")
    path.write_bytes(image)


class _RaisingFrida:
    """A FridaClient stand-in whose every op raises one chosen code, so each
    service_ext except-block is exercised without a live device or debuggee."""

    def __init__(self, code: str) -> None:
        self._code = code

    def _boom(self, where: str) -> Any:
        raise FridaError(self._code, f"{self._code} in {where}")

    def attach(self, pid: int, *, allowed_pid: int) -> Any:
        return self._boom("attach")

    def modules(self, pid: int, *, allowed_pid: int, limit: int = 64) -> Any:
        return self._boom("modules")

    def exports(self, pid: int, module_name: str, *, allowed_pid: int, limit: int = 64) -> Any:
        return self._boom("exports")

    def memory_read(self, pid: int, address: int, size: int, *, allowed_pid: int) -> Any:
        return self._boom("memory_read")

    def hook_template(self, pid: int, template: str, *, allowed_pid: int) -> Any:
        return self._boom("hook_template")


# (method label, callable taking the service + session_id). hook.template takes
# the PE else-branch here (no frida_authorized metadata), so it too resolves the
# pid through the monkeypatched _require_debuggee_pid and calls hook_template.
_INVOCATIONS = {
    "frida.attach": lambda svc, sid: svc.frida_attach(sid),
    "frida.modules": lambda svc, sid: svc.frida_modules(sid),
    "frida.exports": lambda svc, sid: svc.frida_exports(sid, "libc.so"),
    "frida.memory.read": lambda svc, sid: svc.frida_memory_read(sid, 0x1000, 16),
    "frida.hook.template": lambda svc, sid: svc.frida_hook_template(sid, template="noop"),
}


def _service_with_raising_frida(
    tmp_path: Path, monkeypatch: Any, code: str
) -> tuple[AnalysisService, str]:
    monkeypatch.setattr(service_ext, "FridaClient", lambda *a, **k: _RaisingFrida(code))
    # No live x64dbg debuggee in a unit test; every op that needs a pid resolves
    # it here so the except-block, not the pid guard, is what runs.
    monkeypatch.setattr(service_ext, "_require_debuggee_pid", lambda service, session_id: 4321)
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None, created.error
    return service, created.data["session"]["id"]


@pytest.mark.parametrize("label", sorted(_INVOCATIONS))
def test_service_ext_frida_timeout_is_retryable(
    label: str, tmp_path: Path, monkeypatch: Any
) -> None:
    """A FridaError('timeout') from any of the five optional-backend Frida
    methods reaches the caller as a retryable timeout envelope."""
    service, session_id = _service_with_raising_frida(tmp_path, monkeypatch, "timeout")
    try:
        result = _INVOCATIONS[label](service, session_id)
        assert result.ok is False, label
        assert result.error is not None
        assert result.error.code == "timeout", label
        assert result.error.retryable is True, label
    finally:
        service.close_all()


@pytest.mark.parametrize("label", sorted(_INVOCATIONS))
def test_service_ext_frida_deterministic_error_is_not_retryable(
    label: str, tmp_path: Path, monkeypatch: Any
) -> None:
    """The mirror: a deterministic FridaError (invalid_params) stays
    retryable=False through every site, so widening the rule at one is caught."""
    service, session_id = _service_with_raising_frida(tmp_path, monkeypatch, "invalid_params")
    try:
        result = _INVOCATIONS[label](service, session_id)
        assert result.error is not None
        assert result.error.code == "invalid_params", label
        assert result.error.retryable is False, label
    finally:
        service.close_all()
