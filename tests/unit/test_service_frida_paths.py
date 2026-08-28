"""Frida optional-backend service paths (frida_attach/modules/exports/memory_read
and the local hook_template branch).

The device hook_template branch is pinned by test_frida_hook_template_closed_session;
this covers the PE/local branch that resolves a live debuggee pid, the probe read
ops around it, and the FridaError -> structured-envelope mapping each funnels
through. The debuggee-pid resolver and the FridaClient are both constructed inside
the mixin, so each is monkeypatched at the service_ext boundary (a real debuggee
would need a live dynamic session; this isolates the service logic).
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

_PID = 4321


def _service(tmp_path: Path) -> AnalysisService:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    return AnalysisService(settings)


def _web_session(service: AnalysisService) -> str:
    created = service.create_session("https://example.com/app", target="web")
    assert created.ok and created.data is not None, created.error
    return str(created.data["session"]["id"])


class _FakeFrida:
    def __init__(self, exc: BaseException | None = None) -> None:
        self.exc = exc

    def _maybe(self) -> None:
        if self.exc is not None:
            raise self.exc

    def attach(self, pid: int, *, allowed_pid: int) -> dict[str, Any]:
        self._maybe()
        return {"pid": pid, "attached": True, "detached": True}

    def modules(self, pid: int, *, allowed_pid: int, limit: int = 64) -> dict[str, Any]:
        self._maybe()
        return {"pid": pid, "modules": [], "count": 0}

    def exports(
        self, pid: int, module_name: str, *, allowed_pid: int, limit: int = 64
    ) -> dict[str, Any]:
        self._maybe()
        return {"pid": pid, "module": module_name, "exports": [], "count": 0}

    def memory_read(self, pid: int, address: int, size: int, *, allowed_pid: int) -> dict[str, Any]:
        self._maybe()
        return {"pid": pid, "address": address, "size": size, "data": ""}

    def hook_template(self, pid: int, template: str, *, allowed_pid: int) -> dict[str, Any]:
        self._maybe()
        return {"pid": pid, "template": template, "loaded": True, "persisted": False}

    def hook_template_device(
        self, device_id: Any, pid: int, template: str, *, allowed_pids: Any
    ) -> dict[str, Any]:
        self._maybe()
        return {"pid": pid, "template": template, "loaded": True, "persisted": False}


def _install(monkeypatch: pytest.MonkeyPatch, fake: _FakeFrida) -> None:
    monkeypatch.setattr(service_ext, "_require_debuggee_pid", lambda self, sid: _PID)
    monkeypatch.setattr(service_ext, "FridaClient", lambda *a, **k: fake)


# ---------------------------------------------------------------------------
# happy paths: each probe op resolves the debuggee pid and reports frida backend
# ---------------------------------------------------------------------------
def test_frida_attach_records_backend(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service(tmp_path)
    _install(monkeypatch, _FakeFrida())
    try:
        sid = _web_session(service)
        result = service.frida_attach(sid)
        assert result.ok, result.error
        assert result.data is not None and result.data["pid"] == _PID
        assert result.meta["backend"] == "frida"
    finally:
        service.close_all()


def test_frida_modules_and_exports_and_memory_read_succeed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    _install(monkeypatch, _FakeFrida())
    try:
        sid = _web_session(service)
        assert service.frida_modules(sid, limit=8).ok
        assert service.frida_exports(sid, "libc.so", limit=8).ok
        assert service.frida_memory_read(sid, 0x1000, 16).ok
    finally:
        service.close_all()


def test_frida_hook_template_uses_the_local_branch_without_auth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    _install(monkeypatch, _FakeFrida())
    try:
        sid = _web_session(service)  # no frida_authorized metadata -> local branch
        result = service.frida_hook_template(sid, template="noop")
        assert result.ok, result.error
        assert result.data is not None and result.data["pid"] == _PID
    finally:
        service.close_all()


# ---------------------------------------------------------------------------
# FridaError -> structured envelope for every op
# ---------------------------------------------------------------------------
def test_frida_ops_map_frida_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service(tmp_path)
    _install(monkeypatch, _FakeFrida(FridaError("capability_unavailable", "frida not installed")))
    try:
        sid = _web_session(service)
        for result in (
            service.frida_attach(sid),
            service.frida_modules(sid),
            service.frida_exports(sid, "libc.so"),
            service.frida_memory_read(sid, 0x1000, 16),
            service.frida_hook_template(sid, template="noop"),
        ):
            assert result.ok is False
            assert result.error is not None
            assert result.error.code == "capability_unavailable"
    finally:
        service.close_all()


def test_frida_attach_maps_an_unexpected_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    _install(monkeypatch, _FakeFrida(RuntimeError("frida core panicked")))
    try:
        sid = _web_session(service)
        result = service.frida_attach(sid)
        assert result.ok is False
        assert result.error is not None and result.error.code == "internal_error"
    finally:
        service.close_all()
