"""Branch coverage for the probe-frida service methods in ``service_ext``.

Companion to ``test_service_ext_r2_ghidra_branches``. That file gave the r2 and
Ghidra service methods fake-backend success and error-mapping coverage; the
sibling frida probe methods in the *same* file -- ``frida.attach`` /
``frida.modules`` / ``frida.exports`` / ``frida.memory.read`` and the PE branch
of ``frida.hook.template`` -- were still driven only on their refusal paths.
They need both a real frida and a live debuggee pid, so the success wrap
(``_success(..., backend="frida")``), the ``FridaError`` -> structured-failure
mapping, and the ``except BaseException`` capture never ran through the service.

These fakes stand in for ``FridaClient`` (a module-level import in
``service_ext``, so setting the name reaches every call site) and for the
debuggee-pid lookup (``dynamic_state`` is monkeypatched to report a pid, which
also exercises the real ``_require_debuggee_pid`` -- its ``registry.get`` guard
and pid extraction). They pin: a successful probe reports ``backend="frida"``
and passes the backend payload through; a ``FridaError`` becomes a structured
failure carrying the backend's code; an unexpected error is still captured; and
the PE branch of ``frida.hook.template`` (no device authorization on the
session) routes through the local ``hook_template`` and succeeds.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.frida.client import FridaError
from headless_re_mcp.config import Settings
from headless_re_mcp.core import service_ext
from headless_re_mcp.core.models import Result
from headless_re_mcp.core.service import AnalysisService

MP = pytest.MonkeyPatch
JsonObject = dict[str, Any]


def _write_minimal_pe(path: Path) -> None:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = (0x8664).to_bytes(2, "little")
    path.write_bytes(image)


@pytest.fixture
def service(tmp_path: Path) -> Any:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    svc = AnalysisService(settings)
    try:
        yield svc
    finally:
        svc.close_all()


def _session(service: AnalysisService, tmp_path: Path) -> str:
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None, created.error
    return str(created.data["session"]["id"])


def _give_debuggee(service: AnalysisService, monkeypatch: MP, pid: int = 4321) -> None:
    """Report a live debuggee pid so _require_debuggee_pid returns instead of
    refusing. Goes through the real helper (registry.get + pid extraction);
    only the x64dbg dynamic-state read is stubbed, which no real backend can
    supply in a unit test."""

    def fake_state(session_id: str) -> Result[JsonObject]:
        return Result[JsonObject](
            ok=True, data={"debuggee_pid": pid}, error=None, meta={}
        )

    monkeypatch.setattr(service, "dynamic_state", fake_state)


class _FakeFrida:
    """A frida client that answers each probe with a payload echoing its pid."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        pass

    def attach(self, pid: int, *, allowed_pid: int) -> JsonObject:
        return {"attached": True, "pid": pid, "allowed_pid": allowed_pid}

    def modules(self, pid: int, *, allowed_pid: int, limit: int = 64) -> JsonObject:
        return {"pid": pid, "modules": [], "count": 0, "limit": limit}

    def exports(
        self, pid: int, module_name: str, *, allowed_pid: int, limit: int = 64
    ) -> JsonObject:
        return {"pid": pid, "module": module_name, "exports": [], "count": 0}

    def memory_read(self, pid: int, address: int, size: int, *, allowed_pid: int) -> JsonObject:
        return {"pid": pid, "address": address, "size": size, "bytes": []}

    def hook_template(self, pid: int, template: str, *, allowed_pid: int) -> JsonObject:
        return {"pid": pid, "template": template, "loaded": True, "persisted": False}


class TestProbeFridaSuccess:
    @pytest.mark.parametrize(
        ("call", "check"),
        [
            (lambda s, sid: s.frida_attach(sid), lambda d: d["attached"] is True),
            (lambda s, sid: s.frida_modules(sid), lambda d: d["count"] == 0),
            (
                lambda s, sid: s.frida_exports(sid, "libc.so"),
                lambda d: d["module"] == "libc.so",
            ),
            (
                lambda s, sid: s.frida_memory_read(sid, 0x1000, 16),
                lambda d: d["address"] == 0x1000 and d["size"] == 16,
            ),
        ],
        ids=["attach", "modules", "exports", "memory_read"],
    )
    def test_probe_reports_backend_and_passes_payload_through(
        self,
        service: AnalysisService,
        tmp_path: Path,
        monkeypatch: MP,
        call: Any,
        check: Any,
    ) -> None:
        monkeypatch.setattr(service_ext, "FridaClient", _FakeFrida)
        sid = _session(service, tmp_path)
        _give_debuggee(service, monkeypatch)
        result = call(service, sid)
        assert result.ok is True and result.data is not None, result.error
        assert result.meta["backend"] == "frida"
        assert check(result.data)
        # The pid the probe used is the one _require_debuggee_pid resolved.
        assert result.data["pid"] == 4321


class TestProbeFridaErrorMapping:
    @pytest.mark.parametrize(
        ("method", "call"),
        [
            ("attach", lambda s, sid: s.frida_attach(sid)),
            ("modules", lambda s, sid: s.frida_modules(sid)),
            ("exports", lambda s, sid: s.frida_exports(sid, "libc.so")),
            ("memory_read", lambda s, sid: s.frida_memory_read(sid, 0x1000, 16)),
        ],
    )
    def test_backend_error_becomes_a_structured_failure(
        self,
        service: AnalysisService,
        tmp_path: Path,
        monkeypatch: MP,
        method: str,
        call: Any,
    ) -> None:
        class _Err(_FakeFrida):
            def _raise(self, *_a: object, **_k: object) -> JsonObject:
                raise FridaError("permission_denied", "not authorized for this pid")

        setattr(_Err, method, _Err._raise)
        monkeypatch.setattr(service_ext, "FridaClient", _Err)
        sid = _session(service, tmp_path)
        _give_debuggee(service, monkeypatch)
        result = call(service, sid)
        assert result.ok is False and result.error is not None
        assert result.error.code == "permission_denied"

    def test_unexpected_error_is_captured(
        self, service: AnalysisService, tmp_path: Path, monkeypatch: MP
    ) -> None:
        class _Boom(_FakeFrida):
            def modules(self, *_a: object, **_k: object) -> JsonObject:
                raise RuntimeError("kaboom")

        monkeypatch.setattr(service_ext, "FridaClient", _Boom)
        sid = _session(service, tmp_path)
        _give_debuggee(service, monkeypatch)
        assert service.frida_modules(sid).ok is False


class TestHookTemplatePeBranch:
    def test_pe_branch_without_device_auth_hooks_the_debuggee(
        self, service: AnalysisService, tmp_path: Path, monkeypatch: MP
    ) -> None:
        """A session with no ``frida_authorized`` metadata takes the PE branch:
        it resolves the debuggee pid and hooks it locally (the device branch is
        pinned by test_frida_hook_template_closed_session)."""
        monkeypatch.setattr(service_ext, "FridaClient", _FakeFrida)
        sid = _session(service, tmp_path)
        _give_debuggee(service, monkeypatch)
        result = service.frida_hook_template(sid, template="noop")
        assert result.ok is True and result.data is not None, result.error
        assert result.meta["backend"] == "frida"
        assert result.data["pid"] == 4321
        assert result.data["template"] == "noop"

    def test_pe_branch_maps_a_backend_error(
        self, service: AnalysisService, tmp_path: Path, monkeypatch: MP
    ) -> None:
        class _Err(_FakeFrida):
            def hook_template(self, *_a: object, **_k: object) -> JsonObject:
                raise FridaError("invalid_params", "unknown template")

        monkeypatch.setattr(service_ext, "FridaClient", _Err)
        sid = _session(service, tmp_path)
        _give_debuggee(service, monkeypatch)
        result = service.frida_hook_template(sid, template="bogus")
        assert result.ok is False and result.error is not None
        assert result.error.code == "invalid_params"
