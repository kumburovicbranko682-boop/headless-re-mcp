"""Drive the optional-backend mixin methods (radare2, Ghidra, Frida, WinDbg)
through a real AnalysisService with each backend client faked out.

The closed-session suites already cover the up-front state guards; these reach
the success paths that record a backend and append to the timeline, the typed
per-backend error mapping to XdbgRpcError, and the catch-all arms -- none of
which run when the guard trips or when a backend binary is absent. WinDbg is
Windows-only, so ``_windbg_client`` is faked to bypass the platform refusal and
exercise the dump and live-target code that Linux CI otherwise never reaches.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.core.service_ext as ext
from headless_re_mcp.backends.frida.client import FridaError
from headless_re_mcp.backends.ghidra.client import GhidraError
from headless_re_mcp.backends.r2.client import R2Error
from headless_re_mcp.backends.windbg.client import WindbgError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Result
from headless_re_mcp.core.service import AnalysisService


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


def _install(monkeypatch: pytest.MonkeyPatch, name: str, instance: Any) -> None:
    monkeypatch.setattr(ext, name, lambda *a, **k: instance)


def _grant_debuggee(monkeypatch: pytest.MonkeyPatch, service: AnalysisService, pid: int) -> None:
    monkeypatch.setattr(
        service,
        "dynamic_state",
        lambda session_id: Result(ok=True, data={"debuggee_pid": pid}),
    )


# --- radare2 ------------------------------------------------------------------


class _FakeR2:
    def __init__(self, error: BaseException | None = None) -> None:
        self.error = error

    def _reply(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self.error is not None:
            raise self.error
        return payload

    def open(self, *a: Any, **k: Any) -> dict[str, Any]:
        return self._reply({"opened": True})

    def disasm(self, *a: Any, **k: Any) -> dict[str, Any]:
        return self._reply({"disasm": []})

    def xrefs(self, *a: Any, **k: Any) -> dict[str, Any]:
        return self._reply({"xrefs": []})

    def run(self, *a: Any, **k: Any) -> dict[str, Any]:
        return self._reply({"raw": "ok"})


def test_r2_methods_report_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service, sid = _open_session(tmp_path)
    _install(monkeypatch, "R2Client", _FakeR2())
    try:
        assert service.r2_open(sid).ok
        assert service.r2_info(sid).ok
        assert service.r2_functions(sid).ok
        assert service.r2_disasm(sid, 0x401000, count=4).ok
        assert service.r2_xrefs(sid, 0x401000).ok
    finally:
        service.close_all()


def test_r2_methods_map_a_backend_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service, sid = _open_session(tmp_path)
    _install(monkeypatch, "R2Client", _FakeR2(R2Error("r2_failed", "boom")))
    try:
        for result in (
            service.r2_open(sid),
            service.r2_info(sid),
            service.r2_disasm(sid, 0x401000),
            service.r2_xrefs(sid, 0x401000),
        ):
            assert result.ok is False
            assert result.error is not None
            assert result.error.code == "r2_failed"
    finally:
        service.close_all()


# --- Ghidra -------------------------------------------------------------------


class _FakeGhidra:
    def __init__(self, export_dir: Path, error: BaseException | None = None) -> None:
        self.export_dir = export_dir
        self.error = error

    def analyze_binary(self, *a: Any, **k: Any) -> dict[str, Any]:
        if self.error is not None:
            raise self.error
        return {"project_dir": "x", "stdout_excerpt": "ok"}

    def _export(self, name: str) -> dict[str, Any]:
        if self.error is not None:
            raise self.error
        self.export_dir.mkdir(parents=True, exist_ok=True)
        exported = self.export_dir / f"{name}.json"
        exported.write_text("{}", encoding="utf-8")
        return {"items": [], "count": 0, "export_path": str(exported)}

    def functions(self, *a: Any, **k: Any) -> dict[str, Any]:
        return self._export("functions")

    def symbols(self, *a: Any, **k: Any) -> dict[str, Any]:
        return self._export("symbols")

    def xrefs(self, *a: Any, **k: Any) -> dict[str, Any]:
        return self._export("xrefs")

    def decompile(self, *a: Any, **k: Any) -> dict[str, Any]:
        return self._export("decompile")


def test_ghidra_methods_report_success_and_register_exports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, sid = _open_session(tmp_path)
    _install(monkeypatch, "GhidraClient", _FakeGhidra(tmp_path / "exports"))
    try:
        assert service.ghidra_analyze(sid).ok
        functions = service.ghidra_functions(sid)
        assert functions.ok and functions.data is not None
        assert "artifact_id" in functions.data
        assert service.ghidra_symbols(sid).ok
        assert service.ghidra_xrefs(sid, 0x1000).ok
        assert service.ghidra_decompile(sid, 0x1000).ok
    finally:
        service.close_all()


def test_ghidra_methods_map_a_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, sid = _open_session(tmp_path)
    _install(
        monkeypatch,
        "GhidraClient",
        _FakeGhidra(tmp_path / "exports", GhidraError("ghidra_failed", "nope")),
    )
    try:
        analyze = service.ghidra_analyze(sid)
        assert analyze.ok is False
        assert analyze.error is not None and analyze.error.code == "ghidra_failed"
        functions = service.ghidra_functions(sid)
        assert functions.ok is False
        assert functions.error is not None and functions.error.code == "ghidra_failed"
    finally:
        service.close_all()


def test_ghidra_export_rejects_missing_address_and_unknown_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, sid = _open_session(tmp_path)
    _install(monkeypatch, "GhidraClient", _FakeGhidra(tmp_path / "exports"))
    try:
        xrefs = ext._ghidra_export(service, sid, "xrefs", address=None)
        assert xrefs.ok is False and xrefs.error is not None
        assert xrefs.error.code == "invalid_params"
        decompile = ext._ghidra_export(service, sid, "decompile", address=None)
        assert decompile.ok is False and decompile.error is not None
        assert decompile.error.code == "invalid_params"
        unknown = ext._ghidra_export(service, sid, "bogus")
        assert unknown.ok is False and unknown.error is not None
        assert unknown.error.code == "invalid_params"
    finally:
        service.close_all()


# --- Frida --------------------------------------------------------------------


class _FakeFrida:
    def __init__(self, error: BaseException | None = None) -> None:
        self.error = error

    def _reply(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self.error is not None:
            raise self.error
        return payload

    def attach(self, *a: Any, **k: Any) -> dict[str, Any]:
        return self._reply({"attached": True})

    def modules(self, *a: Any, **k: Any) -> dict[str, Any]:
        return self._reply({"count": 0, "items": []})

    def exports(self, *a: Any, **k: Any) -> dict[str, Any]:
        return self._reply({"count": 0, "items": []})

    def memory_read(self, *a: Any, **k: Any) -> dict[str, Any]:
        return self._reply({"data": "00"})

    def hook_template(self, *a: Any, **k: Any) -> dict[str, Any]:
        return self._reply({"script": "noop"})


def test_frida_methods_report_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service, sid = _open_session(tmp_path)
    _grant_debuggee(monkeypatch, service, 4321)
    _install(monkeypatch, "FridaClient", _FakeFrida())
    try:
        assert service.frida_attach(sid).ok
        assert service.frida_modules(sid).ok
        assert service.frida_exports(sid, "libc.so").ok
        assert service.frida_memory_read(sid, 0x1000, 16).ok
        assert service.frida_hook_template(sid).ok
    finally:
        service.close_all()


def test_frida_methods_map_a_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, sid = _open_session(tmp_path)
    _grant_debuggee(monkeypatch, service, 4321)
    _install(monkeypatch, "FridaClient", _FakeFrida(FridaError("frida_failed", "down")))
    try:
        for result in (
            service.frida_attach(sid),
            service.frida_modules(sid),
            service.frida_exports(sid, "libc.so"),
            service.frida_memory_read(sid, 0x1000, 16),
            service.frida_hook_template(sid),
        ):
            assert result.ok is False
            assert result.error is not None
            assert result.error.code == "frida_failed"
    finally:
        service.close_all()


def test_frida_refuses_when_no_debuggee_is_active(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, sid = _open_session(tmp_path)
    _grant_debuggee(monkeypatch, service, 0)
    _install(monkeypatch, "FridaClient", _FakeFrida())
    try:
        result = service.frida_attach(sid)
        assert result.ok is False
        assert result.error is not None
        assert "debuggee" in result.error.message
    finally:
        service.close_all()


# --- WinDbg (Windows-only client faked to reach the cross-platform arms) ------


class _FakeWindbg:
    def __init__(self, error: BaseException | None = None) -> None:
        self.error = error

    def _reply(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self.error is not None:
            raise self.error
        return payload

    def open_dump(self, *a: Any, **k: Any) -> dict[str, Any]:
        return self._reply({"modules": []})

    def threads(self, *a: Any, **k: Any) -> dict[str, Any]:
        return self._reply({"threads": []})

    def modules(self, *a: Any, **k: Any) -> dict[str, Any]:
        return self._reply({"modules": []})

    def disasm(self, *a: Any, **k: Any) -> dict[str, Any]:
        return self._reply({"disasm": []})

    def attach(self, *a: Any, **k: Any) -> dict[str, Any]:
        return self._reply({"attached": True})

    def live_threads(self, *a: Any, **k: Any) -> dict[str, Any]:
        return self._reply({"threads": []})

    def live_modules(self, *a: Any, **k: Any) -> dict[str, Any]:
        return self._reply({"modules": []})

    def live_disasm(self, *a: Any, **k: Any) -> dict[str, Any]:
        return self._reply({"disasm": []})


def test_windbg_methods_report_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service, sid = _open_session(tmp_path)
    _grant_debuggee(monkeypatch, service, 4321)
    fake = _FakeWindbg()
    monkeypatch.setattr(ext, "_windbg_client", lambda service: fake)
    dump = str(tmp_path / "crash.dmp")
    try:
        assert service.windbg_open_dump(dump).ok
        assert service.windbg_threads(dump).ok
        assert service.windbg_modules(dump).ok
        assert service.windbg_disasm(dump, 0x401000).ok
        assert service.windbg_attach(sid).ok
        assert service.windbg_live_threads(sid).ok
        assert service.windbg_live_modules(sid).ok
        assert service.windbg_live_disasm(sid, 0x401000).ok
    finally:
        service.close_all()


def test_windbg_dump_methods_wrap_unexpected_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, sid = _open_session(tmp_path)
    fake = _FakeWindbg(RuntimeError("cdb crashed"))
    monkeypatch.setattr(ext, "_windbg_client", lambda service: fake)
    dump = str(tmp_path / "crash.dmp")
    try:
        for result in (
            service.windbg_open_dump(dump),
            service.windbg_threads(dump),
            service.windbg_modules(dump),
            service.windbg_disasm(dump, 0x401000),
        ):
            assert result.ok is False
            assert result.error is not None
    finally:
        service.close_all()


def test_windbg_live_methods_map_a_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, sid = _open_session(tmp_path)
    _grant_debuggee(monkeypatch, service, 4321)
    fake = _FakeWindbg(WindbgError("windbg_failed", "attach refused"))
    monkeypatch.setattr(ext, "_windbg_client", lambda service: fake)
    try:
        for result in (
            service.windbg_attach(sid),
            service.windbg_live_threads(sid),
            service.windbg_live_modules(sid),
            service.windbg_live_disasm(sid, 0x401000),
        ):
            assert result.ok is False
            assert result.error is not None
            assert result.error.code == "windbg_failed"
    finally:
        service.close_all()
