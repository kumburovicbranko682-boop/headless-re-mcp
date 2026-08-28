"""Success and error-mapping paths for the optional-backend service methods.

The r2.*, ghidra.* and frida.* probe methods on ``ExtAnalysisMixin`` share the
same shape as the apk service: run a bounded backend, re-check the session is
still open, record the backend and a timeline row, and wrap the payload -- or
map the backend's structured error back into the canonical envelope. The
*_closed_session suites drive the retained-CLOSED guard, and the field suites
drive the backend clients directly, but the service methods' own success bodies
and their R2Error / GhidraError / FridaError mapping ran in almost none of them.

These drive a real ``AnalysisService`` with an open session and fake r2 / ghidra
/ frida clients so the service layer runs without radare2, a Ghidra install, or
frida-core. The optional backends are the portable-static and Android/native
probe lines, the ones the README calls the least mature.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.frida.client import FridaError
from headless_re_mcp.backends.ghidra.client import GhidraError
from headless_re_mcp.backends.r2.client import R2Error
from headless_re_mcp.config import Settings
from headless_re_mcp.core import service_ext
from headless_re_mcp.core.models import Result, RpcError
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.service_ext import _ghidra_export, _require_debuggee_pid


def _write_minimal_pe(path: Path) -> None:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = (0x8664).to_bytes(2, "little")
    path.write_bytes(image)


def _service_with_session(tmp_path: Path) -> tuple[AnalysisService, str]:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None, created.error
    return service, created.data["session"]["id"]


# ============================================================================
# radare2
# ============================================================================


class _FakeR2:
    def __init__(self, *_args: object, **_kwargs: object) -> None:
        pass

    def open(self, binary: Path, *, timeout: float = 30.0) -> dict[str, Any]:
        del binary, timeout
        return {"opened": True, "binary": "sample.exe", "info": "elf"}

    def run(self, binary: Path, commands: list[str], *, timeout: float = 30.0) -> dict[str, Any]:
        del binary, timeout
        return {"raw": "ok", "commands": commands}

    def disasm(
        self, binary: Path, address: int, *, count: int = 32, timeout: float = 30.0
    ) -> dict[str, Any]:
        del binary, timeout
        return {"address": address, "count": count, "instructions": []}

    def xrefs(self, binary: Path, address: int, *, timeout: float = 30.0) -> dict[str, Any]:
        del binary, timeout
        return {"address": address, "xrefs": []}


def test_r2_open_records_and_wraps(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service_ext, "R2Client", _FakeR2)
    service, session_id = _service_with_session(tmp_path)
    try:
        result = service.r2_open(session_id)
        assert result.ok is True, result.error
        assert result.data is not None and result.data["opened"] is True
        assert result.meta.get("backend") == "radare2"
    finally:
        service.close_all()


@pytest.mark.parametrize(
    "invoke",
    [
        lambda s, sid: s.r2_info(sid),
        lambda s, sid: s.r2_functions(sid),
        lambda s, sid: s.r2_strings(sid),
        lambda s, sid: s.r2_imports(sid),
        lambda s, sid: s.r2_exports(sid),
    ],
)
def test_r2_request_ops_succeed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, invoke: Any
) -> None:
    """Every whitelist-command read wraps the r2 payload on an open session."""
    monkeypatch.setattr(service_ext, "R2Client", _FakeR2)
    service, session_id = _service_with_session(tmp_path)
    try:
        result = invoke(service, session_id)
        assert result.ok is True, result.error
        assert result.data is not None and result.data["raw"] == "ok"
        assert result.meta.get("backend") == "radare2"
    finally:
        service.close_all()


def test_r2_disasm_and_xrefs_succeed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(service_ext, "R2Client", _FakeR2)
    service, session_id = _service_with_session(tmp_path)
    try:
        disasm = service.r2_disasm(session_id, 0x1000, count=8)
        assert disasm.ok is True, disasm.error
        assert disasm.data is not None and disasm.data["count"] == 8

        xrefs = service.r2_xrefs(session_id, 0x1000)
        assert xrefs.ok is True, xrefs.error
        assert xrefs.data is not None and xrefs.data["address"] == 0x1000
    finally:
        service.close_all()


def test_r2_methods_map_r2_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An R2Error from any r2 method keeps its structured code."""

    class _RaisingR2(_FakeR2):
        def open(self, *args: object, **kwargs: object) -> dict[str, Any]:
            raise R2Error("backend_error", "r2 pipe died")

        def run(self, *args: object, **kwargs: object) -> dict[str, Any]:
            raise R2Error("timeout", "r2 command timed out")

        def disasm(self, *args: object, **kwargs: object) -> dict[str, Any]:
            raise R2Error("backend_error", "bad address")

        def xrefs(self, *args: object, **kwargs: object) -> dict[str, Any]:
            raise R2Error("backend_error", "xref scan failed")

    monkeypatch.setattr(service_ext, "R2Client", _RaisingR2)
    service, session_id = _service_with_session(tmp_path)
    try:
        assert service.r2_open(session_id).error.code == "backend_error"  # type: ignore[union-attr]
        assert service.r2_functions(session_id).error.code == "timeout"  # type: ignore[union-attr]
        assert service.r2_disasm(session_id, 0x1000).error.code == "backend_error"  # type: ignore[union-attr]
        assert service.r2_xrefs(session_id, 0x1000).error.code == "backend_error"  # type: ignore[union-attr]
    finally:
        service.close_all()


def test_r2_open_maps_an_unexpected_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _BoomR2(_FakeR2):
        def open(self, *args: object, **kwargs: object) -> dict[str, Any]:
            raise RuntimeError("r2pipe import blew up")

    monkeypatch.setattr(service_ext, "R2Client", _BoomR2)
    service, session_id = _service_with_session(tmp_path)
    try:
        result = service.r2_open(session_id)
        assert result.ok is False
        assert result.error is not None and result.error.code == "internal_error"
    finally:
        service.close_all()


def test_r2_disasm_and_xrefs_map_unexpected_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _BoomR2(_FakeR2):
        def disasm(self, *args: object, **kwargs: object) -> dict[str, Any]:
            raise RuntimeError("r2 process crashed")

        def xrefs(self, *args: object, **kwargs: object) -> dict[str, Any]:
            raise RuntimeError("r2 process crashed")

    monkeypatch.setattr(service_ext, "R2Client", _BoomR2)
    service, session_id = _service_with_session(tmp_path)
    try:
        assert service.r2_disasm(session_id, 0x1000).error.code == "internal_error"  # type: ignore[union-attr]
        assert service.r2_xrefs(session_id, 0x1000).error.code == "internal_error"  # type: ignore[union-attr]
    finally:
        service.close_all()


def test_r2_disasm_and_xrefs_refuse_a_closed_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A retained CLOSED session must not start r2 for disasm/xrefs either."""
    calls: list[str] = []

    class _TrackR2(_FakeR2):
        def disasm(self, *args: object, **kwargs: object) -> dict[str, Any]:
            calls.append("disasm")
            return super().disasm(*args, **kwargs)  # type: ignore[arg-type]

        def xrefs(self, *args: object, **kwargs: object) -> dict[str, Any]:
            calls.append("xrefs")
            return super().xrefs(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(service_ext, "R2Client", lambda *a, **k: _TrackR2())
    service, session_id = _service_with_session(tmp_path)
    try:
        assert service.close_session(session_id).ok
        assert service.r2_disasm(session_id, 0x1000).error.code == "invalid_request"  # type: ignore[union-attr]
        assert service.r2_xrefs(session_id, 0x1000).error.code == "invalid_request"  # type: ignore[union-attr]
        assert calls == []
    finally:
        service.close_all()


def test_r2_disasm_does_not_record_when_the_session_closes_mid_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A close during r2.disasm re-checks state and refuses to record a backend."""
    service, session_id = _service_with_session(tmp_path)

    class _CloseThenDisasm(_FakeR2):
        def disasm(self, *args: object, **kwargs: object) -> dict[str, Any]:
            service.close_session(session_id)
            return super().disasm(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(service_ext, "R2Client", lambda *a, **k: _CloseThenDisasm())
    try:
        result = service.r2_disasm(session_id, 0x1000)
        assert result.ok is False
        assert result.error is not None and result.error.code == "invalid_request"
    finally:
        service.close_all()


def test_r2_xrefs_does_not_record_when_the_session_closes_mid_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _service_with_session(tmp_path)

    class _CloseThenXrefs(_FakeR2):
        def xrefs(self, *args: object, **kwargs: object) -> dict[str, Any]:
            service.close_session(session_id)
            return super().xrefs(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(service_ext, "R2Client", lambda *a, **k: _CloseThenXrefs())
    try:
        result = service.r2_xrefs(session_id, 0x1000)
        assert result.ok is False
        assert result.error is not None and result.error.code == "invalid_request"
    finally:
        service.close_all()


def test_r2_request_does_not_record_when_the_session_closes_mid_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The shared whitelist-command path guards the post-run state too."""
    service, session_id = _service_with_session(tmp_path)

    class _CloseThenRun(_FakeR2):
        def run(self, *args: object, **kwargs: object) -> dict[str, Any]:
            service.close_session(session_id)
            return super().run(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(service_ext, "R2Client", lambda *a, **k: _CloseThenRun())
    try:
        result = service.r2_info(session_id)
        assert result.ok is False
        assert result.error is not None and result.error.code == "invalid_request"
    finally:
        service.close_all()


# ============================================================================
# Ghidra
# ============================================================================


class _FakeGhidra:
    def __init__(self, *_args: object, export_path: str | None = None, **_kwargs: object) -> None:
        self._export_path = export_path

    def analyze_binary(
        self, binary: Path, project: Path, *, timeout: float = 120.0
    ) -> dict[str, Any]:
        del binary, project, timeout
        return {"analyzed": True, "note": "fake"}

    def _export(self, project: Path) -> dict[str, Any]:
        payload: dict[str, Any] = {"items": [], "count": 0, "has_more": False}
        if self._export_path is not None:
            payload["export_path"] = self._export_path
        return payload

    def functions(
        self, binary: Path, project: Path, *, limit: int = 256, timeout: float = 180.0
    ) -> dict[str, Any]:
        del binary, limit, timeout
        return self._export(project)

    def symbols(
        self, binary: Path, project: Path, *, limit: int = 256, timeout: float = 180.0
    ) -> dict[str, Any]:
        del binary, limit, timeout
        return self._export(project)

    def xrefs(
        self, binary: Path, project: Path, address: Any, *, limit: int = 256, timeout: float = 180.0
    ) -> dict[str, Any]:
        del binary, limit, timeout
        return {"address": address, "items": []}

    def decompile(
        self, binary: Path, project: Path, address: Any, *, timeout: float = 180.0
    ) -> dict[str, Any]:
        del binary, project, timeout
        return {"address": address, "code": "int main(){}"}


def test_ghidra_analyze_records_and_wraps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(service_ext, "GhidraClient", _FakeGhidra)
    service, session_id = _service_with_session(tmp_path)
    try:
        result = service.ghidra_analyze(session_id)
        assert result.ok is True, result.error
        assert result.data is not None and result.data["analyzed"] is True
        assert result.meta.get("backend") == "ghidra"
    finally:
        service.close_all()


def test_ghidra_export_modes_succeed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(service_ext, "GhidraClient", _FakeGhidra)
    service, session_id = _service_with_session(tmp_path)
    try:
        assert service.ghidra_functions(session_id).ok is True
        assert service.ghidra_symbols(session_id).ok is True
        xrefs = service.ghidra_xrefs(session_id, "0x401000")
        assert xrefs.ok is True and xrefs.data is not None
        decomp = service.ghidra_decompile(session_id, "0x401000")
        assert decomp.ok is True and decomp.data is not None and "code" in decomp.data
    finally:
        service.close_all()


def test_ghidra_xrefs_and_decompile_require_an_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The address-taking exports refuse a None address up front."""
    monkeypatch.setattr(service_ext, "GhidraClient", _FakeGhidra)
    service, session_id = _service_with_session(tmp_path)
    try:
        assert service.ghidra_xrefs(session_id, None).error.code == "invalid_params"  # type: ignore[arg-type,union-attr]
        assert service.ghidra_decompile(session_id, None).error.code == "invalid_params"  # type: ignore[arg-type,union-attr]
    finally:
        service.close_all()


def test_ghidra_export_records_an_artifact_when_a_file_is_produced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A full decompilation exported to disk is hashed and registered."""
    export_file = tmp_path / "decomp.c"
    export_file.write_text("int main(){return 0;}", encoding="utf-8")
    monkeypatch.setattr(
        service_ext,
        "GhidraClient",
        lambda *a, **k: _FakeGhidra(export_path=str(export_file)),
    )
    service, session_id = _service_with_session(tmp_path)
    try:
        result = service.ghidra_functions(session_id)
        assert result.ok is True, result.error
        assert result.data is not None and "artifact_id" in result.data
    finally:
        service.close_all()


def test_ghidra_maps_a_ghidra_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class _RaisingGhidra(_FakeGhidra):
        def analyze_binary(self, *args: object, **kwargs: object) -> dict[str, Any]:
            raise GhidraError("backend_error", "headless analysis failed")

        def functions(self, *args: object, **kwargs: object) -> dict[str, Any]:
            raise GhidraError("timeout", "export timed out")

    monkeypatch.setattr(service_ext, "GhidraClient", _RaisingGhidra)
    service, session_id = _service_with_session(tmp_path)
    try:
        assert service.ghidra_analyze(session_id).error.code == "backend_error"  # type: ignore[union-attr]
        assert service.ghidra_functions(session_id).error.code == "timeout"  # type: ignore[union-attr]
    finally:
        service.close_all()


def test_ghidra_export_maps_an_unexpected_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _BoomGhidra(_FakeGhidra):
        def functions(self, *args: object, **kwargs: object) -> dict[str, Any]:
            raise RuntimeError("jvm launcher missing")

    monkeypatch.setattr(service_ext, "GhidraClient", _BoomGhidra)
    service, session_id = _service_with_session(tmp_path)
    try:
        result = service.ghidra_functions(session_id)
        assert result.ok is False
        assert result.error is not None and result.error.code == "internal_error"
    finally:
        service.close_all()


def test_ghidra_export_rejects_an_unknown_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The internal dispatcher fails closed on a mode it does not implement."""
    monkeypatch.setattr(service_ext, "GhidraClient", _FakeGhidra)
    service, session_id = _service_with_session(tmp_path)
    try:
        result = _ghidra_export(service, session_id, "does-not-exist")
        assert result.ok is False
        assert result.error is not None and result.error.code == "invalid_params"
    finally:
        service.close_all()


# ============================================================================
# Frida in-process probe (attach / modules / exports / memory / hook)
# ============================================================================


class _FakeFridaProbe:
    def attach(self, pid: int, *, allowed_pid: int) -> dict[str, Any]:
        del allowed_pid
        return {"pid": pid, "attached": True, "device": "local"}

    def modules(
        self, pid: int, *, allowed_pid: int, offset: int = 0, limit: int = 64
    ) -> dict[str, Any]:
        del pid, allowed_pid, offset, limit
        return {"modules": [], "count": 0}

    def exports(
        self,
        pid: int,
        module_name: str,
        *,
        allowed_pid: int,
        offset: int = 0,
        limit: int = 64,
    ) -> dict[str, Any]:
        del pid, allowed_pid, offset, limit
        return {"module": module_name, "exports": [], "count": 0}

    def memory_read(self, pid: int, address: int, size: int, *, allowed_pid: int) -> dict[str, Any]:
        del pid, allowed_pid
        return {"address": address, "size": size, "bytes": ""}

    def hook_template(self, pid: int, template: str, *, allowed_pid: int) -> dict[str, Any]:
        del pid, allowed_pid
        return {"template": template, "hooked": True}


def _patch_frida_probe(monkeypatch: pytest.MonkeyPatch, *, pid: int = 4242) -> None:
    monkeypatch.setattr(service_ext, "FridaClient", lambda *a, **k: _FakeFridaProbe())
    monkeypatch.setattr(service_ext, "_require_debuggee_pid", lambda service, session_id: pid)


def test_frida_probe_methods_record_and_wrap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """attach/modules/exports/memory_read/hook all wrap and record a timeline row."""
    _patch_frida_probe(monkeypatch)
    rows: list[tuple[str, dict[str, object]]] = []
    real_append = service_ext._timeline_append

    def _capture(service: object, session_id: str, event: str, message: str, **d: object) -> None:
        rows.append((event, d))
        real_append(service, session_id, event, message, **d)

    monkeypatch.setattr(service_ext, "_timeline_append", _capture)
    service, session_id = _service_with_session(tmp_path)
    try:
        assert service.frida_attach(session_id).ok is True
        assert service.frida_modules(session_id).ok is True
        assert service.frida_exports(session_id, "libc.so").ok is True
        mem = service.frida_memory_read(session_id, 0x1000, 16)
        assert mem.ok is True and mem.data is not None and mem.data["size"] == 16
        hook = service.frida_hook_template(session_id, "noop")
        assert hook.ok is True and hook.data is not None and hook.data["hooked"] is True
    finally:
        service.close_all()
    events = {event for event, _ in rows}
    # memory_read used to be the one probe that left no timeline row; it must now
    # record like its siblings so an arbitrary-memory read is not invisible in
    # the audit trail, and the row must carry the address/size (never the bytes).
    assert {"frida.attach", "frida.modules", "frida.exports", "frida.hook"} <= events
    memory_rows = [d for event, d in rows if event == "frida.memory.read"]
    assert memory_rows == [{"address": 0x1000, "size": 16}]


def test_frida_probe_methods_map_frida_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _RaisingFrida(_FakeFridaProbe):
        def attach(self, *args: object, **kwargs: object) -> dict[str, Any]:
            raise FridaError("backend_error", "attach refused")

        def modules(self, *args: object, **kwargs: object) -> dict[str, Any]:
            raise FridaError("timeout", "module walk stalled")

        def exports(self, *args: object, **kwargs: object) -> dict[str, Any]:
            raise FridaError("backend_error", "export walk failed")

        def memory_read(self, *args: object, **kwargs: object) -> dict[str, Any]:
            raise FridaError("invalid_params", "unreadable range")

        def hook_template(self, *args: object, **kwargs: object) -> dict[str, Any]:
            raise FridaError("backend_error", "script load failed")

    monkeypatch.setattr(service_ext, "FridaClient", lambda *a, **k: _RaisingFrida())
    monkeypatch.setattr(service_ext, "_require_debuggee_pid", lambda service, session_id: 4242)
    service, session_id = _service_with_session(tmp_path)
    try:
        assert service.frida_attach(session_id).error.code == "backend_error"  # type: ignore[union-attr]
        assert service.frida_modules(session_id).error.code == "timeout"  # type: ignore[union-attr]
        assert service.frida_exports(session_id, "libc.so").error.code == "backend_error"  # type: ignore[union-attr]
        assert service.frida_memory_read(session_id, 0x1000, 16).error.code == "invalid_params"  # type: ignore[union-attr]
        assert service.frida_hook_template(session_id).error.code == "backend_error"  # type: ignore[union-attr]
    finally:
        service.close_all()


def test_frida_probe_methods_map_unexpected_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A non-FridaError escaping the probe becomes the generic envelope."""

    class _BoomFrida(_FakeFridaProbe):
        def modules(self, *args: object, **kwargs: object) -> dict[str, Any]:
            raise RuntimeError("frida-core not loadable")

        def exports(self, *args: object, **kwargs: object) -> dict[str, Any]:
            raise RuntimeError("frida-core not loadable")

        def memory_read(self, *args: object, **kwargs: object) -> dict[str, Any]:
            raise RuntimeError("frida-core not loadable")

    monkeypatch.setattr(service_ext, "FridaClient", lambda *a, **k: _BoomFrida())
    monkeypatch.setattr(service_ext, "_require_debuggee_pid", lambda service, session_id: 4242)
    service, session_id = _service_with_session(tmp_path)
    try:
        assert service.frida_modules(session_id).error.code == "internal_error"  # type: ignore[union-attr]
        assert service.frida_exports(session_id, "libc.so").error.code == "internal_error"  # type: ignore[union-attr]
        assert service.frida_memory_read(session_id, 0x1000, 16).error.code == "internal_error"  # type: ignore[union-attr]
    finally:
        service.close_all()


def test_frida_attach_without_a_debuggee_is_invalid_state(tmp_path: Path) -> None:
    """A session with no active debuggee cannot be probed; the guard says so."""
    service, session_id = _service_with_session(tmp_path)
    try:
        result = service.frida_attach(session_id)
        assert result.ok is False
        assert result.error is not None and result.error.code == "invalid_state"
    finally:
        service.close_all()


# --- _require_debuggee_pid guard --------------------------------------------


class _FakeDynamicService:
    def __init__(self, result: Result[dict[str, Any]]) -> None:
        self._result = result

    def dynamic_state(self, session_id: str) -> Result[dict[str, Any]]:
        del session_id
        return self._result


def test_require_debuggee_pid_returns_a_live_pid() -> None:
    service = _FakeDynamicService(Result(ok=True, data={"debuggee_pid": 4242}))
    assert _require_debuggee_pid(service, "s") == 4242


@pytest.mark.parametrize("pid", [0, -1, None, "nope"])
def test_require_debuggee_pid_rejects_a_dead_or_absent_pid(pid: Any) -> None:
    service = _FakeDynamicService(Result(ok=True, data={"debuggee_pid": pid}))
    with pytest.raises(Exception) as caught:
        _require_debuggee_pid(service, "s")
    assert getattr(caught.value, "code", None) == "invalid_state"


def test_require_debuggee_pid_rejects_unreadable_state() -> None:
    service = _FakeDynamicService(
        Result(ok=False, error=RpcError(code="internal_error", message="no dynamic backend"))
    )
    with pytest.raises(Exception) as caught:
        _require_debuggee_pid(service, "s")
    assert getattr(caught.value, "code", None) == "invalid_state"
