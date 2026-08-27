"""Success and error envelopes for the optional-backend façade in service_ext.

The closed-session refusals live in their own files; this one drives the happy
paths, the backend-error mappings, and the small helper functions so every
optional backend and artifact op is exercised end to end with faked clients.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.core.service_ext as ext
from headless_re_mcp.backends.frida.client import FridaError
from headless_re_mcp.backends.ghidra.client import GhidraError
from headless_re_mcp.backends.r2.client import R2Error
from headless_re_mcp.backends.windbg.client import WindbgError
from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.capabilities_catalog import list_capabilities
from headless_re_mcp.core.models import Result, RpcError
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.service_ext import (
    _breakpoint_binding_address,
    _ghidra_export,
    _record_artifact,
    _register_capture,
    _require_debuggee_pid,
    note_session_created,
)


def _write_minimal_pe(path: Path) -> None:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = (0x8664).to_bytes(2, "little")
    path.write_bytes(image)


def _service(tmp_path: Path) -> tuple[AnalysisService, str]:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None, created.error
    return service, created.data["session"]["id"]


# --------------------------------------------------------------------------
# _breakpoint_binding_address guards
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("workflow", "intent", "message_part"),
    [
        ({"workflow": {}}, "", "must not be blank"),
        ({}, "i", "missing workflow data"),
        ({"workflow": {}}, "i", "missing workflow state"),
        ({"workflow": {"state": {}}}, "i", "missing breakpoint state"),
        (
            {"workflow": {"state": {"breakpoints": {}}}},
            "i",
            "invalid breakpoint bindings",
        ),
    ],
)
def test_breakpoint_binding_address_rejects_malformed_workflow(
    workflow: dict[str, Any], intent: str, message_part: str
) -> None:
    with pytest.raises((ValueError, XdbgRpcError)) as info:
        _breakpoint_binding_address(workflow, intent)
    assert message_part in str(info.value)


def test_breakpoint_binding_address_rejects_a_nonpositive_address() -> None:
    workflow = {
        "workflow": {"state": {"breakpoints": {"bindings": [{"intent_id": "t", "address": 0}]}}}
    }
    with pytest.raises(XdbgRpcError) as info:
        _breakpoint_binding_address(workflow, "t")
    assert "invalid address" in str(info.value)


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------


def test_record_artifact_falls_back_to_the_repository(tmp_path: Path) -> None:
    service = SimpleNamespace(settings=SimpleNamespace(artifact_root=tmp_path / "artifacts"))
    sample = tmp_path / "artifacts" / "a.bin"
    sample.parent.mkdir(parents=True)
    sample.write_bytes(b"data")
    artifact = _record_artifact(
        service,
        session_id="s",
        kind="dump",
        path=sample,
        sha256="0" * 64,
        source="test",
        size=4,
    )
    assert artifact["id"]


def test_register_capture_returns_payload_untouched_for_a_missing_file(
    tmp_path: Path,
) -> None:
    payload = {"path": str(tmp_path / "nope")}
    out = _register_capture(
        SimpleNamespace(),
        "s",
        tmp_path / "nope",
        kind="screenshot",
        source="test",
        payload=payload,
    )
    assert out is payload


def test_note_session_created_reports_a_store_failure_in_meta() -> None:
    class _Boom:
        def note_session_created(self, binary: str, result: Result[Any]) -> None:
            raise OSError("store gone")

    service = SimpleNamespace(repository=_Boom())
    result: Result[dict[str, Any]] = Result(ok=True, data={})
    note_session_created(service, "bin", result)
    assert result.meta["persisted"] is False
    assert "OSError" in result.meta["persist_error"]


# --------------------------------------------------------------------------
# capabilities
# --------------------------------------------------------------------------


def test_capabilities_describe_returns_a_known_capability(tmp_path: Path) -> None:
    service, _ = _service(tmp_path)
    try:
        cap_id = list_capabilities(service.settings)[0]["id"]
        result = service.capabilities_describe(cap_id)
        assert result.ok and result.data is not None
        assert result.data["capability"]["id"] == cap_id
    finally:
        service.close_all()


def test_capabilities_describe_reports_not_found(tmp_path: Path) -> None:
    service, _ = _service(tmp_path)
    try:
        result = service.capabilities_describe("does.not.exist")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "not_found"
    finally:
        service.close_all()


# --------------------------------------------------------------------------
# radare2
# --------------------------------------------------------------------------


class _FakeR2:
    def __init__(self, answer: Any = None) -> None:
        self.answer = answer if answer is not None else {"ok": True}

    def open(self, binary: Path, *, timeout: float = 30.0) -> dict[str, Any]:
        return dict(self.answer)

    def run(self, binary: Path, commands: list[str], *, timeout: float = 30.0) -> dict[str, Any]:
        return dict(self.answer)

    def disasm(
        self, binary: Path, address: int, *, count: int = 32, timeout: float = 30.0
    ) -> dict[str, Any]:
        return {"address": address, "count": count}

    def xrefs(self, binary: Path, address: int, *, timeout: float = 30.0) -> dict[str, Any]:
        return {"address": address}


def _patch_r2(monkeypatch: pytest.MonkeyPatch, client: Any) -> None:
    monkeypatch.setattr(ext, "R2Client", lambda *a, **k: client)


def test_r2_open_records_backend_and_timeline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _service(tmp_path)
    _patch_r2(monkeypatch, _FakeR2({"opened": True, "info": "arch x86"}))
    try:
        result = service.r2_open(session_id)
        assert result.ok and result.data is not None
        assert result.data["info"] == "arch x86"
        assert result.meta["backend"] == "radare2"
    finally:
        service.close_all()


def test_r2_info_runs_a_whitelisted_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _service(tmp_path)
    _patch_r2(monkeypatch, _FakeR2({"raw": "info"}))
    try:
        result = service.r2_info(session_id)
        assert result.ok and result.data is not None
        assert result.data["raw"] == "info"
    finally:
        service.close_all()


def test_r2_disasm_and_xrefs_forward_addresses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _service(tmp_path)
    _patch_r2(monkeypatch, _FakeR2())
    try:
        disasm = service.r2_disasm(session_id, 0x401000, count=8)
        assert disasm.ok and disasm.data is not None
        assert disasm.data["address"] == 0x401000
        assert disasm.data["count"] == 8
        xrefs = service.r2_xrefs(session_id, 0x402000)
        assert xrefs.ok and xrefs.data is not None
        assert xrefs.data["address"] == 0x402000
    finally:
        service.close_all()


class _R2Boom(_FakeR2):
    def open(self, binary: Path, *, timeout: float = 30.0) -> dict[str, Any]:
        raise R2Error("backend_error", "r2 crashed", where="open")

    def run(self, binary: Path, commands: list[str], *, timeout: float = 30.0) -> dict[str, Any]:
        raise R2Error("backend_error", "r2 crashed", where="run")

    def disasm(
        self, binary: Path, address: int, *, count: int = 32, timeout: float = 30.0
    ) -> dict[str, Any]:
        raise R2Error("backend_error", "r2 crashed", where="disasm")

    def xrefs(self, binary: Path, address: int, *, timeout: float = 30.0) -> dict[str, Any]:
        raise R2Error("backend_error", "r2 crashed", where="xrefs")


def test_r2_ops_map_r2error_to_a_failure_envelope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _service(tmp_path)
    _patch_r2(monkeypatch, _R2Boom())
    try:
        for result in (
            service.r2_open(session_id),
            service.r2_info(session_id),
            service.r2_disasm(session_id, 0x1000),
            service.r2_xrefs(session_id, 0x1000),
        ):
            assert result.ok is False
            assert result.error is not None
            assert result.error.code == "backend_error"
            assert result.error.details.get("where")
    finally:
        service.close_all()


# --------------------------------------------------------------------------
# ghidra
# --------------------------------------------------------------------------


class _FakeGhidra:
    def __init__(self, export_path: Path | None = None) -> None:
        self.export_path = export_path

    def analyze_binary(
        self, binary: Path, project: Path, *, timeout: float = 120.0
    ) -> dict[str, Any]:
        project.mkdir(parents=True, exist_ok=True)
        return {"project_dir": str(project)}

    def _export(self, project: Path) -> dict[str, Any]:
        project.mkdir(parents=True, exist_ok=True)
        payload: dict[str, Any] = {"items": [], "count": 0}
        if self.export_path is not None:
            payload["export_path"] = str(self.export_path)
        return payload

    def functions(
        self, binary: Path, project: Path, *, limit: int = 256, timeout: float = 180.0
    ) -> dict[str, Any]:
        return self._export(project)

    def symbols(
        self, binary: Path, project: Path, *, limit: int = 256, timeout: float = 180.0
    ) -> dict[str, Any]:
        return self._export(project)

    def xrefs(
        self,
        binary: Path,
        project: Path,
        address: Any,
        *,
        limit: int = 256,
        timeout: float = 180.0,
    ) -> dict[str, Any]:
        return self._export(project)

    def decompile(
        self, binary: Path, project: Path, address: Any, *, timeout: float = 180.0
    ) -> dict[str, Any]:
        return self._export(project)


def test_ghidra_analyze_success_records_backend(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _service(tmp_path)
    monkeypatch.setattr(ext, "GhidraClient", lambda *a, **k: _FakeGhidra())
    try:
        result = service.ghidra_analyze(session_id)
        assert result.ok and result.data is not None
        assert result.meta["backend"] == "ghidra"
    finally:
        service.close_all()


def test_ghidra_analyze_maps_ghidra_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class _Boom(_FakeGhidra):
        def analyze_binary(
            self, binary: Path, project: Path, *, timeout: float = 120.0
        ) -> dict[str, Any]:
            raise GhidraError("backend_error", "jvm died")

    service, session_id = _service(tmp_path)
    monkeypatch.setattr(ext, "GhidraClient", lambda *a, **k: _Boom())
    try:
        result = service.ghidra_analyze(session_id)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "backend_error"
    finally:
        service.close_all()


def test_ghidra_exports_cover_every_mode_and_register_the_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    export = tmp_path / "export.json"
    export.write_text("{}", encoding="utf-8")
    service, session_id = _service(tmp_path)
    monkeypatch.setattr(ext, "GhidraClient", lambda *a, **k: _FakeGhidra(export))
    try:
        functions = service.ghidra_functions(session_id)
        assert functions.ok and functions.data is not None
        assert functions.data["artifact_id"]
        assert service.ghidra_symbols(session_id).ok
        assert service.ghidra_xrefs(session_id, "0x1000").ok
        assert service.ghidra_decompile(session_id, "0x1000").ok
    finally:
        service.close_all()


def test_ghidra_export_requires_an_address_and_rejects_unknown_modes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _service(tmp_path)
    monkeypatch.setattr(ext, "GhidraClient", lambda *a, **k: _FakeGhidra())
    try:
        missing_xrefs = _ghidra_export(service, session_id, "xrefs", address=None)
        assert missing_xrefs.ok is False
        assert missing_xrefs.error is not None
        assert "address required" in missing_xrefs.error.message

        missing_decompile = _ghidra_export(service, session_id, "decompile", address=None)
        assert missing_decompile.ok is False

        unknown = _ghidra_export(service, session_id, "bogus")
        assert unknown.ok is False
        assert unknown.error is not None
        assert unknown.error.code == "invalid_params"
    finally:
        service.close_all()


# --------------------------------------------------------------------------
# frida
# --------------------------------------------------------------------------


class _FakeFrida:
    def attach(self, pid: int, *, allowed_pid: int) -> dict[str, Any]:
        return {"pid": pid, "attached": True}

    def modules(self, pid: int, *, allowed_pid: int, limit: int = 64) -> dict[str, Any]:
        return {"count": 2, "items": []}

    def exports(
        self, pid: int, module_name: str, *, allowed_pid: int, limit: int = 64
    ) -> dict[str, Any]:
        return {"module": module_name, "count": 1}

    def memory_read(self, pid: int, address: int, size: int, *, allowed_pid: int) -> dict[str, Any]:
        return {"address": address, "size": size}

    def hook_template(self, pid: int, template: str, *, allowed_pid: int) -> dict[str, Any]:
        return {"template": template, "pid": pid}

    def hook_template_device(
        self,
        device_id: Any,
        pid: int,
        template: str,
        *,
        allowed_pids: list[int],
    ) -> dict[str, Any]:
        return {"template": template, "pid": pid, "device_id": device_id}


def _with_debuggee(service: AnalysisService, pid: int = 4242) -> None:
    service.dynamic_state = lambda session_id: Result(  # type: ignore[method-assign]
        ok=True, data={"debuggee_pid": pid}
    )


def test_frida_ops_succeed_against_an_authorized_pid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _service(tmp_path)
    monkeypatch.setattr(ext, "FridaClient", lambda *a, **k: _FakeFrida())
    _with_debuggee(service)
    try:
        assert service.frida_attach(session_id).ok
        modules = service.frida_modules(session_id)
        assert modules.ok and modules.data is not None
        assert modules.data["count"] == 2
        exports = service.frida_exports(session_id, "kernel32.dll")
        assert exports.ok and exports.data is not None
        assert exports.data["module"] == "kernel32.dll"
        read = service.frida_memory_read(session_id, 0x1000, 16)
        assert read.ok and read.data is not None
        assert read.data["size"] == 16
        hook = service.frida_hook_template(session_id)
        assert hook.ok and hook.data is not None
        assert hook.data["template"] == "noop"
    finally:
        service.close_all()


def test_frida_hook_template_uses_the_authorized_device_pid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _service(tmp_path)
    monkeypatch.setattr(ext, "FridaClient", lambda *a, **k: _FakeFrida())
    service.registry.update_metadata(
        session_id,
        {"frida_authorized": {"device_id": "emulator-5554", "pids": [10, 20]}},
    )
    try:
        result = service.frida_hook_template(session_id, template="trace")
        assert result.ok and result.data is not None
        assert result.data["device_id"] == "emulator-5554"
        assert result.data["pid"] == 20
    finally:
        service.close_all()


def test_frida_attach_maps_frida_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class _Boom(_FakeFrida):
        def attach(self, pid: int, *, allowed_pid: int) -> dict[str, Any]:
            raise FridaError("backend_error", "device offline")

    service, session_id = _service(tmp_path)
    monkeypatch.setattr(ext, "FridaClient", lambda *a, **k: _Boom())
    _with_debuggee(service)
    try:
        result = service.frida_attach(session_id)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "backend_error"
    finally:
        service.close_all()


def test_require_debuggee_pid_refuses_a_static_session(tmp_path: Path) -> None:
    service, session_id = _service(tmp_path)
    try:
        with pytest.raises(XdbgRpcError) as info:
            _require_debuggee_pid(service, session_id)
        assert info.value.code == "invalid_state"
    finally:
        service.close_all()


def test_require_debuggee_pid_refuses_when_state_is_unreadable(
    tmp_path: Path,
) -> None:
    service, session_id = _service(tmp_path)
    service.dynamic_state = lambda session_id: Result(  # type: ignore[method-assign]
        ok=False, error=RpcError(code="invalid_state", message="no debugger")
    )
    try:
        with pytest.raises(XdbgRpcError):
            _require_debuggee_pid(service, session_id)
    finally:
        service.close_all()


# --------------------------------------------------------------------------
# windbg
# --------------------------------------------------------------------------


class _FakeWindbg:
    def open_dump(
        self, dump: Path, commands: list[str], *, timeout: float, kernel: bool
    ) -> dict[str, Any]:
        return {"commands": commands, "kernel": kernel}

    def threads(self, dump: Path, *, timeout: float) -> dict[str, Any]:
        return {"threads": []}

    def modules(self, dump: Path, *, timeout: float) -> dict[str, Any]:
        return {"modules": []}

    def disasm(self, dump: Path, address: Any, *, length: int, timeout: float) -> dict[str, Any]:
        return {"address": str(address), "length": length}

    def attach(self, pid: int, *, allowed_pid: int, timeout: float) -> dict[str, Any]:
        return {"pid": pid}

    def live_threads(self, pid: int, *, allowed_pid: int, timeout: float) -> dict[str, Any]:
        return {"pid": pid, "threads": []}

    def live_modules(self, pid: int, *, allowed_pid: int, timeout: float) -> dict[str, Any]:
        return {"pid": pid, "modules": []}

    def live_disasm(
        self, pid: int, address: Any, *, allowed_pid: int, length: int, timeout: float
    ) -> dict[str, Any]:
        return {"pid": pid, "address": str(address)}


def _windows_windbg(monkeypatch: pytest.MonkeyPatch, client: Any) -> None:
    monkeypatch.setattr(ext, "is_windows_host", lambda: True)
    monkeypatch.setattr(ext, "WindbgClient", lambda *a, **k: client)


def test_windbg_dump_ops_succeed_on_a_windows_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _windows_windbg(monkeypatch, _FakeWindbg())
    service, _ = _service(tmp_path)
    dump = str(tmp_path / "crash.dmp")
    try:
        opened = service.windbg_open_dump(dump, ["lm"], kernel=False)
        assert opened.ok and opened.data is not None
        assert opened.data["commands"] == ["lm"]
        assert service.windbg_threads(dump).ok
        assert service.windbg_modules(dump).ok
        assert service.windbg_disasm(dump, "0x1000").ok
    finally:
        service.close_all()


def test_windbg_live_ops_succeed_against_a_debuggee(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _windows_windbg(monkeypatch, _FakeWindbg())
    service, session_id = _service(tmp_path)
    _with_debuggee(service)
    try:
        assert service.windbg_attach(session_id).ok
        assert service.windbg_live_threads(session_id).ok
        assert service.windbg_live_modules(session_id).ok
        assert service.windbg_live_disasm(session_id, "0x1000").ok
    finally:
        service.close_all()


def test_windbg_maps_backend_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class _Boom(_FakeWindbg):
        def threads(self, dump: Path, *, timeout: float) -> dict[str, Any]:
            raise WindbgError("backend_error", "cdb crashed")

    _windows_windbg(monkeypatch, _Boom())
    service, _ = _service(tmp_path)
    try:
        result = service.windbg_threads(str(tmp_path / "crash.dmp"))
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "backend_error"
    finally:
        service.close_all()


def test_windbg_live_ops_map_backend_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class _Boom(_FakeWindbg):
        def attach(self, pid: int, *, allowed_pid: int, timeout: float) -> dict[str, Any]:
            raise WindbgError("backend_error", "attach failed")

        def live_threads(self, pid: int, *, allowed_pid: int, timeout: float) -> dict[str, Any]:
            raise WindbgError("backend_error", "threads failed")

        def live_modules(self, pid: int, *, allowed_pid: int, timeout: float) -> dict[str, Any]:
            raise WindbgError("backend_error", "modules failed")

        def live_disasm(
            self,
            pid: int,
            address: Any,
            *,
            allowed_pid: int,
            length: int,
            timeout: float,
        ) -> dict[str, Any]:
            raise WindbgError("backend_error", "disasm failed")

    _windows_windbg(monkeypatch, _Boom())
    service, session_id = _service(tmp_path)
    _with_debuggee(service)
    try:
        for result in (
            service.windbg_attach(session_id),
            service.windbg_live_threads(session_id),
            service.windbg_live_modules(session_id),
            service.windbg_live_disasm(session_id, "0x1000"),
        ):
            assert result.ok is False
            assert result.error is not None
            assert result.error.code == "backend_error"
    finally:
        service.close_all()


def test_windbg_is_unsupported_off_windows(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ext, "is_windows_host", lambda: False)
    service, _ = _service(tmp_path)
    try:
        result = service.windbg_modules(str(tmp_path / "crash.dmp"))
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "unsupported_on_platform"
    finally:
        service.close_all()


# --------------------------------------------------------------------------
# artifacts_read guards
# --------------------------------------------------------------------------


def test_artifacts_read_refuses_a_path_outside_the_artifact_root(
    tmp_path: Path,
) -> None:
    service, session_id = _service(tmp_path)
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"secret")
    try:
        repo = ext._ensure_repository(service)
        artifact = repo.register_artifact(
            session_id=session_id,
            kind="dump",
            path=outside,
            sha256="0" * 64,
            source="test",
            size=6,
        )
        result = service.artifacts_read(artifact["id"])
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "permission_denied"
    finally:
        service.close_all()


def test_artifacts_read_reports_a_missing_file(tmp_path: Path) -> None:
    service, session_id = _service(tmp_path)
    root = service.settings.artifact_root.expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    ghost = root / "ghost.bin"
    try:
        repo = ext._ensure_repository(service)
        artifact = repo.register_artifact(
            session_id=session_id,
            kind="dump",
            path=ghost,
            sha256="0" * 64,
            source="test",
            size=0,
        )
        result = service.artifacts_read(artifact["id"])
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "not_found"
    finally:
        service.close_all()


# --------------------------------------------------------------------------
# peek_session_record
# --------------------------------------------------------------------------


def test_peek_session_record_reads_the_stored_row_after_close(
    tmp_path: Path,
) -> None:
    service, session_id = _service(tmp_path)
    try:
        service.close_session(session_id)
        service.registry.remove_closed(session_id)
        result = service.peek_session_record(session_id)
        assert result.ok and result.data is not None
        assert result.data["live"] is False
        assert result.data["id"] == session_id
    finally:
        service.close_all()


def test_peek_session_record_reports_an_unknown_id(tmp_path: Path) -> None:
    service, _ = _service(tmp_path)
    try:
        result = service.peek_session_record("00000000-0000-0000-0000-000000000000")
        assert result.ok is False
        assert result.error is not None
    finally:
        service.close_all()


# --------------------------------------------------------------------------
# batch_analyze
# --------------------------------------------------------------------------


def test_batch_analyze_rejects_more_than_32_paths(tmp_path: Path) -> None:
    service, _ = _service(tmp_path)
    try:
        result = service.batch_analyze([f"/tmp/b{i}.exe" for i in range(33)])
        assert result.ok is False
        assert result.error is not None
        assert "at most 32" in result.error.message
    finally:
        service.close_all()


def test_batch_analyze_reports_per_entry_outcomes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, _ = _service(tmp_path)

    def fake_create(path: str) -> Result[dict[str, Any]]:
        if "bad" in path:
            return Result(ok=False, error=RpcError(code="invalid_params", message="no"))
        if "empty" in path:
            return Result(ok=True, data={"session": "not-a-dict"})
        return Result(ok=True, data={"session": {"id": f"id-for-{Path(path).name}"}})

    def fake_open_static(session_id: str) -> Result[dict[str, Any]]:
        if "fail" in session_id:
            return Result(ok=False, error=RpcError(code="backend_error", message="static failed"))
        return Result(ok=True, data={})

    monkeypatch.setattr(service, "create_session", fake_create)
    monkeypatch.setattr(service, "open_static", fake_open_static)
    try:
        result = service.batch_analyze(
            ["/tmp/good.exe", "/tmp/bad.exe", "/tmp/empty.exe", "/tmp/fail.exe"],
            max_workers=1,
        )
        assert result.ok and result.data is not None
        entries = {entry["binary"]: entry for entry in result.data["entries"]}
        assert entries["/tmp/good.exe"]["ok"] is True
        assert entries["/tmp/bad.exe"]["error"]["code"] == "invalid_params"
        assert entries["/tmp/empty.exe"]["error"]["message"] == "no session"
        assert entries["/tmp/fail.exe"]["ok"] is False
        assert entries["/tmp/fail.exe"]["static_open"] is False
    finally:
        service.close_all()


def test_batch_analyze_tolerates_a_created_error_that_is_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, _ = _service(tmp_path)
    monkeypatch.setattr(
        service,
        "create_session",
        lambda path: Result(ok=True, data=None),
    )
    try:
        result = service.batch_analyze(["/tmp/x.exe"], max_workers=1)
        assert result.ok and result.data is not None
        assert result.data["entries"][0]["ok"] is False
        assert "error" not in result.data["entries"][0]
    finally:
        service.close_all()


# --------------------------------------------------------------------------
# knowledge / report / tool metrics validation
# --------------------------------------------------------------------------


def test_knowledge_record_rejects_blank_and_oversized_kind_key(
    tmp_path: Path,
) -> None:
    service, session_id = _service(tmp_path)
    try:
        blank_kind = service.knowledge_record(session_id, "  ", "key")
        assert blank_kind.ok is False
        assert blank_kind.error is not None
        assert "kind must" in blank_kind.error.message

        blank_key = service.knowledge_record(session_id, "finding", "x" * 300)
        assert blank_key.ok is False
        assert blank_key.error is not None
        assert "key must" in blank_key.error.message
    finally:
        service.close_all()


def test_report_generate_rejects_a_bad_audit_limit(tmp_path: Path) -> None:
    service, session_id = _service(tmp_path)
    try:
        result = service.report_generate(session_id, audit_limit=0)
        assert result.ok is False
        assert result.error is not None
        assert "audit_limit must be 1..200" in result.error.message
    finally:
        service.close_all()


def test_tool_metrics_rejects_a_bad_limit(tmp_path: Path) -> None:
    service, _ = _service(tmp_path)
    try:
        result = service.tool_metrics(limit=-1)
        assert result.ok is False
        assert result.error is not None
        assert "limit must be 0..200" in result.error.message
    finally:
        service.close_all()


def test_tool_metrics_returns_the_current_sample(tmp_path: Path) -> None:
    service, _ = _service(tmp_path)
    try:
        result = service.tool_metrics(limit=5)
        assert result.ok and result.data is not None
        assert "recent" in result.data
    finally:
        service.close_all()


def test_knowledge_record_rejects_an_oversized_value(tmp_path: Path) -> None:
    service, session_id = _service(tmp_path)
    try:
        huge = {"blob": "x" * 9000}
        result = service.knowledge_record(session_id, "finding", "big", huge)
        assert result.ok is False
        assert result.error is not None
        assert "serialises to" in result.error.message
    finally:
        service.close_all()


def test_knowledge_query_maps_an_unknown_session(tmp_path: Path) -> None:
    service, _ = _service(tmp_path)
    try:
        result = service.knowledge_query("00000000-0000-0000-0000-000000000000")
        assert result.ok is False
        assert result.error is not None
    finally:
        service.close_all()


# --------------------------------------------------------------------------
# additional r2 state-gate branches
# --------------------------------------------------------------------------


def test_r2_disasm_and_xrefs_refuse_a_closed_session(tmp_path: Path) -> None:
    service, session_id = _service(tmp_path)
    try:
        service.close_session(session_id)
        disasm = service.r2_disasm(session_id, 0x1000)
        assert disasm.ok is False
        assert disasm.error is not None
        assert "closed" in disasm.error.message
        xrefs = service.r2_xrefs(session_id, 0x1000)
        assert xrefs.ok is False
        assert xrefs.error is not None
        assert "closed" in xrefs.error.message
    finally:
        service.close_all()


@pytest.mark.parametrize("op", ["info", "disasm", "xrefs"])
def test_r2_ops_refuse_a_session_that_closes_mid_run(
    op: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A fresh session per op: the mid-run close must fire while this op runs,
    # not leave a session already closed by an earlier op in the same test.
    service, session_id = _service(tmp_path)

    class _CloseThenAnswer(_FakeR2):
        def run(
            self, binary: Path, commands: list[str], *, timeout: float = 30.0
        ) -> dict[str, Any]:
            service.close_session(session_id)
            return {"raw": "late"}

        def disasm(
            self,
            binary: Path,
            address: int,
            *,
            count: int = 32,
            timeout: float = 30.0,
        ) -> dict[str, Any]:
            service.close_session(session_id)
            return {"address": address}

        def xrefs(self, binary: Path, address: int, *, timeout: float = 30.0) -> dict[str, Any]:
            service.close_session(session_id)
            return {"address": address}

    _patch_r2(monkeypatch, _CloseThenAnswer())
    try:
        if op == "info":
            result = service.r2_info(session_id)
        elif op == "disasm":
            result = service.r2_disasm(session_id, 0x1000)
        else:
            result = service.r2_xrefs(session_id, 0x1000)
        assert result.ok is False
        assert result.error is not None
        assert "closed" in result.error.message
    finally:
        service.close_all()


# --------------------------------------------------------------------------
# frida error mapping for the remaining ops
# --------------------------------------------------------------------------


def test_frida_ops_map_frida_error_across_the_surface(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _AllBoom(_FakeFrida):
        def modules(self, pid: int, *, allowed_pid: int, limit: int = 64) -> dict[str, Any]:
            raise FridaError("backend_error", "modules failed")

        def exports(
            self, pid: int, module_name: str, *, allowed_pid: int, limit: int = 64
        ) -> dict[str, Any]:
            raise FridaError("backend_error", "exports failed")

        def memory_read(
            self, pid: int, address: int, size: int, *, allowed_pid: int
        ) -> dict[str, Any]:
            raise FridaError("backend_error", "read failed")

        def hook_template(self, pid: int, template: str, *, allowed_pid: int) -> dict[str, Any]:
            raise FridaError("backend_error", "hook failed")

    service, session_id = _service(tmp_path)
    monkeypatch.setattr(ext, "FridaClient", lambda *a, **k: _AllBoom())
    _with_debuggee(service)
    try:
        for result in (
            service.frida_modules(session_id),
            service.frida_exports(session_id, "kernel32.dll"),
            service.frida_memory_read(session_id, 0x1000, 16),
            service.frida_hook_template(session_id),
        ):
            assert result.ok is False
            assert result.error is not None
            assert result.error.code == "backend_error"
    finally:
        service.close_all()


# --------------------------------------------------------------------------
# windbg generic-exception mapping
# --------------------------------------------------------------------------


def test_windbg_ops_map_an_unexpected_exception(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _AllBoom(_FakeWindbg):
        def open_dump(
            self, dump: Path, commands: list[str], *, timeout: float, kernel: bool
        ) -> dict[str, Any]:
            raise RuntimeError("crash")

        def threads(self, dump: Path, *, timeout: float) -> dict[str, Any]:
            raise RuntimeError("crash")

        def modules(self, dump: Path, *, timeout: float) -> dict[str, Any]:
            raise RuntimeError("crash")

        def disasm(
            self, dump: Path, address: Any, *, length: int, timeout: float
        ) -> dict[str, Any]:
            raise RuntimeError("crash")

        def attach(self, pid: int, *, allowed_pid: int, timeout: float) -> dict[str, Any]:
            raise RuntimeError("crash")

        def live_threads(self, pid: int, *, allowed_pid: int, timeout: float) -> dict[str, Any]:
            raise RuntimeError("crash")

        def live_modules(self, pid: int, *, allowed_pid: int, timeout: float) -> dict[str, Any]:
            raise RuntimeError("crash")

        def live_disasm(
            self,
            pid: int,
            address: Any,
            *,
            allowed_pid: int,
            length: int,
            timeout: float,
        ) -> dict[str, Any]:
            raise RuntimeError("crash")

    _windows_windbg(monkeypatch, _AllBoom())
    service, session_id = _service(tmp_path)
    _with_debuggee(service)
    dump = str(tmp_path / "crash.dmp")
    try:
        for result in (
            service.windbg_open_dump(dump),
            service.windbg_threads(dump),
            service.windbg_modules(dump),
            service.windbg_disasm(dump, "0x1000"),
            service.windbg_attach(session_id),
            service.windbg_live_threads(session_id),
            service.windbg_live_modules(session_id),
            service.windbg_live_disasm(session_id, "0x1000"),
        ):
            assert result.ok is False
            assert result.error is not None
    finally:
        service.close_all()


# --------------------------------------------------------------------------
# _require_debuggee_pid missing-pid, ghidra no-export, batch invalid envelope
# --------------------------------------------------------------------------


def test_require_debuggee_pid_refuses_state_without_a_pid(tmp_path: Path) -> None:
    service, session_id = _service(tmp_path)
    service.dynamic_state = lambda session_id: Result(  # type: ignore[method-assign]
        ok=True, data={"debugger_pid": 100}
    )
    try:
        with pytest.raises(XdbgRpcError) as info:
            _require_debuggee_pid(service, session_id)
        assert "no active debuggee" in str(info.value)
    finally:
        service.close_all()


def test_ghidra_export_without_an_export_path_omits_the_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _service(tmp_path)
    monkeypatch.setattr(ext, "GhidraClient", lambda *a, **k: _FakeGhidra())
    try:
        result = service.ghidra_functions(session_id)
        assert result.ok and result.data is not None
        assert "artifact_id" not in result.data
    finally:
        service.close_all()


def test_batch_analyze_tolerates_an_open_static_result_without_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, _ = _service(tmp_path)
    monkeypatch.setattr(
        service,
        "create_session",
        lambda path: Result(ok=True, data={"session": {"id": "sid"}}),
    )
    monkeypatch.setattr(
        service,
        "open_static",
        lambda session_id: Result.model_construct(ok=False, error=None),
    )
    try:
        result = service.batch_analyze(["/tmp/x.exe"], max_workers=1)
        assert result.ok and result.data is not None
        entry = result.data["entries"][0]
        assert entry["ok"] is False
        assert entry["static_open"] is False
        assert "error" not in entry
    finally:
        service.close_all()


def test_batch_analyze_skips_static_open_when_disabled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, _ = _service(tmp_path)
    monkeypatch.setattr(
        service,
        "create_session",
        lambda path: Result(ok=True, data={"session": {"id": "sid"}}),
    )
    called = {"n": 0}

    def _open_static(session_id: str) -> Result[dict[str, Any]]:
        called["n"] += 1
        return Result(ok=True, data={})

    monkeypatch.setattr(service, "open_static", _open_static)
    try:
        result = service.batch_analyze(["/tmp/x.exe"], max_workers=1, open_static=False)
        assert result.ok and result.data is not None
        assert called["n"] == 0
        assert "static_open" not in result.data["entries"][0]
    finally:
        service.close_all()


def test_ui_drive_to_breakpoint_maps_a_binding_error() -> None:
    service = object.__new__(AnalysisService)
    workflow: Result[dict[str, Any]] = Result(
        ok=True,
        data={"workflow": {"state": {"breakpoints": {"bindings": []}}}},
    )
    service.workflow_status = lambda session_id: workflow  # type: ignore[method-assign]
    result = service.ui_drive_to_breakpoint("sess", "transform")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "invalid_state"
