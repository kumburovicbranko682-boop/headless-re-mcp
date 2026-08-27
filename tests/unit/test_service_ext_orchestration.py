"""The optional-backend and artifact surface must gate, delegate and map errors.

``ExtAnalysisMixin`` fronts the optional foreign tools (radare2, Ghidra, Frida,
WinDbg) and the durable artifact/knowledge/report store. Every backend op
refuses to run against a terminal session, instantiates its client, maps a
backend error (keeping the transient ``timeout`` signal) onto a structured
``Result`` and records a timeline/backend row on success. The real executables
are absent here, so the client classes are monkeypatched in the module
namespace and the store-backed ops run against the real on-disk SQLite store.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.frida.client import FridaError
from headless_re_mcp.backends.ghidra.client import GhidraError
from headless_re_mcp.backends.r2.client import R2Error
from headless_re_mcp.backends.windbg.client import WindbgError
from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.core import service_ext
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.store.sqlite_store import KNOWLEDGE_VALUE_MAX_CHARS
from tests.unit.test_dynamic_service import (
    FakeDynamicWorker,
    _service,
    _state,
    _write_minimal_pe,
)

JsonObject = dict[str, Any]


def _static_session(tmp_path: Path) -> tuple[AnalysisService, str]:
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    worker = FakeDynamicWorker()
    service = _service(tmp_path, worker)
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None
    session = created.data["session"]
    assert isinstance(session, dict)
    return service, str(session["id"])


def _paused_dynamic_session(tmp_path: Path) -> tuple[AnalysisService, str]:
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    worker = FakeDynamicWorker()
    worker.current_state = _state("paused")
    service = _service(tmp_path, worker)
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None
    session_id = str(created.data["session"]["id"])
    assert service.open_dynamic(session_id).ok
    return service, session_id


# --------------------------------------------------------------------------
# pure helpers
# --------------------------------------------------------------------------


def test_rpc_error_marks_timeout_retryable() -> None:
    timed_out = service_ext._rpc_error(R2Error("timeout", "r2 stalled", detail=1))
    assert isinstance(timed_out, XdbgRpcError)
    assert timed_out.code == "timeout"
    assert timed_out.retryable is True
    assert timed_out.details == {"detail": 1}

    other = service_ext._rpc_error(GhidraError("invalid_params", "bad address"))
    assert other.retryable is False


def _binding_workflow(address: Any, intent_id: str = "oep") -> JsonObject:
    return {
        "workflow": {
            "state": {
                "breakpoints": {
                    "bindings": [{"intent_id": intent_id, "address": address}]
                }
            }
        }
    }


def test_breakpoint_binding_address_returns_the_single_binding() -> None:
    assert service_ext._breakpoint_binding_address(_binding_workflow(0x1234), "oep") == 0x1234


@pytest.mark.parametrize(
    "data",
    [
        {"workflow": "nope"},
        {"workflow": {"state": "nope"}},
        {"workflow": {"state": {"breakpoints": "nope"}}},
        {"workflow": {"state": {"breakpoints": {"bindings": "nope"}}}},
    ],
)
def test_breakpoint_binding_address_rejects_malformed_status(data: JsonObject) -> None:
    with pytest.raises(XdbgRpcError):
        service_ext._breakpoint_binding_address(data, "oep")


def test_breakpoint_binding_address_rejects_a_blank_intent() -> None:
    with pytest.raises(ValueError, match="intent_id"):
        service_ext._breakpoint_binding_address(_binding_workflow(0x1234), "  ")


def test_breakpoint_binding_address_requires_exactly_one_binding() -> None:
    empty: JsonObject = {"workflow": {"state": {"breakpoints": {"bindings": []}}}}
    with pytest.raises(XdbgRpcError):
        service_ext._breakpoint_binding_address(empty, "oep")


def test_breakpoint_binding_address_rejects_a_bad_address() -> None:
    with pytest.raises(XdbgRpcError):
        service_ext._breakpoint_binding_address(_binding_workflow(0), "oep")


# --------------------------------------------------------------------------
# capabilities catalog
# --------------------------------------------------------------------------


def test_capabilities_search_and_describe(tmp_path: Path) -> None:
    service, _ = _static_session(tmp_path)
    listed = service.capabilities_search()
    assert listed.ok and listed.data is not None
    assert listed.data["count"] == len(listed.data["capabilities"])
    first = listed.data["capabilities"][0]
    described = service.capabilities_describe(str(first["id"]))
    assert described.ok and described.data is not None
    assert described.data["capability"]["id"] == first["id"]


def test_capabilities_describe_reports_not_found(tmp_path: Path) -> None:
    service, _ = _static_session(tmp_path)
    result = service.capabilities_describe("no-such-capability")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "not_found"


# --------------------------------------------------------------------------
# radare2 wrappers
# --------------------------------------------------------------------------


class _FakeR2Client:
    def __init__(self, exe: Path | None = None) -> None:
        del exe

    def open(self, binary: Path, *, timeout: float) -> JsonObject:
        del binary, timeout
        return {"opened": True}

    def run(self, binary: Path, commands: list[str], *, timeout: float) -> JsonObject:
        del binary, timeout
        return {"commands": commands}

    def disasm(self, binary: Path, address: int, *, count: int, timeout: float) -> JsonObject:
        del binary, timeout
        return {"address": address, "count": count}

    def xrefs(self, binary: Path, address: int, *, timeout: float) -> JsonObject:
        del binary, timeout
        return {"address": address}


class _BoomR2Client(_FakeR2Client):
    def open(self, binary: Path, *, timeout: float) -> JsonObject:
        raise R2Error("timeout", "r2 open stalled")

    def run(self, binary: Path, commands: list[str], *, timeout: float) -> JsonObject:
        raise R2Error("r2_failed", "command refused")

    def disasm(self, binary: Path, address: int, *, count: int, timeout: float) -> JsonObject:
        raise R2Error("r2_failed", "disasm refused")

    def xrefs(self, binary: Path, address: int, *, timeout: float) -> JsonObject:
        raise R2Error("r2_failed", "xrefs refused")


def test_r2_wrappers_succeed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service_ext, "R2Client", _FakeR2Client)
    service, session_id = _static_session(tmp_path)
    assert service.r2_open(session_id).ok
    assert service.r2_info(session_id).ok
    assert service.r2_functions(session_id).ok
    assert service.r2_strings(session_id).ok
    assert service.r2_imports(session_id).ok
    assert service.r2_exports(session_id).ok
    disasm = service.r2_disasm(session_id, 0x1000, count=8)
    assert disasm.ok and disasm.data is not None and disasm.data["address"] == 0x1000
    assert service.r2_xrefs(session_id, 0x2000).ok


def test_r2_wrappers_map_backend_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service_ext, "R2Client", _BoomR2Client)
    service, session_id = _static_session(tmp_path)
    opened = service.r2_open(session_id)
    assert opened.ok is False and opened.error is not None
    assert opened.error.code == "timeout" and opened.error.retryable is True
    for op in (
        service.r2_info(session_id),
        service.r2_disasm(session_id, 0x1000),
        service.r2_xrefs(session_id, 0x2000),
    ):
        assert op.ok is False and op.error is not None
        assert op.error.code == "r2_failed"


def test_r2_open_refuses_a_closed_session(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service_ext, "R2Client", _FakeR2Client)
    service, session_id = _static_session(tmp_path)
    assert service.close_session(session_id).ok
    result = service.r2_open(session_id)
    assert result.ok is False
    assert result.error is not None


# --------------------------------------------------------------------------
# ghidra wrappers
# --------------------------------------------------------------------------


class _FakeGhidraClient:
    def __init__(self, home: Path | None = None) -> None:
        del home

    def analyze_binary(self, binary: Path, project: Path, *, timeout: float) -> JsonObject:
        del binary, project, timeout
        return {"analyzed": True}

    def functions(self, binary: Path, project: Path, *, limit: int, timeout: float) -> JsonObject:
        del binary, project, limit, timeout
        return {"functions": []}

    def symbols(self, binary: Path, project: Path, *, limit: int, timeout: float) -> JsonObject:
        del binary, project, limit, timeout
        return {"symbols": []}

    def xrefs(
        self, binary: Path, project: Path, address: Any, *, limit: int, timeout: float
    ) -> JsonObject:
        del binary, project, address, limit, timeout
        return {"xrefs": []}

    def decompile(self, binary: Path, project: Path, address: Any, *, timeout: float) -> JsonObject:
        del binary, project, address, timeout
        return {"decompiled": True}


def test_ghidra_wrappers_succeed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service_ext, "GhidraClient", _FakeGhidraClient)
    service, session_id = _static_session(tmp_path)
    assert service.ghidra_analyze(session_id).ok
    assert service.ghidra_functions(session_id).ok
    assert service.ghidra_symbols(session_id).ok
    assert service.ghidra_xrefs(session_id, "0x1000").ok
    assert service.ghidra_decompile(session_id, "0x1000").ok


def test_ghidra_export_requires_an_address(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service_ext, "GhidraClient", _FakeGhidraClient)
    service, session_id = _static_session(tmp_path)
    # _ghidra_export is shared; drive the address-required branch directly.
    missing_xref = service_ext._ghidra_export(service, session_id, "xrefs", address=None)
    assert missing_xref.ok is False and missing_xref.error is not None
    missing_dec = service_ext._ghidra_export(service, session_id, "decompile", address=None)
    assert missing_dec.ok is False and missing_dec.error is not None
    unknown = service_ext._ghidra_export(service, session_id, "bogus")
    assert unknown.ok is False and unknown.error is not None


def test_ghidra_analyze_maps_backend_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Boom(_FakeGhidraClient):
        def analyze_binary(self, binary: Path, project: Path, *, timeout: float) -> JsonObject:
            raise GhidraError("timeout", "ghidra stalled")

    monkeypatch.setattr(service_ext, "GhidraClient", _Boom)
    service, session_id = _static_session(tmp_path)
    result = service.ghidra_analyze(session_id)
    assert result.ok is False and result.error is not None
    assert result.error.code == "timeout" and result.error.retryable is True


def test_ghidra_export_maps_backend_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Boom(_FakeGhidraClient):
        def functions(
            self, binary: Path, project: Path, *, limit: int, timeout: float
        ) -> JsonObject:
            raise GhidraError("ghidra_failed", "export refused")

    monkeypatch.setattr(service_ext, "GhidraClient", _Boom)
    service, session_id = _static_session(tmp_path)
    result = service.ghidra_functions(session_id)
    assert result.ok is False and result.error is not None
    assert result.error.code == "ghidra_failed"


def test_ghidra_export_registers_an_export_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    export_file = tmp_path / "export.json"
    export_file.write_text('{"functions": []}')

    class _Exporting(_FakeGhidraClient):
        def functions(
            self, binary: Path, project: Path, *, limit: int, timeout: float
        ) -> JsonObject:
            return {"functions": [], "export_path": str(export_file)}

    monkeypatch.setattr(service_ext, "GhidraClient", _Exporting)
    service, session_id = _static_session(tmp_path)
    result = service.ghidra_functions(session_id)
    assert result.ok and result.data is not None
    assert "artifact_id" in result.data


# --------------------------------------------------------------------------
# frida wrappers (need a live debuggee pid)
# --------------------------------------------------------------------------


class _FakeFridaClient:
    def attach(self, pid: int, *, allowed_pid: int) -> JsonObject:
        del allowed_pid
        return {"attached": pid}

    def modules(self, pid: int, *, allowed_pid: int, limit: int) -> JsonObject:
        del pid, allowed_pid, limit
        return {"count": 0, "modules": []}

    def exports(self, pid: int, module_name: str, *, allowed_pid: int, limit: int) -> JsonObject:
        del pid, allowed_pid, limit
        return {"count": 0, "module": module_name}

    def memory_read(self, pid: int, address: int, size: int, *, allowed_pid: int) -> JsonObject:
        del pid, allowed_pid
        return {"address": address, "size": size}

    def hook_template(self, pid: int, template: str, *, allowed_pid: int) -> JsonObject:
        del pid, allowed_pid
        return {"template": template}


def test_frida_wrappers_succeed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service_ext, "FridaClient", _FakeFridaClient)
    service, session_id = _paused_dynamic_session(tmp_path)
    assert service.frida_attach(session_id).ok
    assert service.frida_modules(session_id).ok
    assert service.frida_exports(session_id, "ntdll.dll").ok
    assert service.frida_memory_read(session_id, 0x1000, 16).ok
    assert service.frida_hook_template(session_id).ok


def test_frida_attach_without_a_debuggee_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(service_ext, "FridaClient", _FakeFridaClient)
    service, session_id = _static_session(tmp_path)
    result = service.frida_attach(session_id)
    assert result.ok is False and result.error is not None


def test_frida_attach_maps_backend_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class _Boom(_FakeFridaClient):
        def attach(self, pid: int, *, allowed_pid: int) -> JsonObject:
            raise FridaError("timeout", "frida stalled")

    monkeypatch.setattr(service_ext, "FridaClient", _Boom)
    service, session_id = _paused_dynamic_session(tmp_path)
    result = service.frida_attach(session_id)
    assert result.ok is False and result.error is not None
    assert result.error.code == "timeout" and result.error.retryable is True


class _BoomFridaClient:
    def _fail(self, *args: Any, **kwargs: Any) -> JsonObject:
        del args, kwargs
        raise FridaError("frida_failed", "probe refused")

    attach = _fail
    modules = _fail
    exports = _fail
    memory_read = _fail
    hook_template = _fail


@pytest.mark.parametrize(
    "op",
    [
        lambda s, sid: s.frida_modules(sid),
        lambda s, sid: s.frida_exports(sid, "ntdll.dll"),
        lambda s, sid: s.frida_memory_read(sid, 0x1000, 16),
        lambda s, sid: s.frida_hook_template(sid),
    ],
)
def test_frida_per_method_errors_are_mapped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, op: Any
) -> None:
    monkeypatch.setattr(service_ext, "FridaClient", _BoomFridaClient)
    service, session_id = _paused_dynamic_session(tmp_path)
    result = op(service, session_id)
    assert result.ok is False and result.error is not None
    assert result.error.code == "frida_failed"


# --------------------------------------------------------------------------
# windbg wrappers (Windows-gated client)
# --------------------------------------------------------------------------


def _install_windbg(monkeypatch: pytest.MonkeyPatch, client_cls: Any) -> None:
    monkeypatch.setattr(service_ext, "is_windows_host", lambda: True)
    monkeypatch.setattr(
        service_ext, "WindbgClient", lambda cdb=None, allow_kernel=False: client_cls()
    )


class _FakeWindbgClient:
    def open_dump(
        self, dump: Path, commands: list[str], *, timeout: float, kernel: bool
    ) -> JsonObject:
        del dump, commands, timeout, kernel
        return {"opened": True}

    def threads(self, dump: Path, *, timeout: float) -> JsonObject:
        del dump, timeout
        return {"threads": []}

    def modules(self, dump: Path, *, timeout: float) -> JsonObject:
        del dump, timeout
        return {"modules": []}

    def disasm(self, dump: Path, address: Any, *, length: int, timeout: float) -> JsonObject:
        del dump, address, length, timeout
        return {"disasm": []}

    def attach(self, pid: int, *, allowed_pid: int, timeout: float) -> JsonObject:
        del allowed_pid, timeout
        return {"attached": pid}

    def live_threads(self, pid: int, *, allowed_pid: int, timeout: float) -> JsonObject:
        del pid, allowed_pid, timeout
        return {"threads": []}

    def live_modules(self, pid: int, *, allowed_pid: int, timeout: float) -> JsonObject:
        del pid, allowed_pid, timeout
        return {"modules": []}

    def live_disasm(
        self, pid: int, address: Any, *, allowed_pid: int, length: int, timeout: float
    ) -> JsonObject:
        del pid, address, allowed_pid, length, timeout
        return {"disasm": []}


def test_windbg_is_unsupported_off_windows(tmp_path: Path) -> None:
    service, session_id = _static_session(tmp_path)
    result = service.windbg_open_dump(str(tmp_path / "crash.dmp"))
    assert result.ok is False and result.error is not None
    assert result.error.code == "unsupported_on_platform"


def test_windbg_dump_wrappers_succeed_on_windows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_windbg(monkeypatch, _FakeWindbgClient)
    service, _ = _static_session(tmp_path)
    dump = str(tmp_path / "crash.dmp")
    assert service.windbg_open_dump(dump).ok
    assert service.windbg_threads(dump).ok
    assert service.windbg_modules(dump).ok
    assert service.windbg_disasm(dump, "0x1000").ok


def test_windbg_live_wrappers_succeed_on_windows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_windbg(monkeypatch, _FakeWindbgClient)
    service, session_id = _paused_dynamic_session(tmp_path)
    assert service.windbg_attach(session_id).ok
    assert service.windbg_live_threads(session_id).ok
    assert service.windbg_live_modules(session_id).ok
    assert service.windbg_live_disasm(session_id, "0x1000").ok


def test_windbg_open_dump_maps_backend_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Boom(_FakeWindbgClient):
        def open_dump(
            self, dump: Path, commands: list[str], *, timeout: float, kernel: bool
        ) -> JsonObject:
            raise WindbgError("timeout", "cdb stalled")

    _install_windbg(monkeypatch, _Boom)
    service, _ = _static_session(tmp_path)
    result = service.windbg_open_dump(str(tmp_path / "crash.dmp"))
    assert result.ok is False and result.error is not None
    assert result.error.code == "timeout" and result.error.retryable is True


class _BoomWindbgClient:
    def _fail(self, *args: Any, **kwargs: Any) -> JsonObject:
        del args, kwargs
        raise WindbgError("windbg_failed", "cdb refused")

    threads = _fail
    modules = _fail
    disasm = _fail
    attach = _fail
    live_threads = _fail
    live_modules = _fail
    live_disasm = _fail


@pytest.mark.parametrize(
    "op",
    [
        lambda s, sid: s.windbg_threads("d.dmp"),
        lambda s, sid: s.windbg_modules("d.dmp"),
        lambda s, sid: s.windbg_disasm("d.dmp", "0x1000"),
        lambda s, sid: s.windbg_attach(sid),
        lambda s, sid: s.windbg_live_threads(sid),
        lambda s, sid: s.windbg_live_modules(sid),
        lambda s, sid: s.windbg_live_disasm(sid, "0x1000"),
    ],
)
def test_windbg_per_method_errors_are_mapped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, op: Any
) -> None:
    _install_windbg(monkeypatch, _BoomWindbgClient)
    service, session_id = _paused_dynamic_session(tmp_path)
    result = op(service, session_id)
    assert result.ok is False and result.error is not None
    assert result.error.code == "windbg_failed"


# --------------------------------------------------------------------------
# artifact / knowledge / report store
# --------------------------------------------------------------------------


def test_artifacts_list_and_gc(tmp_path: Path) -> None:
    service, _ = _static_session(tmp_path)
    listed = service.artifacts_list()
    assert listed.ok
    assert service.artifacts_gc().ok
    assert service.audit_list().ok


def test_artifacts_describe_and_read_missing(tmp_path: Path) -> None:
    service, _ = _static_session(tmp_path)
    described = service.artifacts_describe("no-such-id")
    assert described.ok is False and described.error is not None
    assert described.error.code == "not_found"
    read = service.artifacts_read("no-such-id")
    assert read.ok is False and read.error is not None
    assert read.error.code == "not_found"


def test_timeline_and_knowledge_roundtrip(tmp_path: Path) -> None:
    service, session_id = _static_session(tmp_path)
    recorded = service.knowledge_record(session_id, "note", "oep", {"rva": 0x1000})
    assert recorded.ok, recorded.error
    queried = service.knowledge_query(session_id, kind="note")
    assert queried.ok and queried.data is not None
    assert service.timeline_list(session_id).ok


def test_knowledge_query_rejects_an_unknown_session(tmp_path: Path) -> None:
    service, _ = _static_session(tmp_path)
    result = service.knowledge_query("no-such-session")
    assert result.ok is False and result.error is not None


@pytest.mark.parametrize(
    "call",
    [
        lambda s, sid: s.knowledge_record(sid, "", "key", {}),
        lambda s, sid: s.knowledge_record(sid, "kind", "", {}),
        lambda s, sid: s.knowledge_record(sid, "k" * 65, "key", {}),
    ],
)
def test_knowledge_record_rejects_bad_identifiers(tmp_path: Path, call: Any) -> None:
    service, session_id = _static_session(tmp_path)
    result = call(service, session_id)
    assert result.ok is False and result.error is not None


def test_knowledge_record_rejects_an_oversize_value(tmp_path: Path) -> None:
    service, session_id = _static_session(tmp_path)
    huge = {"blob": "x" * (KNOWLEDGE_VALUE_MAX_CHARS + 10)}
    result = service.knowledge_record(session_id, "note", "big", huge)
    assert result.ok is False and result.error is not None


def test_report_generate_writes_markdown(tmp_path: Path) -> None:
    service, session_id = _static_session(tmp_path)
    result = service.report_generate(session_id, title="Sample")
    assert result.ok, result.error
    assert result.data is not None
    assert Path(result.data["path"]).is_file()
    assert result.data["bytes"] > 0


def test_report_generate_rejects_a_bad_audit_limit(tmp_path: Path) -> None:
    service, session_id = _static_session(tmp_path)
    result = service.report_generate(session_id, audit_limit=0)
    assert result.ok is False and result.error is not None


def test_tool_metrics_and_limit_guard(tmp_path: Path) -> None:
    service, _ = _static_session(tmp_path)
    assert service.tool_metrics().ok
    bad = service.tool_metrics(limit=-1)
    assert bad.ok is False and bad.error is not None


def test_sessions_unclean_and_peek(tmp_path: Path) -> None:
    service, session_id = _static_session(tmp_path)
    unclean = service.sessions_unclean()
    assert unclean.ok and unclean.data is not None
    live = service.peek_session_record(session_id)
    assert live.ok and live.data is not None
    assert live.data["live"] is True
    missing = service.peek_session_record("no-such-session")
    assert missing.ok is False and missing.error is not None


# --------------------------------------------------------------------------
# batch analyze
# --------------------------------------------------------------------------


def test_batch_analyze_creates_a_session_per_binary(tmp_path: Path) -> None:
    service, _ = _static_session(tmp_path)
    one = tmp_path / "a.exe"
    two = tmp_path / "b.exe"
    _write_minimal_pe(one)
    _write_minimal_pe(two)
    result = service.batch_analyze([str(one), str(two)], open_static=False)
    assert result.ok and result.data is not None
    assert result.data["count"] == 2
    assert result.data["succeeded"] == 2


def test_batch_analyze_records_a_static_open_failure(tmp_path: Path) -> None:
    # No static worker factory is wired, so open_static fails and the entry is
    # marked failed even though the session was created.
    service, _ = _static_session(tmp_path)
    good = tmp_path / "good.exe"
    _write_minimal_pe(good)
    result = service.batch_analyze([str(good)], open_static=True)
    assert result.ok and result.data is not None
    entry = result.data["entries"][0]
    assert entry["static_open"] is False
    assert entry["ok"] is False


def test_batch_analyze_reports_a_bad_entry(tmp_path: Path) -> None:
    service, _ = _static_session(tmp_path)
    good = tmp_path / "good.exe"
    _write_minimal_pe(good)
    result = service.batch_analyze([str(good), str(tmp_path / "missing.exe")], open_static=False)
    assert result.ok and result.data is not None
    assert result.data["failed"] == 1


@pytest.mark.parametrize(
    "call",
    [
        lambda s: s.batch_analyze([]),
        lambda s: s.batch_analyze([f"p{i}" for i in range(33)]),
        lambda s: s.batch_analyze(["p"], max_workers=0),
    ],
)
def test_batch_analyze_rejects_bad_arguments(tmp_path: Path, call: Any) -> None:
    service, _ = _static_session(tmp_path)
    result = call(service)
    assert result.ok is False and result.error is not None
