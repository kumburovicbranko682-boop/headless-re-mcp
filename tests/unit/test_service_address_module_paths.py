"""Error and edge arcs for the address/module surface of ``AnalysisService``.

``sync.*``, ``modules.resolve`` and ``dynamic.analyze_function`` translate
between the IDA static image and the live x64dbg runtime, so their fatal-error
arms (which fail the affected runtime) and the ``analyze_function`` execution
report only fire with both backends open. ``test_addressing*`` exercises the
underlying ``core.addressing`` mapping directly; this file drives the service
methods against paired fakes and, for the runtime-fatal arms, replaces the
mapping/snapshot helpers so the classified exceptions reach the handlers.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.ida.client import IdaWorkerError
from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.core.models import BackendKind, ModuleSelector, Result, RpcError
from headless_re_mcp.core.service import AnalysisService, JsonObject
from tests.unit.test_dynamic_service import (
    FakeDynamicWorker,
    FakeStaticWorker,
    _create,
    _service,
    _state,
    _write_minimal_pe,
)


class _DecompileStaticWorker(FakeStaticWorker):
    """A static worker that also answers static.decompile."""

    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset({"static.functions", "static.decompile"})

    def request(
        self,
        command: str,
        params: JsonObject | None = None,
        *,
        timeout: float = 120.0,
    ) -> JsonObject:
        if command == "decompile":
            return {"code": "int main(){return 0;}", "address": (params or {}).get("address")}
        return super().request(command, params, timeout=timeout)


class _NoModulesWorker(FakeDynamicWorker):
    """A dynamic worker that does not advertise modules.list."""

    @property
    def capabilities(self) -> frozenset[str]:
        return super().capabilities - {"modules.list"}


class _FailOnCommandWorker(FakeDynamicWorker):
    def __init__(self, fail_command: str, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._fail_command = fail_command

    def request(
        self,
        command: str,
        params: JsonObject | None = None,
        *,
        timeout: float = 120.0,
    ) -> JsonObject:
        if command == self._fail_command:
            self.requests.append((command, params or {}))
            raise XdbgRpcError("backend_error", f"{command} rejected")
        return super().request(command, params, timeout=timeout)


def _dual(
    tmp_path: Path,
    dynamic: FakeDynamicWorker,
    static: FakeStaticWorker | None = None,
) -> tuple[AnalysisService, str]:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    service = _service(tmp_path, dynamic, static or FakeStaticWorker())
    session_id = _create(service, binary)
    assert service.open_static(session_id).ok
    assert service.open_dynamic(session_id).ok
    return service, session_id


def _dual_real_module(tmp_path: Path) -> tuple[AnalysisService, str]:
    """A dual-backend session whose runtime module points at the real PE.

    ``build_rebased_module_mapping`` verifies the module file on disk, so
    ``_explicit_module_operation`` only reaches its argument guards when the
    runtime module path resolves to the session binary.
    """
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    dynamic = FakeDynamicWorker(
        module_path=str(binary),
        module_base=0x140000000,
        module_size=0x4000,
    )
    service = _service(tmp_path, dynamic, FakeStaticWorker())
    session_id = _create(service, binary)
    assert service.open_static(session_id).ok
    assert service.open_dynamic(session_id).ok
    return service, session_id


def _raise(exc: BaseException) -> Any:
    def _thrower(self: AnalysisService, *_a: Any, **_k: Any) -> Any:
        raise exc

    return _thrower


# --- resolve_runtime_address happy paths (both backends) ------------------------


def test_resolve_runtime_address_translates_a_static_va(tmp_path: Path) -> None:
    service, session_id = _dual(tmp_path, FakeDynamicWorker())

    result = service.resolve_runtime_address(session_id, 0x140001000, source="static")

    assert result.ok and result.data is not None
    assert result.data["runtime_address"] == 0x140001000
    assert result.data["static_address"] == 0x140001000


def test_resolve_runtime_address_translates_an_rva(tmp_path: Path) -> None:
    service, session_id = _dual(tmp_path, FakeDynamicWorker())

    result = service.resolve_runtime_address(session_id, 0x1000, source="rva")

    assert result.ok and result.data is not None
    assert result.data["runtime_address"] == 0x140001000


def test_resolve_runtime_address_translates_a_runtime_va(tmp_path: Path) -> None:
    service, session_id = _dual(tmp_path, FakeDynamicWorker())

    result = service.resolve_runtime_address(session_id, 0x140001000, source="runtime")

    assert result.ok and result.data is not None
    assert result.data["static_address"] == 0x140001000


# --- resolve_runtime_address fatal / non-fatal runtime arms ---------------------


def test_resolve_runtime_address_fails_the_ida_runtime_on_a_fatal_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _dual(tmp_path, FakeDynamicWorker())
    monkeypatch.setattr(
        AnalysisService,
        "_main_module_mapping",
        _raise(IdaWorkerError("worker_exited", "ida died")),
    )

    result = service.resolve_runtime_address(session_id, 0x140001000)

    assert not result.ok and result.error is not None
    assert result.error.code == "worker_exited"
    # The fatal arm tore the IDA runtime down.
    assert service._runtime_owner.get(session_id, BackendKind.IDA) is None


def test_resolve_runtime_address_keeps_a_non_fatal_ida_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _dual(tmp_path, FakeDynamicWorker())
    monkeypatch.setattr(
        AnalysisService,
        "_main_module_mapping",
        _raise(IdaWorkerError("backend_unavailable", "not open")),
    )

    result = service.resolve_runtime_address(session_id, 0x140001000)

    assert not result.ok and result.error is not None
    assert result.error.code == "backend_unavailable"
    assert service._runtime_owner.get(session_id, BackendKind.IDA) is not None


def test_resolve_runtime_address_fails_the_x64dbg_runtime_on_a_fatal_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _dual(tmp_path, FakeDynamicWorker())
    monkeypatch.setattr(
        AnalysisService,
        "_main_module_mapping",
        _raise(XdbgRpcError("rpc_protocol_error", "x64dbg desynced")),
    )

    result = service.resolve_runtime_address(session_id, 0x140001000)

    assert not result.ok and result.error is not None
    assert result.error.code == "rpc_protocol_error"
    assert service._runtime_owner.get(session_id, BackendKind.X64DBG) is None


def test_resolve_runtime_address_maps_a_missing_modules_capability(tmp_path: Path) -> None:
    service, session_id = _dual(tmp_path, _NoModulesWorker())

    result = service.resolve_runtime_address(session_id, 0x140001000)

    assert not result.ok and result.error is not None
    assert result.error.code == "capability_unavailable"
    assert result.error.details["capability"] == "modules.list"
    # A capability gap is not fatal: the runtime survives.
    assert service._runtime_owner.get(session_id, BackendKind.X64DBG) is not None


# --- _sync_address fatal arms ---------------------------------------------------


def test_sync_static_to_runtime_fails_the_ida_runtime_on_a_fatal_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _dual(tmp_path, FakeDynamicWorker())
    monkeypatch.setattr(
        AnalysisService,
        "_main_module_mapping",
        _raise(IdaWorkerError("worker_protocol_error", "ida garbled")),
    )

    result = service.sync_static_to_runtime(session_id, 0x140001000)

    assert not result.ok and result.error is not None
    assert result.error.code == "worker_protocol_error"
    assert service._runtime_owner.get(session_id, BackendKind.IDA) is None


def test_sync_static_to_runtime_keeps_a_non_fatal_ida_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _dual(tmp_path, FakeDynamicWorker())
    monkeypatch.setattr(
        AnalysisService,
        "_main_module_mapping",
        _raise(IdaWorkerError("backend_unavailable", "not open")),
    )

    result = service.sync_static_to_runtime(session_id, 0x140001000)

    assert not result.ok and result.error is not None
    assert result.error.code == "backend_unavailable"
    assert service._runtime_owner.get(session_id, BackendKind.IDA) is not None


def test_sync_runtime_to_static_fails_the_x64dbg_runtime_on_a_fatal_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _dual(tmp_path, FakeDynamicWorker())
    monkeypatch.setattr(
        AnalysisService,
        "_main_module_mapping",
        _raise(XdbgRpcError("worker_exited", "x64dbg died")),
    )

    result = service.sync_runtime_to_static(session_id, 0x140001000)

    assert not result.ok and result.error is not None
    assert result.error.code == "worker_exited"
    assert service._runtime_owner.get(session_id, BackendKind.X64DBG) is None


# --- _explicit_module_operation edge/fatal arms ---------------------------------


def test_explicit_module_operation_requires_an_address_for_translation(
    tmp_path: Path,
) -> None:
    service, session_id = _dual_real_module(tmp_path)

    result = service._explicit_module_operation(
        session_id,
        ModuleSelector(base=0x140000000),
        source="runtime",
        address=None,
    )

    assert not result.ok and result.error is not None
    assert "address is required" in result.error.message


def test_explicit_module_operation_fails_runtime_on_a_fatal_snapshot_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _dual(tmp_path, FakeDynamicWorker())
    monkeypatch.setattr(
        AnalysisService,
        "_runtime_module_snapshot",
        _raise(XdbgRpcError("worker_exited", "snapshot died")),
    )

    result = service.sync_module_preferred_to_runtime(
        session_id,
        ModuleSelector(base=0x140000000),
        0x140001000,
    )

    assert not result.ok and result.error is not None
    assert result.error.code == "worker_exited"
    assert service._runtime_owner.get(session_id, BackendKind.X64DBG) is None


# --- dynamic_breakpoint_set static/rva translation arms -------------------------


def test_breakpoint_set_maps_an_ida_translation_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _dual(tmp_path, FakeDynamicWorker())
    monkeypatch.setattr(
        AnalysisService,
        "_main_module_mapping",
        _raise(IdaWorkerError("backend_error", "ida translate failed")),
    )

    result = service.dynamic_breakpoint_set(
        session_id, 0x140001000, address_space="static"
    )

    assert not result.ok and result.error is not None
    assert result.error.code == "backend_error"
    assert result.error.details["backend"] == BackendKind.IDA.value


def test_breakpoint_set_maps_an_x64dbg_translation_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _dual(tmp_path, FakeDynamicWorker())
    monkeypatch.setattr(
        AnalysisService,
        "_main_module_mapping",
        _raise(XdbgRpcError("backend_error", "x64dbg translate failed")),
    )

    result = service.dynamic_breakpoint_set(
        session_id, 0x140001000, address_space="rva"
    )

    assert not result.ok and result.error is not None
    assert result.error.code == "backend_error"
    assert result.error.details["backend"] == BackendKind.X64DBG.value


# --- analyze_function_dynamic ---------------------------------------------------


def test_analyze_function_includes_a_successful_decompilation(tmp_path: Path) -> None:
    service, session_id = _dual(
        tmp_path, FakeDynamicWorker(), _DecompileStaticWorker()
    )

    result = service.analyze_function_dynamic(session_id, 0x140001000, timeout=5.0)

    assert result.ok and result.data is not None
    static_section = result.data["static"]
    assert static_section["decompiled"] is True
    assert "decompilation" in static_section


def test_analyze_function_returns_a_failed_arm(tmp_path: Path) -> None:
    service, session_id = _dual(tmp_path, _FailOnCommandWorker("breakpoints.set"))

    result = service.analyze_function_dynamic(
        session_id, 0x140001000, decompile=False, timeout=5.0
    )

    assert not result.ok and result.error is not None
    assert result.error.code == "backend_error"


def test_analyze_function_tolerates_a_failing_register_read(tmp_path: Path) -> None:
    service, session_id = _dual(tmp_path, _FailOnCommandWorker("registers.read"))

    result = service.analyze_function_dynamic(
        session_id, 0x140001000, decompile=False, timeout=5.0
    )

    assert result.ok and result.data is not None
    assert result.data["registers"] is None
    assert result.data["execution"]["instruction_pointer"] is None


def test_analyze_function_reports_a_failing_resume_with_the_partial_report(
    tmp_path: Path,
) -> None:
    # The arm succeeds but the resume fails: analyze returns a failure whose
    # data still carries the function/breakpoint report and execution.resumed
    # is False.
    service, session_id = _dual(tmp_path, _FailOnCommandWorker("debug.resume"))

    result = service.analyze_function_dynamic(
        session_id, 0x140001000, decompile=False, timeout=5.0
    )

    assert not result.ok and result.error is not None
    assert result.error.code == "backend_error"
    assert result.data is not None
    assert result.data["execution"]["resumed"] is False
    assert result.data["breakpoint"]["armed"] is True


# --- _main_module_mapping capability guard is reachable through the facade ------


def test_state_is_annotated_after_open(tmp_path: Path) -> None:
    # Anchors the dual-backend harness: both runtimes exist and debug.state works.
    worker = FakeDynamicWorker()
    service, session_id = _dual(tmp_path, worker)
    worker.current_state = _state("paused")

    result = service.dynamic_state(session_id)

    assert result.ok
