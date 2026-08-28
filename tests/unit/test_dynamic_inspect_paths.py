"""Path coverage for the paused-target inspection mixin (``service_dynamic_inspect``).

The dynamic-service suite exercises the happy paths, but the thin wrappers'
parameter guards, the artifact-path and capability guards inside
``modules_dump``/``pe_headers_runtime``, the memory-read PE-header fallback edges,
and the XdbgRpcError/BaseException handlers were largely unreached. These reuse
the ``FakeDynamicWorker`` harness (subclassing it to withhold capabilities or
raise) and, where a guard sits before any backend call, invoke the wrapper on a
bare service so no runtime is needed.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, cast

import pytest

import headless_re_mcp.core.service_dynamic_inspect as sdi
from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.core.service import AnalysisService
from tests.unit.test_dynamic_service import (
    FakeDynamicWorker,
    _create,
    _NoNativePeHeadersWorker,
    _service,
    _settings,
    _state,
    _write_minimal_pe,
)

JsonObject = dict[str, Any]

_VALID_BASE = 0x140000000


def _bare(tmp_path: Path) -> AnalysisService:
    return AnalysisService(_settings(tmp_path))


def _open_paused(tmp_path: Path, worker: FakeDynamicWorker) -> tuple[AnalysisService, str]:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    worker.current_state = _state("paused")
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok
    return service, session_id


# --------------------------------------------------------------------------- #
# module-level helpers                                                         #
# --------------------------------------------------------------------------- #
def test_module_base_present_rejects_malformed_payloads() -> None:
    assert sdi._module_base_present("not-a-dict", _VALID_BASE) is False
    assert sdi._module_base_present({"modules": "not-a-list"}, _VALID_BASE) is False
    assert sdi._module_base_present({"modules": [{"base": _VALID_BASE}]}, _VALID_BASE) is True


def test_atomic_write_cleans_up_the_temp_file_when_replace_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "out" / "payload.bin"

    def boom(src: Any, dst: Any) -> None:
        raise OSError("replace failed")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError, match="replace failed"):
        sdi._atomic_write_bytes(destination, b"data")
    assert not destination.exists()
    assert list(destination.parent.glob("*.tmp")) == []


# --------------------------------------------------------------------------- #
# parameter guards that reject before touching a runtime                       #
# --------------------------------------------------------------------------- #
def test_parameter_guards_reject_bad_arguments(tmp_path: Path) -> None:
    service = _bare(tmp_path)
    cases = [
        service.modules_dump("s1", _VALID_BASE, size=0),
        service.memory_regions("s1", offset=-1),
        service.memory_regions("s1", offset=0, limit=0),
        service.memory_protect_query("s1", -1),
        service.memory_protection("s1", -1),
        service.memory_protection("s1", 0x1000, rights=""),
        service.threads_list("s1", offset=-1),
        service.threads_list("s1", offset=0, limit=0),
        service.stack_read("s1", count=0),
        service.stack_read("s1", address=-1),
        service.stack_trace("s1", limit=0),
        service.disassembly_read("s1", -1),
        service.disassembly_read("s1", 0x1000, count=0),
        service.symbols_list("s1", _VALID_BASE, limit=99999),
        service.symbols_resolve("s1", ""),
        service.imports_scan("s1", 0),
        service.imports_scan("s1", _VALID_BASE, mode="bogus"),
        service.imports_read("s1", 0x1000, 0),
        service.breakpoints_hardware_set("s1", -1),
        service.breakpoints_hardware_set("s1", 0x1000, bp_type="bad"),
        service.breakpoints_hardware_set("s1", 0x1000, size=3),
        service.breakpoints_hardware_remove("s1", -1),
        service.breakpoints_memory_set("s1", 0x1000, bp_type="bad"),
        service.breakpoints_memory_set("s1", -1),
        service.breakpoints_memory_remove("s1", -1),
        service.breakpoints_condition_set("s1", 0x1000, ""),
        service.breakpoints_condition_set("s1", 0x1000, "a;b"),
        service.breakpoints_condition_set("s1", -1, "rax==1"),
        service.breakpoints_condition_get("s1", -1),
        service.patches_apply("s1", 0x1000, ""),
        service.patches_restore("s1", -1),
    ]
    for result in cases:
        assert result.ok is False and result.error is not None
        assert result.error.code == "invalid_params"


@pytest.mark.parametrize("bad_address", ["0x1000", 1.5, None, True])
def test_condition_and_restore_reject_a_non_integer_address(
    tmp_path: Path, bad_address: object
) -> None:
    """The address guard also rejects non-integers, not just negatives.

    These are the mixin methods that used to forward the address raw:
    breakpoints.condition.set screened only its expression, memory.set only its
    type, and condition.get/patches.restore/hardware.remove/memory.remove guarded
    nothing. Each now rejects a non-integer address as a structured invalid_params
    the way breakpoints.hardware.set does.
    """
    service = _bare(tmp_path)
    calls = [
        service.breakpoints_condition_set("s1", cast(int, bad_address), "rax==1"),
        service.breakpoints_condition_get("s1", cast(int, bad_address)),
        service.patches_restore("s1", cast(int, bad_address)),
        service.breakpoints_hardware_remove("s1", cast(int, bad_address)),
        service.breakpoints_memory_set("s1", cast(int, bad_address)),
        service.breakpoints_memory_remove("s1", cast(int, bad_address)),
    ]
    for result in calls:
        assert result.ok is False and result.error is not None
        assert result.error.code == "invalid_params"


def test_valid_arguments_reach_the_dynamic_request(tmp_path: Path) -> None:
    """With no backend open these fail, but only after the guarded param setup runs."""
    service = _bare(tmp_path)
    for result in (
        service.memory_protection("s1", 0x1000, rights="rwx"),
        service.threads_context_read("s1", 1),
        service.threads_context_write("s1", 1, "rax", 0),
        service.stack_read("s1", address=0x1000),
        service.symbols_list("s1", _VALID_BASE, limit=10),
        service.imports_scan("s1", _VALID_BASE, search_start=0x1000, search_size=0x2000),
    ):
        assert result.ok is False and result.error is not None


# --------------------------------------------------------------------------- #
# modules_dump                                                                 #
# --------------------------------------------------------------------------- #
def test_modules_dump_rejects_a_path_unsafe_session_id(tmp_path: Path) -> None:
    result = _bare(tmp_path).modules_dump("../evil", _VALID_BASE, size=0x100)
    assert result.ok is False and result.error is not None
    assert result.error.code == "invalid_request"


class _NoDumpCapWorker(FakeDynamicWorker):
    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset(c for c in super().capabilities if c != "modules.dump")


def test_modules_dump_reports_a_missing_capability(tmp_path: Path) -> None:
    service, session_id = _open_paused(tmp_path, _NoDumpCapWorker())
    result = service.modules_dump(session_id, _VALID_BASE, size=0x100)
    assert result.ok is False and result.error is not None
    assert result.error.code == "capability_unavailable"


def test_modules_dump_reports_a_module_absent_before_the_dump(tmp_path: Path) -> None:
    service, session_id = _open_paused(tmp_path, FakeDynamicWorker())
    result = service.modules_dump(session_id, 0x150000000, size=0x100)
    assert result.ok is False and result.error is not None
    assert result.error.code == "module_not_found"
    assert result.error.details["race"] == "pre_dump"


class _NoModulesListWorker(FakeDynamicWorker):
    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset(c for c in super().capabilities if c != "modules.list")


def test_modules_dump_skips_unload_checks_without_modules_list(tmp_path: Path) -> None:
    service, session_id = _open_paused(tmp_path, _NoModulesListWorker())
    result = service.modules_dump(session_id, _VALID_BASE, size=0x100)
    assert result.ok, result.error
    assert result.data is not None
    assert Path(str(result.data["output_path"])).is_file()


class _DumpRaisesWorker(FakeDynamicWorker):
    def request(
        self, command: str, params: JsonObject | None = None, *, timeout: float = 120.0
    ) -> JsonObject:
        if command == "modules.dump":
            self.requests.append((command, params or {}))
            raise RuntimeError("dump blew up")
        return super().request(command, params, timeout=timeout)


def test_modules_dump_cleans_up_after_an_unexpected_failure(tmp_path: Path) -> None:
    service, session_id = _open_paused(tmp_path, _DumpRaisesWorker())
    result = service.modules_dump(session_id, _VALID_BASE, size=0x100)
    assert result.ok is False and result.error is not None
    assert list((tmp_path / "artifacts" / "dump" / session_id).glob("*.bin")) == []


class _DumpBadPathWorker(FakeDynamicWorker):
    def request(
        self, command: str, params: JsonObject | None = None, *, timeout: float = 120.0
    ) -> JsonObject:
        if command == "modules.dump":
            values = params or {}
            self.requests.append((command, values))
            Path(str(values["output_path"])).write_bytes(b"\x90" * 0x10)
            return {"output_path": "\x00bad"}
        return super().request(command, params, timeout=timeout)


def test_modules_dump_rejects_an_unparseable_artifact_path(tmp_path: Path) -> None:
    service, session_id = _open_paused(tmp_path, _DumpBadPathWorker())
    result = service.modules_dump(session_id, _VALID_BASE, size=0x100)
    assert result.ok is False and result.error is not None
    assert result.error.code == "rpc_protocol_error"


class _DumpNoWriteWorker(FakeDynamicWorker):
    def request(
        self, command: str, params: JsonObject | None = None, *, timeout: float = 120.0
    ) -> JsonObject:
        if command == "modules.dump":
            values = params or {}
            self.requests.append((command, values))
            return {"output_path": str(values["output_path"])}
        return super().request(command, params, timeout=timeout)


def test_modules_dump_reports_a_missing_artifact_file(tmp_path: Path) -> None:
    service, session_id = _open_paused(tmp_path, _DumpNoWriteWorker())
    result = service.modules_dump(session_id, _VALID_BASE, size=0x100)
    assert result.ok is False and result.error is not None
    assert result.error.code == "artifact_missing"


def test_modules_dump_skips_registration_without_a_string_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _open_paused(tmp_path, FakeDynamicWorker())
    monkeypatch.setattr(sdi, "file_sha256", lambda path: 12345)
    result = service.modules_dump(session_id, _VALID_BASE, size=0x100)
    assert result.ok, result.error
    assert result.data is not None
    assert "artifact_id" not in result.data


# --------------------------------------------------------------------------- #
# pe_headers_runtime                                                           #
# --------------------------------------------------------------------------- #
def test_pe_headers_runtime_rejects_a_path_unsafe_session_id(tmp_path: Path) -> None:
    result = _bare(tmp_path).pe_headers_runtime("../evil", _VALID_BASE, save_artifact=True)
    assert result.ok is False and result.error is not None


def test_pe_headers_runtime_without_saving_returns_native_headers(tmp_path: Path) -> None:
    service, session_id = _open_paused(tmp_path, FakeDynamicWorker())
    result = service.pe_headers_runtime(session_id, _VALID_BASE, save_artifact=False)
    assert result.ok, result.error
    assert result.data is not None
    assert "header_artifact" not in result.data


class _PeHeadersNoWriteWorker(FakeDynamicWorker):
    def request(
        self, command: str, params: JsonObject | None = None, *, timeout: float = 120.0
    ) -> JsonObject:
        if command == "pe.headers.runtime":
            values = params or {}
            self.requests.append((command, values))
            return {"base": values["base"], "module_size": self.module_size}
        return super().request(command, params, timeout=timeout)


def test_pe_headers_runtime_tolerates_an_unwritten_header_file(tmp_path: Path) -> None:
    service, session_id = _open_paused(tmp_path, _PeHeadersNoWriteWorker())
    result = service.pe_headers_runtime(session_id, _VALID_BASE, save_artifact=True)
    assert result.ok, result.error
    assert result.data is not None
    assert "header_artifact" not in result.data


class _NoPeCapMemFailWorker(FakeDynamicWorker):
    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset(c for c in super().capabilities if c != "pe.headers.runtime")

    def request(
        self, command: str, params: JsonObject | None = None, *, timeout: float = 120.0
    ) -> JsonObject:
        if command == "memory.read":
            self.requests.append((command, params or {}))
            raise XdbgRpcError("debugger_command_failed", "memory read rejected")
        return super().request(command, params, timeout=timeout)


def test_pe_headers_runtime_returns_the_error_when_the_fallback_read_fails(
    tmp_path: Path,
) -> None:
    service, session_id = _open_paused(tmp_path, _NoPeCapMemFailWorker())
    result = service.pe_headers_runtime(session_id, _VALID_BASE)
    assert result.ok is False and result.error is not None
    assert result.error.code == "capability_unavailable"


class _NoPeCapWorker(FakeDynamicWorker):
    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset(c for c in super().capabilities if c != "pe.headers.runtime")


def test_pe_headers_runtime_reports_invalid_pe_bytes_from_the_fallback(
    tmp_path: Path,
) -> None:
    service, session_id = _open_paused(tmp_path, _NoPeCapWorker())
    result = service.pe_headers_runtime(session_id, _VALID_BASE)
    assert result.ok is False and result.error is not None
    assert result.error.code == "invalid_pe"


def test_pe_headers_runtime_fallback_can_skip_saving(tmp_path: Path) -> None:
    service, session_id = _open_paused(tmp_path, _NoNativePeHeadersWorker())
    result = service.pe_headers_runtime(session_id, _VALID_BASE, save_artifact=False)
    assert result.ok, result.error
    assert result.data is not None
    assert result.data.get("source") == "memory.read_fallback"
    assert "header_artifact" not in result.data


def test_pe_headers_runtime_marks_the_runtime_failed_on_a_fatal_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _open_paused(tmp_path, FakeDynamicWorker())

    def fatal(path: Any) -> str:
        raise XdbgRpcError("worker_exited", "worker died mid-hash")

    monkeypatch.setattr(sdi, "file_sha256", fatal)
    result = service.pe_headers_runtime(session_id, _VALID_BASE, save_artifact=True)
    assert result.ok is False and result.error is not None
    assert result.error.code == "worker_exited"


def test_pe_headers_runtime_reports_a_non_fatal_error_without_failing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _open_paused(tmp_path, FakeDynamicWorker())

    def non_fatal(path: Any) -> str:
        raise XdbgRpcError("debugger_command_failed", "hash rejected")

    monkeypatch.setattr(sdi, "file_sha256", non_fatal)
    result = service.pe_headers_runtime(session_id, _VALID_BASE, save_artifact=True)
    assert result.ok is False and result.error is not None
    assert result.error.code == "debugger_command_failed"


# --------------------------------------------------------------------------- #
# imports_scan / module_catalog error handlers                                 #
# --------------------------------------------------------------------------- #
def test_imports_scan_marks_the_runtime_failed_on_a_fatal_setup_error(
    tmp_path: Path,
) -> None:
    service, session_id = _open_paused(tmp_path, FakeDynamicWorker())

    def fatal(*args: Any, **kwargs: Any) -> None:
        raise XdbgRpcError("worker_exited", "worker died before scan")

    service._require_current_runtime = fatal  # type: ignore[method-assign]
    result = service.imports_scan(session_id, _VALID_BASE)
    assert result.ok is False and result.error is not None
    assert result.error.code == "worker_exited"


class _ModulesListFatalWorker(FakeDynamicWorker):
    def request(
        self, command: str, params: JsonObject | None = None, *, timeout: float = 120.0
    ) -> JsonObject:
        if command == "modules.list":
            self.requests.append((command, params or {}))
            raise XdbgRpcError("worker_exited", "worker died listing modules")
        return super().request(command, params, timeout=timeout)


def test_module_catalog_marks_the_runtime_failed_on_a_fatal_error(tmp_path: Path) -> None:
    service, session_id = _open_paused(tmp_path, _ModulesListFatalWorker())
    result = service.module_catalog(session_id)
    assert result.ok is False and result.error is not None
    assert result.error.code == "worker_exited"


class _ModulesListBoomWorker(FakeDynamicWorker):
    def request(
        self, command: str, params: JsonObject | None = None, *, timeout: float = 120.0
    ) -> JsonObject:
        if command == "modules.list":
            self.requests.append((command, params or {}))
            raise RuntimeError("listing blew up")
        return super().request(command, params, timeout=timeout)


def test_module_catalog_wraps_an_unexpected_error(tmp_path: Path) -> None:
    service, session_id = _open_paused(tmp_path, _ModulesListBoomWorker())
    result = service.module_catalog(session_id)
    assert result.ok is False and result.error is not None


def test_module_catalog_reports_a_missing_modules_list_capability(tmp_path: Path) -> None:
    service, session_id = _open_paused(tmp_path, _NoModulesListWorker())
    result = service.module_catalog(session_id)
    assert result.ok is False and result.error is not None
    assert result.error.code == "capability_unavailable"
