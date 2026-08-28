"""Coverage for ``DynamicInspectMixin`` wrappers on ``AnalysisService``.

Two shapes are exercised: the ``invalid_params`` guards each wrapper runs before
touching the backend (reachable with no worker at all), and the success paths of
the handful whose commands the in-process fake worker implements
(``modules.dump``, ``pe.headers.runtime``, ``imports.scan/read``,
``modules.list``) once a dynamic backend is open.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.core.models import Result
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.service_dynamic_inspect import (
    _atomic_write_bytes,
    _module_base_present,
)
from tests.unit.test_dynamic_service import (
    FakeDynamicWorker,
    FakeStaticWorker,
    _create,
    _NoNativePeHeadersWorker,
    _service,
    _settings,
    _write_minimal_pe,
)

JsonObject = dict[str, Any]
JsonResult = Result[dict[str, object]]
_BASE = 0x140000000


def _plain_session(tmp_path: Path) -> tuple[AnalysisService, str]:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    service = AnalysisService(_settings(tmp_path))
    return service, _create(service, binary)


def _dynamic_session(tmp_path: Path) -> tuple[AnalysisService, str]:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    service = _service(tmp_path, FakeDynamicWorker(), FakeStaticWorker())
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok
    return service, session_id


def _bad(result: JsonResult) -> None:
    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_params"


# ---------------------------------------------------------------------------
# invalid_params guards
# ---------------------------------------------------------------------------


def test_memory_wrappers_validate_their_inputs(tmp_path: Path) -> None:
    service, session_id = _plain_session(tmp_path)

    _bad(service.memory_regions(session_id, offset=-1))
    _bad(service.memory_regions(session_id, limit=0))
    _bad(service.memory_protect_query(session_id, -1))
    _bad(service.memory_protection(session_id, -1))
    _bad(service.memory_protection(session_id, _BASE, rights=""))


def test_thread_wrappers_validate_their_inputs(tmp_path: Path) -> None:
    service, session_id = _plain_session(tmp_path)

    _bad(service.threads_list(session_id, offset=-1))
    _bad(service.threads_list(session_id, limit=0))
    _bad(service.threads_context_read(session_id, 0))
    _bad(service.threads_context_write(session_id, 0, "rax", 1))


def test_stack_and_disasm_wrappers_validate_their_inputs(tmp_path: Path) -> None:
    service, session_id = _plain_session(tmp_path)

    _bad(service.stack_read(session_id, count=0))
    _bad(service.stack_read(session_id, address=-1))
    _bad(service.stack_trace(session_id, limit=0))
    _bad(service.disassembly_read(session_id, -1))
    _bad(service.disassembly_read(session_id, _BASE, count=0))


def test_symbol_wrappers_validate_their_inputs(tmp_path: Path) -> None:
    service, session_id = _plain_session(tmp_path)

    _bad(service.symbols_list(session_id, 0))
    _bad(service.symbols_list(session_id, _BASE, limit=0))
    _bad(service.symbols_resolve(session_id, ""))


def test_import_wrappers_validate_their_inputs(tmp_path: Path) -> None:
    service, session_id = _plain_session(tmp_path)

    _bad(service.imports_scan(session_id, 0))
    _bad(service.imports_scan(session_id, _BASE, mode="nonsense"))
    _bad(service.imports_read(session_id, 0, 0x40))
    _bad(service.imports_read(session_id, _BASE, 0))


def test_modules_dump_validates_size_and_session_id(tmp_path: Path) -> None:
    service, session_id = _plain_session(tmp_path)

    _bad(service.modules_dump(session_id, _BASE, size=0))

    too_large = service.modules_dump(session_id, _BASE, size=1 << 40)
    assert not too_large.ok and too_large.error is not None
    assert too_large.error.code == "dump_too_large"

    bad_id = service.modules_dump("a/b", _BASE)
    assert not bad_id.ok


def test_pe_headers_runtime_validates_base(tmp_path: Path) -> None:
    service, session_id = _plain_session(tmp_path)

    _bad(service.pe_headers_runtime(session_id, 0))


def test_breakpoint_wrappers_validate_their_inputs(tmp_path: Path) -> None:
    service, session_id = _plain_session(tmp_path)

    _bad(service.breakpoints_hardware_set(session_id, -1))
    _bad(service.breakpoints_hardware_set(session_id, _BASE, bp_type="bogus"))
    _bad(service.breakpoints_hardware_set(session_id, _BASE, size=3))
    _bad(service.breakpoints_memory_set(session_id, _BASE, bp_type="bogus"))
    _bad(service.breakpoints_condition_set(session_id, _BASE, ""))
    _bad(service.breakpoints_condition_set(session_id, _BASE, "rax == 1; drop"))


def test_patches_apply_validates_data(tmp_path: Path) -> None:
    service, session_id = _plain_session(tmp_path)

    _bad(service.patches_apply(session_id, _BASE, ""))


# ---------------------------------------------------------------------------
# success paths (fake-supported commands)
# ---------------------------------------------------------------------------


def test_modules_dump_writes_and_registers_an_artifact(tmp_path: Path) -> None:
    service, session_id = _dynamic_session(tmp_path)

    result = service.modules_dump(session_id, _BASE, size=0x1000)

    assert result.ok and result.data is not None
    assert result.data["artifact_kind"] == "module_dump"
    assert result.data["actual_size"] == 0x1000
    assert Path(str(result.data["output_path"])).is_file()
    assert "artifact_id" in result.data


def test_pe_headers_runtime_saves_a_header_artifact(tmp_path: Path) -> None:
    service, session_id = _dynamic_session(tmp_path)

    result = service.pe_headers_runtime(session_id, _BASE)

    assert result.ok and result.data is not None
    assert result.data["header_artifact"]
    assert Path(str(result.data["header_artifact"])).is_file()


def test_imports_scan_and_read_reach_the_backend(tmp_path: Path) -> None:
    service, session_id = _dynamic_session(tmp_path)

    scanned = service.imports_scan(session_id, _BASE)
    assert scanned.ok and scanned.data is not None
    assert scanned.data["candidate_count"] == 1

    read = service.imports_read(session_id, _BASE + 0x2000, 0x40)
    assert read.ok and read.data is not None
    assert read.data["resolved_count"] >= 1


def test_module_catalog_lists_the_runtime_modules(tmp_path: Path) -> None:
    service, session_id = _dynamic_session(tmp_path)

    catalog = service.module_catalog(session_id)

    assert catalog.ok and catalog.data is not None


def test_memory_regions_and_protect_query_reach_the_backend(tmp_path: Path) -> None:
    service, session_id = _dynamic_session(tmp_path)

    regions = service.memory_regions(session_id)
    assert regions.ok and regions.data is not None

    protect = service.memory_protect_query(session_id, _BASE)
    assert protect.ok and protect.data is not None


# ---------------------------------------------------------------------------
# module-level helpers
# ---------------------------------------------------------------------------


def test_module_base_present_rejects_malformed_payloads() -> None:
    assert _module_base_present(None, _BASE) is False
    assert _module_base_present({"modules": "not-a-list"}, _BASE) is False
    assert _module_base_present({"modules": [{"base": _BASE}]}, _BASE) is True


def test_atomic_write_bytes_cleans_up_when_replace_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(*args: object, **kwargs: object) -> None:
        raise OSError("disk gone")

    monkeypatch.setattr(os, "replace", refuse)

    with pytest.raises(OSError):
        _atomic_write_bytes(tmp_path / "out.bin", b"payload")

    assert list(tmp_path.iterdir()) == []


# ---------------------------------------------------------------------------
# delegation with valid params (commands the fake does not implement)
# ---------------------------------------------------------------------------


def test_thin_wrappers_delegate_valid_params_to_the_backend(tmp_path: Path) -> None:
    service, session_id = _dynamic_session(tmp_path)

    for result in (
        service.memory_protection(session_id, _BASE, rights="erw-"),
        service.threads_context_read(session_id, 1),
        service.threads_context_write(session_id, 1, "rax", 0),
        service.stack_read(session_id, address=_BASE),
        service.symbols_list(session_id, _BASE),
    ):
        assert not result.ok and result.error is not None
        assert result.error.code == "capability_unavailable"


# ---------------------------------------------------------------------------
# modules_dump error arms
# ---------------------------------------------------------------------------


class _CapabilitySubsetWorker(FakeDynamicWorker):
    """Fake worker advertising everything except the listed capabilities."""

    _removed: frozenset[str] = frozenset()

    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset(c for c in super().capabilities if c not in self._removed)


class _NoDumpCapWorker(_CapabilitySubsetWorker):
    _removed = frozenset({"modules.dump"})


class _NoListCapWorker(_CapabilitySubsetWorker):
    _removed = frozenset({"modules.list"})


class _UnloadDuringDumpWorker(FakeDynamicWorker):
    """Report the module gone from modules.list once the dump has run."""

    def __init__(self) -> None:
        super().__init__()
        self._dumped = False

    def request(
        self,
        command: str,
        params: JsonObject | None = None,
        *,
        timeout: float = 120.0,
    ) -> JsonObject:
        if command == "modules.dump":
            self._dumped = True
        if command == "modules.list" and self._dumped:
            return {"modules": []}
        return super().request(command, params, timeout=timeout)


class _NulPathDumpWorker(FakeDynamicWorker):
    """Return an unparseable artifact path from modules.dump."""

    def request(
        self,
        command: str,
        params: JsonObject | None = None,
        *,
        timeout: float = 120.0,
    ) -> JsonObject:
        if command == "modules.dump":
            super().request(command, params, timeout=timeout)
            return {"output_path": "bad\x00path"}
        return super().request(command, params, timeout=timeout)


class _NoFileDumpWorker(FakeDynamicWorker):
    """Acknowledge modules.dump without writing the artifact file."""

    def request(
        self,
        command: str,
        params: JsonObject | None = None,
        *,
        timeout: float = 120.0,
    ) -> JsonObject:
        if command == "modules.dump":
            return {"output_path": str((params or {})["output_path"])}
        return super().request(command, params, timeout=timeout)


def _dump_dir(service: AnalysisService, session_id: str) -> Path:
    return service.settings.artifact_root.expanduser().resolve() / "dump" / session_id


def _worker_session(tmp_path: Path, worker: FakeDynamicWorker) -> tuple[AnalysisService, str]:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    service = _service(tmp_path, worker, FakeStaticWorker())
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok
    return service, session_id


def test_modules_dump_requires_the_dump_capability(tmp_path: Path) -> None:
    service, session_id = _worker_session(tmp_path, _NoDumpCapWorker())

    result = service.modules_dump(session_id, _BASE, size=0x100)

    assert not result.ok and result.error is not None
    assert result.error.code == "capability_unavailable"


def test_modules_dump_rejects_a_base_that_is_not_loaded(tmp_path: Path) -> None:
    service, session_id = _dynamic_session(tmp_path)

    result = service.modules_dump(session_id, 0x9990000, size=0x100)

    assert not result.ok and result.error is not None
    assert result.error.code == "module_not_found"
    assert result.error.details["race"] == "pre_dump"


def test_modules_dump_detects_an_unload_during_the_dump(tmp_path: Path) -> None:
    service, session_id = _worker_session(tmp_path, _UnloadDuringDumpWorker())

    result = service.modules_dump(session_id, _BASE, size=0x100)

    assert not result.ok and result.error is not None
    assert result.error.code == "module_unloaded_during_dump"
    assert list(_dump_dir(service, session_id).iterdir()) == []


def test_modules_dump_without_modules_list_skips_presence_checks(tmp_path: Path) -> None:
    service, session_id = _worker_session(tmp_path, _NoListCapWorker())

    result = service.modules_dump(session_id, _BASE, size=0x100)

    assert result.ok and result.data is not None
    assert result.data["actual_size"] == 0x100


def test_modules_dump_rejects_an_unparseable_returned_path(tmp_path: Path) -> None:
    service, session_id = _worker_session(tmp_path, _NulPathDumpWorker())

    result = service.modules_dump(session_id, _BASE, size=0x100)

    assert not result.ok and result.error is not None
    assert result.error.code == "rpc_protocol_error"
    assert list(_dump_dir(service, session_id).iterdir()) == []


def test_modules_dump_reports_a_missing_artifact_file(tmp_path: Path) -> None:
    service, session_id = _worker_session(tmp_path, _NoFileDumpWorker())

    result = service.modules_dump(session_id, _BASE, size=0x100)

    assert not result.ok and result.error is not None
    assert result.error.code == "artifact_missing"


def test_modules_dump_cleans_up_when_registration_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _dynamic_session(tmp_path)

    def explode(*args: object, **kwargs: object) -> JsonObject:
        raise RuntimeError("repository offline")

    monkeypatch.setattr(type(service), "record_artifact", explode)

    result = service.modules_dump(session_id, _BASE, size=0x100)

    assert not result.ok and result.error is not None
    assert list(_dump_dir(service, session_id).iterdir()) == []


# ---------------------------------------------------------------------------
# pe_headers_runtime arms
# ---------------------------------------------------------------------------


class _HeaderNoFileWorker(FakeDynamicWorker):
    """Answer pe.headers.runtime without producing the header artifact."""

    def request(
        self,
        command: str,
        params: JsonObject | None = None,
        *,
        timeout: float = 120.0,
    ) -> JsonObject:
        if command == "pe.headers.runtime":
            return {"base": (params or {}).get("base"), "machine": 0x8664}
        return super().request(command, params, timeout=timeout)


class _NoHeadersCapWorker(_CapabilitySubsetWorker):
    _removed = frozenset({"pe.headers.runtime"})


class _NoHeadersNoReadWorker(_CapabilitySubsetWorker):
    _removed = frozenset({"pe.headers.runtime", "memory.read"})


def test_pe_headers_runtime_rejects_a_bad_session_id(tmp_path: Path) -> None:
    service, _ = _plain_session(tmp_path)

    result = service.pe_headers_runtime("a/b", _BASE)

    assert not result.ok and result.error is not None


def test_pe_headers_runtime_tolerates_a_worker_that_skips_the_artifact(tmp_path: Path) -> None:
    service, session_id = _worker_session(tmp_path, _HeaderNoFileWorker())

    result = service.pe_headers_runtime(session_id, _BASE)

    assert result.ok and result.data is not None
    assert "header_artifact" not in result.data


def test_pe_headers_fallback_rejects_bytes_that_are_not_a_pe(tmp_path: Path) -> None:
    service, session_id = _worker_session(tmp_path, _NoHeadersCapWorker())

    result = service.pe_headers_runtime(session_id, _BASE)

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_pe"


def test_pe_headers_fallback_returns_the_original_error_when_read_fails(tmp_path: Path) -> None:
    service, session_id = _worker_session(tmp_path, _NoHeadersNoReadWorker())

    result = service.pe_headers_runtime(session_id, _BASE)

    assert not result.ok and result.error is not None
    assert result.error.code == "capability_unavailable"


def test_pe_headers_fallback_can_skip_the_artifact(tmp_path: Path) -> None:
    service, session_id = _worker_session(tmp_path, _NoNativePeHeadersWorker())

    result = service.pe_headers_runtime(session_id, _BASE, save_artifact=False)

    assert result.ok and result.data is not None
    assert result.data["source"] == "memory.read_fallback"
    assert "header_artifact" not in result.data


# ---------------------------------------------------------------------------
# imports_scan and module_catalog arms
# ---------------------------------------------------------------------------


def test_imports_scan_passes_search_bounds(tmp_path: Path) -> None:
    service, session_id = _dynamic_session(tmp_path)

    result = service.imports_scan(
        session_id,
        _BASE,
        search_start=_BASE + 0x1000,
        search_size=0x1000,
    )

    assert result.ok and result.data is not None


def test_imports_scan_fails_closed_without_a_dynamic_backend(tmp_path: Path) -> None:
    service, session_id = _plain_session(tmp_path)

    result = service.imports_scan(session_id, _BASE)

    assert not result.ok and result.error is not None


def test_module_catalog_requires_the_modules_list_capability(tmp_path: Path) -> None:
    service, session_id = _worker_session(tmp_path, _NoListCapWorker())

    result = service.module_catalog(session_id)

    assert not result.ok and result.error is not None
    assert result.error.code == "capability_unavailable"


# ---------------------------------------------------------------------------
# fatal-error arms
# ---------------------------------------------------------------------------


class _FatalListWorker(FakeDynamicWorker):
    """Raise a fatal protocol error from modules.list."""

    def request(
        self,
        command: str,
        params: JsonObject | None = None,
        *,
        timeout: float = 120.0,
    ) -> JsonObject:
        if command == "modules.list":
            raise XdbgRpcError("rpc_protocol_error", "corrupt frame")
        return super().request(command, params, timeout=timeout)


def test_module_catalog_fails_the_runtime_on_a_fatal_worker_error(tmp_path: Path) -> None:
    service, session_id = _worker_session(tmp_path, _FatalListWorker())

    result = service.module_catalog(session_id)

    assert not result.ok and result.error is not None
    assert result.error.code == "rpc_protocol_error"


def test_pe_headers_runtime_fails_the_runtime_when_hashing_raises_fatally(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _dynamic_session(tmp_path)

    def explode(path: Path) -> str:
        raise XdbgRpcError("rpc_protocol_error", "hash interrupted")

    monkeypatch.setattr(
        "headless_re_mcp.core.service_dynamic_inspect.file_sha256",
        explode,
    )

    result = service.pe_headers_runtime(session_id, _BASE)

    assert not result.ok and result.error is not None
    assert result.error.code == "rpc_protocol_error"


def test_imports_scan_maps_snapshot_check_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _dynamic_session(tmp_path)

    def fatal(self: AnalysisService, runtime: object, *, operation: str) -> None:
        raise XdbgRpcError("rpc_protocol_error", "worker wedged")

    monkeypatch.setattr(type(service), "_require_snapshot_fresh_locked", fatal)

    result = service.imports_scan(session_id, _BASE)

    assert not result.ok and result.error is not None
    assert result.error.code == "rpc_protocol_error"


def test_imports_scan_maps_unexpected_snapshot_check_crashes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _dynamic_session(tmp_path)

    def crash(self: AnalysisService, runtime: object, *, operation: str) -> None:
        raise RuntimeError("unexpected")

    monkeypatch.setattr(type(service), "_require_snapshot_fresh_locked", crash)

    result = service.imports_scan(session_id, _BASE)

    assert not result.ok and result.error is not None
