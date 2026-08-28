"""Coverage for ``DynamicInspectMixin`` wrappers on ``AnalysisService``.

Two shapes are exercised: the ``invalid_params`` guards each wrapper runs before
touching the backend (reachable with no worker at all), and the success paths of
the handful whose commands the in-process fake worker implements
(``modules.dump``, ``pe.headers.runtime``, ``imports.scan/read``,
``modules.list``) once a dynamic backend is open.
"""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.core.models import Result
from headless_re_mcp.core.service import AnalysisService
from tests.unit.test_dynamic_service import (
    FakeDynamicWorker,
    FakeStaticWorker,
    _create,
    _service,
    _settings,
    _write_minimal_pe,
)

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
