"""Closes the remaining partial branch arcs in core/service_unpack.py.

Statement coverage of the module is complete; these exercise the not-yet-taken
side of conditionals in unpack_dump_module, unpack_iat_validate/rebuild,
unpack_verify, unpack_score_oep, the runtime OEP collector, the bounded probe,
and the UPX orchestrator.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.core import service_unpack
from headless_re_mcp.core.models import Result, RpcError
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.unpack.session import UnpackPhase, UnpackSessionState, create_unpack_session
from tests.unit.test_dynamic_service import FakeDynamicWorker
from tests.unit.test_service_unpack_dump_and_stub_paths import (
    _MODULE_BASE,
    _open_session,
)
from tests.unit.test_service_unpack_dump_and_stub_paths import _service as _dump_service
from tests.unit.test_service_unpack_dump_and_stub_paths import _write_pe as _dump_write_pe
from tests.unit.test_service_unpack_iat_paths import _iat_va
from tests.unit.test_service_unpack_verify_paths import _prepared_dump
from tests.unit.test_service_unpack_verify_paths import _service as _verify_service
from tests.unit.test_service_unpack_verify_paths import _write_pe as _verify_write_pe
from tests.unit.test_unpack_iat_rebuild_pe_verify import _ready_iat_rebuild

JsonObject = dict[str, object]


def _detected(session_id: str) -> UnpackSessionState:
    return create_unpack_session(session_id, route="generic_dynamic")


# --------------------------------------------------------------------------- #
# unpack_dump_module
# --------------------------------------------------------------------------- #
def test_dump_module_can_skip_saving_headers(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _dump_write_pe(binary)
    service = _dump_service(tmp_path, FakeDynamicWorker())
    session_id = _open_session(service, binary)

    result = service.unpack_dump_module(session_id, _MODULE_BASE, size=0x200, save_headers=False)

    assert result.ok and result.data is not None
    assert "headers" not in result.data


def test_dump_module_skips_advance_without_an_output_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "sample.exe"
    _dump_write_pe(binary)
    service = _dump_service(tmp_path, FakeDynamicWorker())
    session_id = _open_session(service, binary)

    monkeypatch.setattr(
        service,
        "modules_dump",
        lambda sid, base, **kwargs: Result(ok=True, data={"claims_universal_unpack": False}),
    )

    result = service.unpack_dump_module(session_id, _MODULE_BASE, size=0x200, save_headers=False)

    assert result.ok and result.data is not None


# --------------------------------------------------------------------------- #
# unpack_iat_validate / unpack_iat_rebuild
# --------------------------------------------------------------------------- #
def test_iat_validate_ignores_a_non_int_stub_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, dump_file, worker = _ready_iat_rebuild(tmp_path)
    monkeypatch.setattr(
        service_unpack,
        "analyze_dump_stub_coupling",
        lambda path, **kwargs: {"ok": True, "still_vm_stub_count": "x", "code_nonzero_ratio": 0.9},
    )

    result = service.unpack_iat_validate(
        session_id, iat_va=_iat_va(worker), size=0x20, dump_path=str(dump_file)
    )

    assert result.ok and result.data is not None


def test_iat_validate_downgrade_leaves_non_recoverable_recoverability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, dump_file, worker = _ready_iat_rebuild(tmp_path)
    monkeypatch.setattr(
        service_unpack,
        "analyze_dump_stub_coupling",
        lambda path, **kwargs: {"ok": True, "still_vm_stub_count": 1, "code_nonzero_ratio": 0.01},
    )
    monkeypatch.setattr(
        service_unpack,
        "gate_iat_rebuild",
        lambda analysis, **kwargs: {
            "rebuild_allowed": True,
            "recoverability": "iat_insufficient",
            "reasons": [],
        },
    )

    result = service.unpack_iat_validate(
        session_id, iat_va=_iat_va(worker), size=0x20, dump_path=str(dump_file)
    )

    assert result.ok and result.data is not None
    gate = result.data["rebuild_gate"]
    assert isinstance(gate, dict)
    assert gate["recoverability"] == "iat_insufficient"


def test_iat_rebuild_downgrade_leaves_non_recoverable_recoverability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, dump_file, worker = _ready_iat_rebuild(tmp_path)
    monkeypatch.setattr(
        service_unpack,
        "analyze_dump_stub_coupling",
        lambda path, **kwargs: {"ok": True, "still_vm_stub_count": 1, "code_nonzero_ratio": 0.01},
    )
    monkeypatch.setattr(
        service_unpack,
        "gate_iat_rebuild",
        lambda analysis, **kwargs: {
            "rebuild_allowed": True,
            "recoverability": "iat_insufficient",
            "reasons": [],
        },
    )

    result = service.unpack_iat_rebuild(
        session_id, str(dump_file), iat_va=_iat_va(worker), size=0x20
    )

    assert not result.ok and result.error is not None
    assert result.error.code == "iat_rebuild_blocked"


# --------------------------------------------------------------------------- #
# unpack_verify
# --------------------------------------------------------------------------- #
def test_verify_reopens_in_ida_without_a_baseline(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _verify_write_pe(binary)
    service = _verify_service(tmp_path, FakeDynamicWorker())
    session_id, dump_path = _prepared_dump(service, binary)

    result = service.unpack_verify(session_id, dump_path, use_die=False, open_ida=True)

    assert result.ok and result.data is not None
    ida = result.data["ida"]
    assert isinstance(ida, dict)
    assert ida["static_open_ok"] is True
    assert "baseline_functions" not in ida


# --------------------------------------------------------------------------- #
# unpack_score_oep
# --------------------------------------------------------------------------- #
def test_score_oep_ignores_a_non_int_auto_entry_point(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _dump, worker = _ready_iat_rebuild(tmp_path)
    monkeypatch.setattr(
        service,
        "_collect_oep_observations_from_runtime",
        lambda sid, **kwargs: Result(
            ok=True,
            data={
                "observations": [],
                "stub_rva_ranges": [],
                "entry_point_rva": None,
                "note": "n",
            },
        ),
    )

    result = service.unpack_score_oep(
        session_id, module_base=worker.module_base, module_size=0x4000
    )

    assert result.ok and result.data is not None
    assert "entry_point_rva" not in result.data


# --------------------------------------------------------------------------- #
# _collect_oep_observations_from_runtime
# --------------------------------------------------------------------------- #
def _collect(
    service: AnalysisService,
    session_id: str,
    module_base: int,
    *,
    stub: list[tuple[int, int]],
    previous: list[JsonObject] | None,
) -> Result[JsonObject]:
    return service._collect_oep_observations_from_runtime(
        session_id,
        module_base=module_base,
        module_size=0x4000,
        stub_rva_ranges=stub,
        imports_resolved_hint=False,
        previous_regions=previous,
    )


def _regions(base: int) -> Result[JsonObject]:
    return Result(
        ok=True,
        data={"regions": [{"base": base, "size": 0x1000, "protect": 0x40, "protect_name": "rwx"}]},
    )


def test_collect_handles_non_dict_regs_failed_pe_and_supplied_previous(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _dump, worker = _ready_iat_rebuild(tmp_path)
    base = worker.module_base
    monkeypatch.setattr(
        service, "dynamic_registers_read", lambda sid: Result(ok=True, data={"registers": "nope"})
    )
    monkeypatch.setattr(service, "memory_regions", lambda sid, **kwargs: _regions(base))
    monkeypatch.setattr(
        service,
        "pe_headers_runtime",
        lambda sid, mod_base, **kwargs: Result(ok=False, error=RpcError(code="hx", message="no")),
    )
    monkeypatch.setattr(service_unpack, "collect_oep_observations", lambda **kwargs: [{"rva": 1}])

    result = _collect(
        service,
        session_id,
        base,
        stub=[(0x1000, 0x40)],
        previous=[{"base": 1, "size": 2, "protect": 3, "protect_name": "x"}],
    )

    assert result.ok and result.data is not None
    assert result.data["rip"] is None


def test_collect_handles_non_int_rip_bad_entry_and_non_list_sections(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _dump, worker = _ready_iat_rebuild(tmp_path)
    base = worker.module_base
    monkeypatch.setattr(
        service,
        "dynamic_registers_read",
        lambda sid: Result(ok=True, data={"registers": {"rip": "x", "eip": 0x123}}),
    )
    monkeypatch.setattr(service, "memory_regions", lambda sid, **kwargs: _regions(base))
    monkeypatch.setattr(
        service,
        "pe_headers_runtime",
        lambda sid, mod_base, **kwargs: Result(
            ok=True, data={"entry_point_rva": "nope", "sections": "notalist"}
        ),
    )
    monkeypatch.setattr(service_unpack, "collect_oep_observations", lambda **kwargs: [{"rva": 1}])

    result = _collect(service, session_id, base, stub=[], previous=None)

    assert result.ok and result.data is not None
    assert result.data["rip"] == 0x123
    assert result.data["entry_point_rva"] is None


def test_collect_handles_missing_rip_int_entry_and_supplied_stub(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _dump, worker = _ready_iat_rebuild(tmp_path)
    base = worker.module_base
    monkeypatch.setattr(
        service,
        "dynamic_registers_read",
        lambda sid: Result(ok=True, data={"registers": {"rax": 1}}),
    )
    monkeypatch.setattr(service, "memory_regions", lambda sid, **kwargs: _regions(base))
    monkeypatch.setattr(
        service,
        "pe_headers_runtime",
        lambda sid, mod_base, **kwargs: Result(
            ok=True, data={"entry_point_rva": 0x100, "sections": [{"name": ".text"}]}
        ),
    )
    monkeypatch.setattr(service_unpack, "collect_oep_observations", lambda **kwargs: [{"rva": 1}])

    result = _collect(service, session_id, base, stub=[(0x2000, 0x40)], previous=None)

    assert result.ok and result.data is not None
    assert result.data["rip"] is None
    assert result.data["entry_point_rva"] == 0x100


# --------------------------------------------------------------------------- #
# _bounded_runtime_probe / _run_upx_orchestration
# --------------------------------------------------------------------------- #
def test_probe_records_a_module_base_but_skips_scoring_without_a_size(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _dump, worker = _ready_iat_rebuild(tmp_path)
    monkeypatch.setattr(
        service,
        "dynamic_modules",
        lambda sid: Result(
            ok=True, data={"modules": [{"base": worker.module_base, "size": "nope", "name": "m"}]}
        ),
    )

    _state, probe = service._bounded_runtime_probe(
        _detected(session_id), session_id, route="generic_dynamic"
    )

    assert probe["module_base"] == worker.module_base
    assert probe["oep_scored"] is False


def test_upx_orchestration_verifies_without_an_output_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _dump, _worker = _ready_iat_rebuild(tmp_path)
    monkeypatch.setattr(service, "unpack_upx_test", lambda sid, **kwargs: Result(ok=True, data={}))
    monkeypatch.setattr(
        service,
        "unpack_upx_unpack",
        lambda sid, **kwargs: Result(
            ok=True, data={"reanalyze": {}, "comparison": {}, "die_rescan": {}}
        ),
    )

    result = service._run_upx_orchestration(
        _detected(session_id), session_id, timeout=1.0, open_ida=False
    )

    assert result.phase == UnpackPhase.VERIFIED
