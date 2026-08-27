"""Branch and error paths in unpack_score_oep and its runtime collector.

The happy OEP scoring flow (observations supplied, session in RUNNING) never
trips the stage guard, the auto-collected stub-range merge, the non-RUNNING
timeline branch, or the collector's registers/regions failure and
no-observations paths. These drive each against the real service.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.core import service_unpack
from headless_re_mcp.core.models import Result, RpcError
from headless_re_mcp.core.service import AnalysisService
from tests.unit.test_service_unpack_iat_paths import _stage_blocker
from tests.unit.test_unpack_iat_rebuild_pe_verify import _ready_iat_rebuild

JsonObject = dict[str, object]
_MODULE_SIZE = 0x4000


def _fail(code: str, retryable: bool = False):  # type: ignore[no-untyped-def]
    def call(*args: object, **kwargs: object) -> Result[JsonObject]:
        return Result(
            ok=False,
            error=RpcError(
                code=code, message=f"{code} boom", details={"x": 1}, retryable=retryable
            ),
        )

    return call


def _regs_ok(rip: int):  # type: ignore[no-untyped-def]
    def call(session_id: str) -> Result[JsonObject]:
        return Result(ok=True, data={"registers": {"rip": rip}})

    return call


# --------------------------------------------------------------------------- #
# unpack_score_oep
# --------------------------------------------------------------------------- #
def test_score_oep_returns_the_stage_guard_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _dump, worker = _ready_iat_rebuild(tmp_path)
    monkeypatch.setattr(service, "_guard_unpack_active", _stage_blocker("score_oep"))

    result = service.unpack_score_oep(
        session_id, module_base=worker.module_base, module_size=_MODULE_SIZE
    )

    assert not result.ok and result.error is not None
    assert result.error.code == "unpack_active"


def test_score_oep_with_supplied_observations_appends_a_timeline_entry(
    tmp_path: Path,
) -> None:
    # The session left by the harness is OEP_CANDIDATE (not RUNNING), so the
    # non-RUNNING timeline branch runs, and a supplied stub range is echoed
    # back in the payload.
    service, session_id, _dump, worker = _ready_iat_rebuild(tmp_path)

    result = service.unpack_score_oep(
        session_id,
        module_base=worker.module_base,
        module_size=_MODULE_SIZE,
        observations=[{"kind": "rip_in_main_module_code", "rva": 0x100}],
        stub_rva_ranges=[(0x1000, 0x40)],
    )

    assert result.ok and result.data is not None
    assert result.data["auto_collected"] is False
    assert result.data["stub_rva_ranges"] == [{"rva": 0x1000, "size": 0x40}]


def test_score_oep_merges_stub_ranges_from_auto_collection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _dump, worker = _ready_iat_rebuild(tmp_path)

    def collect(sid: str, **kwargs: object) -> Result[JsonObject]:
        return Result(
            ok=True,
            data={
                "observations": [],
                "stub_rva_ranges": [(0x2000, 0x80)],
                "entry_point_rva": 0x100,
                "note": "auto note",
            },
        )

    monkeypatch.setattr(service, "_collect_oep_observations_from_runtime", collect)

    result = service.unpack_score_oep(
        session_id, module_base=worker.module_base, module_size=_MODULE_SIZE
    )

    assert result.ok and result.data is not None
    assert result.data["auto_collected"] is True
    assert result.data["stub_rva_ranges"] == [{"rva": 0x2000, "size": 0x80}]
    assert result.data["entry_point_rva"] == 0x100
    assert result.data["note"] == "auto note"


# --------------------------------------------------------------------------- #
# _collect_oep_observations_from_runtime
# --------------------------------------------------------------------------- #
def _collect(service: AnalysisService, session_id: str, module_base: int) -> Result[JsonObject]:
    return service._collect_oep_observations_from_runtime(
        session_id,
        module_base=module_base,
        module_size=_MODULE_SIZE,
        stub_rva_ranges=[],
        imports_resolved_hint=False,
        previous_regions=None,
    )


def test_collect_wraps_a_non_backend_registers_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _dump, worker = _ready_iat_rebuild(tmp_path)
    monkeypatch.setattr(service, "dynamic_registers_read", _fail("rpc_error", retryable=True))

    result = _collect(service, session_id, worker.module_base)

    assert not result.ok and result.error is not None
    assert result.error.code == "rpc_error"
    assert (result.error.details or {}).get("step") == "registers.read"


def test_collect_returns_a_backend_unavailable_regions_failure_verbatim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _dump, worker = _ready_iat_rebuild(tmp_path)
    monkeypatch.setattr(service, "dynamic_registers_read", _regs_ok(worker.module_base + 0x100))
    monkeypatch.setattr(service, "memory_regions", _fail("backend_unavailable"))

    result = _collect(service, session_id, worker.module_base)

    assert not result.ok and result.error is not None
    assert result.error.code == "backend_unavailable"
    assert (result.error.details or {}).get("step") is None


def test_collect_wraps_a_non_backend_regions_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _dump, worker = _ready_iat_rebuild(tmp_path)
    monkeypatch.setattr(service, "dynamic_registers_read", _regs_ok(worker.module_base + 0x100))
    monkeypatch.setattr(service, "memory_regions", _fail("rpc_error"))

    result = _collect(service, session_id, worker.module_base)

    assert not result.ok and result.error is not None
    assert result.error.code == "rpc_error"
    assert (result.error.details or {}).get("step") == "memory.regions"


def test_collect_reports_when_snapshots_yield_no_observations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _dump, worker = _ready_iat_rebuild(tmp_path)
    base = worker.module_base
    monkeypatch.setattr(service, "dynamic_registers_read", _regs_ok(base + 0x100))

    def regions(sid: str, *, offset: int = 0, limit: int = 0) -> Result[JsonObject]:
        return Result(
            ok=True,
            data={
                "regions": [{"base": base, "size": 0x1000, "protect": 0x40, "protect_name": "rwx"}]
            },
        )

    def headers(sid: str, mod_base: int, *, save_artifact: bool = False) -> Result[JsonObject]:
        return Result(ok=True, data={"entry_point_rva": 0x100, "sections": []})

    monkeypatch.setattr(service, "memory_regions", regions)
    monkeypatch.setattr(service, "pe_headers_runtime", headers)
    monkeypatch.setattr(service_unpack, "collect_oep_observations", lambda **kwargs: [])

    result = _collect(service, session_id, base)

    assert result.ok and result.data is not None
    assert result.data["observations"] == []
    assert str(result.data["note"]).startswith("runtime snapshots collected but yielded no")
