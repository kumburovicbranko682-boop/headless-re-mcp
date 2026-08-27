"""Branch paths in _bounded_runtime_probe and _run_upx_orchestration.

Neither helper is exercised by the happy staged-unpack flows for these
branches: the probe's not-open / modules-failure / empty / malformed / score
outcomes, and the UPX orchestrator's stage-guard bail, unpack failure, and IDA
reanalyze transition. These drive each directly against the real service.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core import service_unpack
from headless_re_mcp.core.models import Result, RpcError
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.unpack.session import (
    UnpackPhase,
    UnpackSessionState,
    create_unpack_session,
)
from tests.unit.test_dynamic_service import FakeDynamicWorker, FakeStaticWorker
from tests.unit.test_service_unpack_dump_and_stub_paths import _write_pe
from tests.unit.test_unpack_iat_rebuild_pe_verify import _ready_iat_rebuild

JsonObject = dict[str, object]


def _fresh_service(tmp_path: Path) -> tuple[AnalysisService, str]:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )
    service = AnalysisService(
        settings,
        dynamic_worker_factory=lambda session, cfg: FakeDynamicWorker(),
        static_worker_factory=lambda session, cfg: FakeStaticWorker(),
    )
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None
    return service, str(created.data["session"]["id"])


def _detected(session_id: str) -> UnpackSessionState:
    return create_unpack_session(session_id, route="generic_dynamic")


# --------------------------------------------------------------------------- #
# _bounded_runtime_probe
# --------------------------------------------------------------------------- #
def test_probe_skips_when_the_dynamic_backend_is_not_open(tmp_path: Path) -> None:
    service, session_id = _fresh_service(tmp_path)

    state, probe = service._bounded_runtime_probe(
        _detected(session_id), session_id, route="generic_dynamic"
    )

    assert probe["dynamic_open"] is False
    assert probe["module_base"] is None


def test_probe_records_a_modules_list_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _dump, _worker = _ready_iat_rebuild(tmp_path)

    def failing(sid: str) -> Result[JsonObject]:
        return Result(ok=False, error=RpcError(code="rpc_error", message="modules boom"))

    monkeypatch.setattr(service, "dynamic_modules", failing)

    _state, probe = service._bounded_runtime_probe(
        _detected(session_id), session_id, route="generic_dynamic"
    )

    assert probe["dynamic_open"] is True
    assert probe["modules_error"] is not None


def test_probe_handles_an_empty_module_list(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _dump, _worker = _ready_iat_rebuild(tmp_path)
    monkeypatch.setattr(
        service, "dynamic_modules", lambda sid: Result(ok=True, data={"modules": []})
    )

    _state, probe = service._bounded_runtime_probe(
        _detected(session_id), session_id, route="generic_dynamic"
    )

    assert probe["module_base"] is None


def test_probe_ignores_a_non_dict_first_module(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _dump, _worker = _ready_iat_rebuild(tmp_path)
    monkeypatch.setattr(
        service, "dynamic_modules", lambda sid: Result(ok=True, data={"modules": ["nope"]})
    )

    _state, probe = service._bounded_runtime_probe(
        _detected(session_id), session_id, route="generic_dynamic"
    )

    assert probe["module_base"] is None


def test_probe_ignores_a_module_with_a_bad_base(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _dump, _worker = _ready_iat_rebuild(tmp_path)
    monkeypatch.setattr(
        service,
        "dynamic_modules",
        lambda sid: Result(ok=True, data={"modules": [{"base": 0, "size": 0x1000}]}),
    )

    _state, probe = service._bounded_runtime_probe(
        _detected(session_id), session_id, route="generic_dynamic"
    )

    assert probe["module_base"] is None


def test_probe_scores_oep_when_a_module_is_found(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _dump, worker = _ready_iat_rebuild(tmp_path)
    monkeypatch.setattr(
        service,
        "dynamic_modules",
        lambda sid: Result(
            ok=True,
            data={"modules": [{"base": worker.module_base, "size": 0x4000, "name": "m"}]},
        ),
    )
    monkeypatch.setattr(
        service,
        "unpack_score_oep",
        lambda sid, **kwargs: Result(ok=True, data={"candidate_count": 3}),
    )

    _state, probe = service._bounded_runtime_probe(
        _detected(session_id), session_id, route="generic_dynamic"
    )

    assert probe["oep_scored"] is True
    assert probe["candidate_count"] == 3
    assert probe["module_base"] == worker.module_base


def test_probe_defers_when_oep_scoring_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _dump, worker = _ready_iat_rebuild(tmp_path)
    monkeypatch.setattr(
        service,
        "dynamic_modules",
        lambda sid: Result(
            ok=True,
            data={"modules": [{"base": worker.module_base, "size": 0x4000, "name": "m"}]},
        ),
    )
    monkeypatch.setattr(
        service,
        "unpack_score_oep",
        lambda sid, **kwargs: Result(
            ok=False, error=RpcError(code="not_paused", message="cannot score")
        ),
    )

    _state, probe = service._bounded_runtime_probe(
        _detected(session_id), session_id, route="generic_dynamic"
    )

    assert probe["oep_scored"] is False
    assert probe["oep_score_error"] is not None


# --------------------------------------------------------------------------- #
# _run_upx_orchestration
# --------------------------------------------------------------------------- #
def test_upx_orchestration_bails_when_the_stage_guard_trips(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _dump, _worker = _ready_iat_rebuild(tmp_path)
    monkeypatch.setattr(service, "unpack_upx_test", lambda sid, **kwargs: Result(ok=True, data={}))

    def guard(state: UnpackSessionState, *, stage: str) -> tuple[UnpackSessionState, str]:
        return state, "unpack_timeout"

    monkeypatch.setattr(service_unpack, "ensure_unpack_active", guard)

    result = service._run_upx_orchestration(
        _detected(session_id), session_id, timeout=1.0, open_ida=False
    )

    assert result.phase == UnpackPhase.DETECTED


def test_upx_orchestration_fails_when_unpack_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _dump, _worker = _ready_iat_rebuild(tmp_path)
    monkeypatch.setattr(service, "unpack_upx_test", lambda sid, **kwargs: Result(ok=True, data={}))
    monkeypatch.setattr(
        service,
        "unpack_upx_unpack",
        lambda sid, **kwargs: Result(ok=False, error=RpcError(code="upx_boom", message="no")),
    )

    result = service._run_upx_orchestration(
        _detected(session_id), session_id, timeout=1.0, open_ida=False
    )

    assert result.phase == UnpackPhase.FAILED
    assert result.failure is not None
    assert result.failure.code == "upx_unpack_failed"


def test_upx_orchestration_reanalyzes_when_ida_reopens(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _dump, _worker = _ready_iat_rebuild(tmp_path)
    out = service.settings.artifact_root.expanduser().resolve() / "unpacked.bin"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(b"MZ" + b"\x00" * 128)

    monkeypatch.setattr(service, "unpack_upx_test", lambda sid, **kwargs: Result(ok=True, data={}))
    monkeypatch.setattr(
        service,
        "unpack_upx_unpack",
        lambda sid, **kwargs: Result(
            ok=True,
            data={
                "output_path": str(out),
                "reanalyze": {"static_open_ok": True},
                "comparison": {},
                "die_rescan": {},
            },
        ),
    )

    result = service._run_upx_orchestration(
        _detected(session_id), session_id, timeout=1.0, open_ida=True
    )

    assert result.phase == UnpackPhase.REANALYZED
