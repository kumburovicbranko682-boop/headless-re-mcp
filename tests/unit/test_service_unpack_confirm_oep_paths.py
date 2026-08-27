"""Branch and error paths across unpack_confirm_oep.

The happy confirm (valid OEP, running/oep_candidate phase, no auto_dump) never
trips the parameter guards, the timeout refresh, the invalid-phase refusal, the
auto_dump guard/base/dump-failure paths, or the two exception handlers. These
drive each against the real service.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from headless_re_mcp.core import service_unpack
from headless_re_mcp.core.models import Result, RpcError
from headless_re_mcp.unpack.session import (
    UnpackPhase,
    UnpackSessionError,
    UnpackSessionState,
    create_unpack_session,
    transition,
)
from tests.unit.test_service_unpack_iat_paths import _stage_blocker
from tests.unit.test_unpack_iat_rebuild_pe_verify import _ready_iat_rebuild

JsonObject = dict[str, object]


def _oep_candidate(session_id: str) -> UnpackSessionState:
    state = create_unpack_session(session_id, route="generic_dynamic")
    state = transition(state, UnpackPhase.RUNNING, event="run", message="running")
    return transition(state, UnpackPhase.OEP_CANDIDATE, event="oep", message="oep candidate")


def _dumped(session_id: str) -> UnpackSessionState:
    state = _oep_candidate(session_id)
    return transition(state, UnpackPhase.DUMPED, event="dump", message="dumped")


def test_confirm_oep_rejects_a_negative_oep_rva(tmp_path: Path) -> None:
    service, session_id, _dump, _worker = _ready_iat_rebuild(tmp_path)

    result = service.unpack_confirm_oep(session_id, oep_rva=-1)

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_params"
    assert "non-negative" in result.error.message


def test_confirm_oep_rejects_a_non_boolean_auto_dump(tmp_path: Path) -> None:
    service, session_id, _dump, _worker = _ready_iat_rebuild(tmp_path)

    result = service.unpack_confirm_oep(
        session_id,
        oep_rva=0x1000,
        auto_dump=1,  # type: ignore[arg-type]
    )

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_params"
    assert "auto_dump" in result.error.message


def test_confirm_oep_stores_a_refreshed_timeout_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _dump, _worker = _ready_iat_rebuild(tmp_path)
    service._store_unpack_session(_oep_candidate(session_id))

    def refresh(state: UnpackSessionState) -> UnpackSessionState:
        return replace(state)

    monkeypatch.setattr(service_unpack, "check_timeout", refresh)

    result = service.unpack_confirm_oep(session_id, oep_rva=0x1000)

    assert result.ok and result.data is not None
    assert result.data["confirmed_oep_rva"] == 0x1000


def test_confirm_oep_refuses_an_invalid_phase(tmp_path: Path) -> None:
    service, session_id, _dump, _worker = _ready_iat_rebuild(tmp_path)
    service._store_unpack_session(_dumped(session_id))

    result = service.unpack_confirm_oep(session_id, oep_rva=0x1000)

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_phase"


def test_confirm_oep_auto_dump_returns_the_stage_guard_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _dump, worker = _ready_iat_rebuild(tmp_path)
    service._store_unpack_session(_oep_candidate(session_id))
    monkeypatch.setattr(service, "_guard_unpack_active", _stage_blocker("confirm_oep_auto_dump"))

    result = service.unpack_confirm_oep(
        session_id, oep_rva=0x1000, auto_dump=True, module_base=worker.module_base
    )

    assert not result.ok and result.error is not None
    assert result.error.code == "unpack_active"


def test_confirm_oep_auto_dump_requires_a_module_base(tmp_path: Path) -> None:
    service, session_id, _dump, _worker = _ready_iat_rebuild(tmp_path)
    service._store_unpack_session(_oep_candidate(session_id))

    result = service.unpack_confirm_oep(session_id, oep_rva=0x1000, auto_dump=True)

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_params"
    assert "module_base" in result.error.message


def test_confirm_oep_auto_dump_propagates_a_dump_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _dump, worker = _ready_iat_rebuild(tmp_path)
    service._store_unpack_session(_oep_candidate(session_id))

    def failing_dump(sid: str, base: int, **kwargs: object) -> Result[JsonObject]:
        return Result(ok=False, error=RpcError(code="dump_failed", message="no module"))

    monkeypatch.setattr(service, "unpack_dump_module", failing_dump)

    result = service.unpack_confirm_oep(
        session_id, oep_rva=0x1000, auto_dump=True, module_base=worker.module_base
    )

    assert not result.ok and result.error is not None
    assert result.error.code == "dump_failed"


def test_confirm_oep_maps_a_session_error_to_invalid_phase(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _dump, _worker = _ready_iat_rebuild(tmp_path)
    service._store_unpack_session(_oep_candidate(session_id))

    def raise_session(*args: object, **kwargs: object) -> UnpackSessionState:
        raise UnpackSessionError("phase rejected")

    monkeypatch.setattr(service_unpack, "append_timeline", raise_session)

    result = service.unpack_confirm_oep(session_id, oep_rva=0x1000)

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_phase"
    assert "phase rejected" in result.error.message


def test_confirm_oep_wraps_an_unexpected_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _dump, _worker = _ready_iat_rebuild(tmp_path)
    service._store_unpack_session(_oep_candidate(session_id))

    def boom(*args: object, **kwargs: object) -> UnpackSessionState:
        raise RuntimeError("kaboom")

    monkeypatch.setattr(service_unpack, "append_timeline", boom)

    result = service.unpack_confirm_oep(session_id, oep_rva=0x1000)

    assert not result.ok and result.error is not None
