"""Branch and error paths across unpack_plan / start / cancel / artifacts and guards.

The staged happy flows never trip the classify failure, the non-list candidate
guard, the replace/timeout/route branches of unpack_start (dotnet-inspect
failure, generic-dynamic probe, mid-orchestration close race, bounded cancel),
the empty-session guards of cancel/artifacts, or the terminal-refresh guard and
the invalid-session-id path. These drive each against the real service.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from headless_re_mcp.backends.common.bounded_run import BoundedCancelled
from headless_re_mcp.core import service_unpack
from headless_re_mcp.core.models import Result, RpcError, SessionState
from headless_re_mcp.unpack.session import (
    UnpackPhase,
    UnpackSessionState,
    cancel_unpack_session,
    create_unpack_session,
    fail_unpack_session,
    transition,
)
from tests.unit.test_service_unpack_probe_and_upx_paths import _fresh_service
from tests.unit.test_unpack_iat_rebuild_pe_verify import _ready_iat_rebuild

JsonObject = dict[str, object]


def _failed(session_id: str) -> UnpackSessionState:
    state = create_unpack_session(session_id, route="generic_dynamic")
    state = transition(state, UnpackPhase.RUNNING, event="run", message="running")
    return fail_unpack_session(state, code="boom", message="dead")


def _cancelled(session_id: str) -> UnpackSessionState:
    return cancel_unpack_session(
        create_unpack_session(session_id, route="generic_dynamic"), reason="stop"
    )


# --------------------------------------------------------------------------- #
# unpack_plan
# --------------------------------------------------------------------------- #
def test_plan_propagates_a_classify_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _dump, _worker = _ready_iat_rebuild(tmp_path)
    monkeypatch.setattr(
        service,
        "packer_classify",
        lambda sid, **kwargs: Result(ok=False, error=RpcError(code="classify_failed", message="x")),
    )

    result = service.unpack_plan(session_id)

    assert not result.ok and result.error is not None
    assert result.error.code == "classify_failed"


def test_plan_tolerates_a_non_list_candidate_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _fresh_service(tmp_path)
    monkeypatch.setattr(
        service,
        "packer_classify",
        lambda sid, **kwargs: Result(ok=True, data={"candidates": "nope"}),
    )

    result = service.unpack_plan(session_id)

    assert result.ok and result.data is not None
    assert "plan" in result.data


# --------------------------------------------------------------------------- #
# unpack_start
# --------------------------------------------------------------------------- #
def test_start_rejects_a_non_boolean_replace(tmp_path: Path) -> None:
    service, session_id, _dump, _worker = _ready_iat_rebuild(tmp_path)

    result = service.unpack_start(session_id, replace=1)  # type: ignore[arg-type]

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_params"


def test_start_refreshes_a_timed_out_existing_session_then_propagates_plan_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _dump, _worker = _ready_iat_rebuild(tmp_path)
    service._store_unpack_session(_failed(session_id))
    monkeypatch.setattr(service_unpack, "check_timeout", lambda state: replace(state))
    monkeypatch.setattr(
        service,
        "unpack_plan",
        lambda sid, **kwargs: Result(ok=False, error=RpcError(code="plan_failed", message="x")),
    )

    result = service.unpack_start(session_id)

    assert not result.ok and result.error is not None
    assert result.error.code == "plan_failed"


def test_start_records_a_dotnet_inspect_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _dump, _worker = _ready_iat_rebuild(tmp_path)
    monkeypatch.setattr(
        service,
        "unpack_plan",
        lambda sid, **kwargs: Result(ok=True, data={"plan": {"route": "dotnet"}}),
    )
    monkeypatch.setattr(
        service,
        "dotnet_inspect",
        lambda sid, **kwargs: Result(ok=False, error=RpcError(code="clr_bad", message="no clr")),
    )

    result = service.unpack_start(session_id, replace=True)

    assert result.ok and result.data is not None
    probe = result.data["bounded_probe"]
    assert isinstance(probe, dict)
    assert probe["dotnet_inspect_ok"] is False


def test_start_runs_a_bounded_probe_on_the_generic_dynamic_route(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _dump, _worker = _ready_iat_rebuild(tmp_path)
    monkeypatch.setattr(
        service,
        "unpack_plan",
        lambda sid, **kwargs: Result(ok=True, data={"plan": {"route": "generic_dynamic"}}),
    )

    result = service.unpack_start(session_id, replace=True)

    assert result.ok and result.data is not None
    probe = result.data["bounded_probe"]
    assert isinstance(probe, dict)
    assert probe["route"] == "generic_dynamic"


def test_start_raises_when_the_session_closes_mid_orchestration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _dump, _worker = _ready_iat_rebuild(tmp_path)
    real_session = service.registry.get(session_id)

    class _Terminal:
        state = SessionState.FAILED

    # unpack_start reads the session at entry, after planning, inside
    # _reset_unpack_cancel, and again before storing; only that final read
    # should observe a session that was closed mid-orchestration.
    calls = {"n": 0}

    def fake_get(sid: str) -> object:
        calls["n"] += 1
        return _Terminal() if calls["n"] >= 4 else real_session

    monkeypatch.setattr(service.registry, "get", fake_get)
    monkeypatch.setattr(
        service,
        "unpack_plan",
        lambda sid, **kwargs: Result(ok=True, data={"plan": {"route": "none"}}),
    )

    result = service.unpack_start(session_id, replace=True)

    assert not result.ok and result.error is not None


def test_start_treats_a_bounded_cancel_as_a_preserved_cancel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _dump, _worker = _ready_iat_rebuild(tmp_path)
    monkeypatch.setattr(
        service,
        "unpack_plan",
        lambda sid, **kwargs: Result(ok=True, data={"plan": {"route": "upx"}}),
    )

    def cancel(state: UnpackSessionState, sid: str, **kwargs: object) -> UnpackSessionState:
        raise BoundedCancelled()

    monkeypatch.setattr(service, "_run_upx_orchestration", cancel)

    result = service.unpack_start(session_id, replace=True, execute_upx=True)

    assert result.ok and result.data is not None
    assert result.data["original_input_preserved"] is True
    unpack = result.data["unpack"]
    assert isinstance(unpack, dict)
    assert unpack["phase"] == UnpackPhase.CANCELLED.value


# --------------------------------------------------------------------------- #
# unpack_cancel / unpack_artifacts
# --------------------------------------------------------------------------- #
def test_cancel_without_a_session_reports_not_started(tmp_path: Path) -> None:
    service, session_id = _fresh_service(tmp_path)

    result = service.unpack_cancel(session_id)

    assert not result.ok and result.error is not None
    assert result.error.code == "unpack_not_started"


def test_cancel_attempts_a_pause_when_the_dynamic_backend_is_open(tmp_path: Path) -> None:
    service, session_id, _dump, _worker = _ready_iat_rebuild(tmp_path)

    result = service.unpack_cancel(session_id)

    assert result.ok and result.data is not None
    assert result.data["debuggee_paused_attempted"] is True


def test_artifacts_without_a_session_reports_not_started(tmp_path: Path) -> None:
    service, session_id = _fresh_service(tmp_path)

    result = service.unpack_artifacts(session_id)

    assert not result.ok and result.error is not None
    assert result.error.code == "unpack_not_started"


# --------------------------------------------------------------------------- #
# _unpack_session_dir / _guard_unpack_active
# --------------------------------------------------------------------------- #
def test_session_dir_rejects_a_traversal_style_session_id(tmp_path: Path) -> None:
    service, _session_id = _fresh_service(tmp_path)

    with pytest.raises(ValueError):
        service._unpack_session_dir("../evil")


def test_guard_refreshes_and_blocks_a_terminal_session(tmp_path: Path) -> None:
    service, session_id, _dump, _worker = _ready_iat_rebuild(tmp_path)
    service._store_unpack_session(_cancelled(session_id))

    blocked = service._guard_unpack_active(session_id, stage="score_oep")

    assert blocked is not None
    assert not blocked.ok
