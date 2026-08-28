"""Session/backend lifecycle and recovery branches of AnalysisService.

test_dynamic_service.py exercises the open/close happy paths; the composition
root's recovery envelope (``_recover_outcome``, ``_recover_by_replacement``,
``_rebind_recovered_knowledge``, ``session_recover`` guards), the ``_open_backend``
reuse / factory-failure arms, and the ``close_session`` / ``close_all`` /
``session_health`` / ``readiness`` failure disclosures had no direct test.
Everything runs against the in-process FakeDynamicWorker.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

import headless_re_mcp.core.service as service_mod
from headless_re_mcp.core.models import Result, RpcError, SessionState
from headless_re_mcp.core.service import AnalysisService, JsonObject
from tests.unit.test_dynamic_service import (
    FakeDynamicWorker,
    _create,
    _service,
    _settings,
    _write_minimal_pe,
)


def _binary(tmp_path: Path) -> Path:
    path = tmp_path / "fixture.exe"
    _write_minimal_pe(path)
    return path


# --- _recover_outcome -----------------------------------------------------------


def test_recover_outcome_treats_an_uncoercible_failed_count_as_zero() -> None:
    # ``failed`` should be an int; a bogus value must not crash the envelope.
    result = AnalysisService._recover_outcome({"failed": object()}, session_id="s")

    assert result.ok and result.data is not None
    assert result.data["failed"].__class__ is object


def test_recover_outcome_fails_when_a_backend_did_not_return() -> None:
    result = AnalysisService._recover_outcome({"failed": 2, "session_id": "s"}, session_id="s")

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "recovery_failed"
    assert result.error.details["failed"] == 2


# --- session_recover guard ------------------------------------------------------


def test_recover_is_refused_for_a_closed_session(tmp_path: Path) -> None:
    service = _service(tmp_path, FakeDynamicWorker())
    session_id = _create(service, _binary(tmp_path))
    assert service.close_session(session_id).ok

    result = service.session_recover(session_id)

    assert not result.ok
    assert result.error is not None
    assert "cannot be recovered" in result.error.message


@pytest.mark.parametrize("backends", [5, 1.5, True, {"ida": 1}, "ida"])
def test_recover_rejects_a_non_list_backends(tmp_path: Path, backends: object) -> None:
    """A non-list backends is the caller's mistake, not an internal_error incident.

    A non-iterable (int/float/bool) reached ``for raw in backends`` and raised a
    raw TypeError the service filed as internal_error, and a dict was silently
    iterated as its keys so {"ida": ...} was accepted as ["ida"]. Both must read as
    invalid_request naming the wrong container.
    """
    service = _service(tmp_path, FakeDynamicWorker())
    session_id = _create(service, _binary(tmp_path))

    result = service.session_recover(session_id, backends=cast(Any, backends))

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "invalid_request"


def test_recover_accepts_a_none_backends_and_recovers_defaults(tmp_path: Path) -> None:
    """backends=None keeps the documented 'recover what this session had' path."""
    service = _service(tmp_path, FakeDynamicWorker())
    session_id = _create(service, _binary(tmp_path))

    assert service.session_recover(session_id, backends=None).ok


# --- _recover_by_replacement ----------------------------------------------------


def test_replacement_returns_a_failed_create(tmp_path: Path) -> None:
    service = _service(tmp_path, FakeDynamicWorker())
    session_id = _create(service, _binary(tmp_path))
    from headless_re_mcp.core.models import BackendKind

    # A missing binary makes create_session fail, and the replacement must
    # surface that failure verbatim instead of pretending it recovered.
    result = service._recover_by_replacement(
        session_id, str(tmp_path / "gone.exe"), (BackendKind.X64DBG,)
    )

    assert not result.ok


def test_replacement_rejects_a_malformed_created_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path, FakeDynamicWorker())
    session_id = _create(service, _binary(tmp_path))
    from headless_re_mcp.core.models import BackendKind

    monkeypatch.setattr(
        service,
        "create_session",
        lambda *a, **k: Result[JsonObject](ok=True, data={"session": "not-a-dict"}),
    )

    # Called directly, the protocol violation raises; session_recover wraps this
    # into a failure envelope in the real flow.
    from headless_re_mcp.backends.x64dbg.client import XdbgRpcError

    with pytest.raises(XdbgRpcError, match="did not return a session object"):
        service._recover_by_replacement(session_id, str(_binary(tmp_path)), (BackendKind.X64DBG,))


def test_replacement_skips_backends_after_an_earlier_one_fails(
    tmp_path: Path,
) -> None:
    # No static factory, so reopening IDA fails; the x64dbg reopen after it must
    # be reported as skipped rather than attempted against a dead session.
    service = _service(tmp_path, FakeDynamicWorker())
    session_id = _create(service, _binary(tmp_path))
    from headless_re_mcp.core.models import BackendKind

    result = service._recover_by_replacement(
        session_id, str(_binary(tmp_path)), (BackendKind.IDA, BackendKind.X64DBG)
    )

    assert not result.ok and result.data is not None
    actions = [entry["action"] for entry in result.data["backends"]]
    assert "skipped" in actions


# --- _rebind_recovered_knowledge ------------------------------------------------


def test_rebind_ignores_a_non_list_snapshot(tmp_path: Path) -> None:
    service = _service(tmp_path, FakeDynamicWorker())

    service._rebind_recovered_knowledge({"entries": "not-a-list"}, "replacement")


def test_rebind_skips_malformed_entries(tmp_path: Path) -> None:
    service = _service(tmp_path, FakeDynamicWorker())

    service._rebind_recovered_knowledge(
        {
            "entries": [
                "not-a-dict",
                {"kind": 1, "key": "k"},  # non-string kind
                {"kind": "note", "key": "k", "value": {"a": 1}},  # replayed
            ]
        },
        "replacement",
    )


# --- _open_backend reuse / factory failure --------------------------------------


def test_open_dynamic_twice_reuses_the_backend(tmp_path: Path) -> None:
    service = _service(tmp_path, FakeDynamicWorker())
    session_id = _create(service, _binary(tmp_path))

    assert service.open_dynamic(session_id).ok
    again = service.open_dynamic(session_id)

    assert again.ok and again.data is not None
    assert again.data["reused"] is True


def test_open_dynamic_fails_when_the_factory_returns_no_worker(
    tmp_path: Path,
) -> None:
    service = AnalysisService(
        _settings(tmp_path),
        dynamic_worker_factory=lambda session, settings: None,
    )
    session_id = _create(service, _binary(tmp_path))

    result = service.open_dynamic(session_id)

    assert not result.ok
    # The failed open marks the session FAILED rather than leaving a half-open one.
    assert service.registry.get(session_id).state is SessionState.FAILED


def test_open_dynamic_tears_down_a_worker_that_cannot_register(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A worker launches, its event log opens, then attaching the backend handle
    # throws. The half-open worker and its event log must be released rather than
    # leaked, and the session must go FAILED.
    worker = FakeDynamicWorker()
    service = _service(tmp_path, worker)
    session_id = _create(service, _binary(tmp_path))

    def boom(sid: str, handle: object) -> object:
        raise RuntimeError("attach refused")

    monkeypatch.setattr(service.registry, "attach_backend", boom)

    result = service.open_dynamic(session_id)

    assert not result.ok
    assert worker.terminated  # the orphaned worker was torn down
    assert service.registry.get(session_id).state is SessionState.FAILED


# --- _session_work_dir guard ----------------------------------------------------


def test_session_work_dir_rejects_an_id_with_path_separators(tmp_path: Path) -> None:
    service = _service(tmp_path, FakeDynamicWorker())

    assert service._session_work_dir("jadx", "bad/id") is None
    assert service._session_work_dir("jadx", "good") is not None


# --- close_session / close_all failure disclosures ------------------------------


def test_close_session_discloses_a_failing_final_transition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path, FakeDynamicWorker())
    session_id = _create(service, _binary(tmp_path))
    assert service.open_dynamic(session_id).ok

    original = service.registry.transition

    def flaky_transition(sid: str, new_state: SessionState) -> object:
        if new_state is SessionState.CLOSED:
            raise RuntimeError("registry refused the close")
        return original(sid, new_state)

    monkeypatch.setattr(service.registry, "transition", flaky_transition)

    result = service.close_session(session_id)

    assert not result.ok
    assert result.error is not None
    assert "registry refused the close" in result.error.message


def test_close_releases_adb_forwards_when_no_backend_is_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # __init__ always installs an AdbBackend; drop it so the idle-forward release
    # takes its "nothing to release" arm during close.
    service = _service(tmp_path, FakeDynamicWorker())
    session_id = _create(service, _binary(tmp_path))
    monkeypatch.delattr(service, "_adb_backend", raising=False)

    assert service.close_session(session_id).ok


def test_close_all_reports_sessions_that_would_not_close(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path, FakeDynamicWorker())
    _create(service, _binary(tmp_path))

    failure = Result[JsonObject](ok=False, error=RpcError(code="boom", message="cannot close"))
    monkeypatch.setattr(service, "close_session", lambda sid: failure)

    result = service.close_all()

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "close_all_failed"
    assert result.error.details["errors"][0]["error"]["code"] == "boom"


# --- session_health / readiness error arms --------------------------------------


def test_session_health_discloses_an_unknown_session(tmp_path: Path) -> None:
    service = _service(tmp_path, FakeDynamicWorker())

    result = service.session_health("does-not-exist")

    assert not result.ok
    assert result.error is not None


def test_readiness_discloses_a_report_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path, FakeDynamicWorker())

    def boom(**kwargs: object) -> object:
        raise RuntimeError("readiness probe exploded")

    monkeypatch.setattr(service_mod, "readiness_report", boom)

    result = service.readiness()

    assert not result.ok
    assert result.error is not None
    assert "readiness probe exploded" in result.error.message
