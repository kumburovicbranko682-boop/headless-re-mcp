"""Terminal-state and error guards inside the unpack phase-advance helpers.

``_advance_unpack_after_dump`` / ``_after_imports_rebuilt`` / ``_after_verify``
each refuse to advance a session that has already failed and swallow an
``UnpackSessionError`` from the phase-bridge note. The happy flows never hit
either branch, so these drive both directly against the real service.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.core import service_unpack
from headless_re_mcp.unpack.session import (
    UnpackPhase,
    UnpackSessionError,
    UnpackSessionState,
    create_unpack_session,
    fail_unpack_session,
    transition,
)
from tests.unit.test_unpack_iat_rebuild_pe_verify import _ready_iat_rebuild


def _running(session_id: str) -> UnpackSessionState:
    state = create_unpack_session(session_id, route="generic_dynamic")
    return transition(state, UnpackPhase.RUNNING, event="run", message="running")


def _failed(session_id: str) -> UnpackSessionState:
    return fail_unpack_session(_running(session_id), code="boom", message="dead")


def _raise(*args: object, **kwargs: object) -> UnpackSessionState:
    raise UnpackSessionError("phase bridge refused")


# --- after_dump ------------------------------------------------------------ #
def test_advance_after_dump_leaves_a_failed_session_failed(tmp_path: Path) -> None:
    service, session_id, _dump, _worker = _ready_iat_rebuild(tmp_path)
    service._store_unpack_session(_failed(session_id))

    service._advance_unpack_after_dump(session_id, path="x", sha256="a" * 64)

    state = service._unpack_owner.get(session_id)
    assert state is not None and state.phase == UnpackPhase.FAILED


def test_advance_after_dump_swallows_a_session_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _dump, _worker = _ready_iat_rebuild(tmp_path)
    service._store_unpack_session(_running(session_id))
    monkeypatch.setattr(service_unpack, "note_dump_success", _raise)

    service._advance_unpack_after_dump(session_id, path="x", sha256="a" * 64)

    state = service._unpack_owner.get(session_id)
    assert state is not None and state.phase == UnpackPhase.RUNNING


# --- after_imports_rebuilt ------------------------------------------------- #
def test_advance_after_imports_rebuilt_leaves_a_failed_session_failed(tmp_path: Path) -> None:
    service, session_id, _dump, _worker = _ready_iat_rebuild(tmp_path)
    service._store_unpack_session(_failed(session_id))

    service._advance_unpack_after_imports_rebuilt(
        session_id, path="x", sha256="a" * 64, kind="iat_rebuilt"
    )

    state = service._unpack_owner.get(session_id)
    assert state is not None and state.phase == UnpackPhase.FAILED


def test_advance_after_imports_rebuilt_swallows_a_session_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _dump, _worker = _ready_iat_rebuild(tmp_path)
    service._store_unpack_session(_running(session_id))
    monkeypatch.setattr(service_unpack, "note_imports_rebuilt", _raise)

    service._advance_unpack_after_imports_rebuilt(
        session_id, path="x", sha256="a" * 64, kind="iat_rebuilt"
    )

    state = service._unpack_owner.get(session_id)
    assert state is not None and state.phase == UnpackPhase.RUNNING


# --- after_verify ---------------------------------------------------------- #
def test_advance_after_verify_leaves_a_failed_session_failed(tmp_path: Path) -> None:
    service, session_id, _dump, _worker = _ready_iat_rebuild(tmp_path)
    service._store_unpack_session(_failed(session_id))

    service._advance_unpack_after_verify(
        session_id, path="x", sha256="a" * 64, open_ida=False, ida_ok=False
    )

    state = service._unpack_owner.get(session_id)
    assert state is not None and state.phase == UnpackPhase.FAILED


def test_advance_after_verify_swallows_a_session_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _dump, _worker = _ready_iat_rebuild(tmp_path)
    service._store_unpack_session(_running(session_id))
    monkeypatch.setattr(service_unpack, "note_verified", _raise)

    service._advance_unpack_after_verify(
        session_id, path="x", sha256="a" * 64, open_ida=True, ida_ok=True
    )

    state = service._unpack_owner.get(session_id)
    assert state is not None and state.phase == UnpackPhase.RUNNING
