from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from headless_re_mcp.core.models import (
    Architecture,
    BackendHandle,
    BackendKind,
    SessionState,
)
from headless_re_mcp.core.session import (
    InvalidStateTransition,
    SessionNotFound,
    SessionRegistry,
    detect_pe_architecture,
    hydrate_persisted_sessions,
    session_from_store_row,
)


def _write_minimal_pe(path: Path, machine: int) -> None:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = machine.to_bytes(2, "little")
    path.write_bytes(image)


@pytest.mark.parametrize(
    ("machine", "expected"),
    [(0x014C, Architecture.X86), (0x8664, Architecture.X64)],
)
def test_detect_pe_architecture(tmp_path: Path, machine: int, expected: Architecture) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary, machine)
    assert detect_pe_architecture(binary) == expected


def test_registry_state_machine(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary, 0x8664)
    registry = SessionRegistry()
    session = registry.create(binary)
    assert session.architecture == Architecture.X64
    assert registry.transition(session.id, SessionState.OPENING).state == SessionState.OPENING
    assert registry.transition(session.id, SessionState.READY).state == SessionState.READY
    assert registry.transition(session.id, SessionState.CLOSING).state == SessionState.CLOSING
    assert registry.transition(session.id, SessionState.CLOSED).state == SessionState.CLOSED
    registry.remove_closed(session.id)
    with pytest.raises(KeyError):
        registry.get(session.id)


def test_closed_sessions_are_retained_but_bounded(tmp_path: Path) -> None:
    """A closed session stays readable for a while, but not forever.

    The registry lives in memory and nothing outside tests ever called
    remove_closed, so every session a long-lived server had ever opened stayed
    resident and session.list handed back the entire history. Five hundred
    open/close cycles left five hundred sessions behind.
    """
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary, 0x8664)
    registry = SessionRegistry(retained_closed=3)

    ids = []
    for _ in range(10):
        session = registry.create(binary)
        ids.append(session.id)
        registry.transition(session.id, SessionState.CLOSING)
        registry.transition(session.id, SessionState.CLOSED)

    assert len(registry.list()) == 3
    # The newest closures are the ones a caller might still ask about.
    assert [item.id for item in registry.list()] == ids[-3:]
    for stale in ids[:-3]:
        with pytest.raises(KeyError):
            registry.get(stale)


def test_failed_sessions_enter_the_closed_retirement_queue(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary, 0x8664)
    registry = SessionRegistry(retained_closed=3)
    ids = []
    for _ in range(6):
        session = registry.create(binary)
        ids.append(session.id)
        registry.transition(session.id, SessionState.FAILED)

    assert len(registry.list()) == 3
    for stale in ids[:-3]:
        with pytest.raises(KeyError):
            registry.get(stale)


def test_retiring_closed_sessions_never_touches_a_live_one(tmp_path: Path) -> None:
    """A long-running session must survive any number of closures around it."""
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary, 0x8664)
    registry = SessionRegistry(retained_closed=2)
    survivor = registry.create(binary)
    registry.transition(survivor.id, SessionState.OPENING)
    registry.transition(survivor.id, SessionState.READY)

    for _ in range(10):
        session = registry.create(binary)
        registry.transition(session.id, SessionState.CLOSING)
        registry.transition(session.id, SessionState.CLOSED)

    assert registry.get(survivor.id).state == SessionState.READY


def test_opening_may_return_to_created(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary, 0x8664)
    registry = SessionRegistry()
    session = registry.create(binary)
    registry.transition(session.id, SessionState.OPENING)
    assert registry.transition(session.id, SessionState.CREATED).state == SessionState.CREATED


def test_registry_rejects_invalid_transition(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary, 0x014C)
    registry = SessionRegistry()
    session = registry.create(binary)
    with pytest.raises(InvalidStateTransition):
        registry.transition(session.id, SessionState.RUNNING)


def test_registry_updates_backend_and_metadata(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary, 0x8664)
    registry = SessionRegistry()
    session = registry.create(binary)
    handle = BackendHandle(
        kind=BackendKind.IDA,
        worker_id="ida:test",
        pid=123,
        capabilities=frozenset({"static.functions"}),
    )

    attached = registry.attach_backend(session.id, handle)
    assert attached.backends[BackendKind.IDA].pid == 123
    updated = registry.update_metadata(session.id, {"image_base": 0x140000000})
    assert updated.metadata["image_base"] == 0x140000000
    detached = registry.detach_backend(session.id, BackendKind.IDA)
    assert BackendKind.IDA not in detached.backends


def test_a_missing_session_error_does_not_echo_an_unbounded_id() -> None:
    """The id is caller-controlled and used to sit in the message and the details.

    Measured: 200,000 characters produced a 400,229 byte envelope, twice the
    input, because the same string was interpolated into the exception and
    then copied into details.session_id.
    """
    from headless_re_mcp.core.results import _failure

    huge = "A" * 200_000
    with pytest.raises(SessionNotFound) as caught:
        SessionRegistry().get(huge)
    text = str(caught.value)
    assert huge not in text
    assert "200000" in text
    assert len(text) < 100

    result = _failure(caught.value, session_id=huge)
    dumped = result.model_dump_json()
    assert result.error is not None
    assert result.error.code == "session_not_found"
    assert huge not in dumped
    assert len(dumped) < 8_000
    assert "200000" in dumped


@pytest.mark.parametrize("session_id", [["x"], {"a": 1}, 5, 1.5, True, None, b"x"])
def test_a_non_string_session_id_reads_as_not_found_not_a_crash(session_id: object) -> None:
    """No non-string names a session, so the registry refuses it cleanly.

    session_id is schema-typed as a string, but the agent transport binds it
    straight from model output. An unhashable id (list, dict) raised TypeError
    out of dict.get -- filed as internal_error by most service envelopes, and
    escaped close_session with no envelope at all because the bookkeeping hook
    repeated the lookup while handling the first failure. A hashable
    non-string (int) got past dict.get only to crash for_id's len() *while the
    not-found was being named*.     Both must read as the session_not_found every
    caller already handles.
    """
    with pytest.raises(SessionNotFound) as caught:
        SessionRegistry().get(cast(Any, session_id))
    assert type(session_id).__name__ in str(caught.value)


def test_for_id_names_a_non_string_id_without_echoing_it() -> None:
    """The formatter itself must survive what it is asked to name."""
    error = SessionNotFound.for_id(["deadbeef"])
    assert "list" in str(error)
    assert "deadbeef" not in str(error)


@pytest.mark.parametrize("session_id", [["x"], {"a": 1}, 5, None])
def test_timeline_list_answers_not_found_for_a_non_string_id(
    tmp_path: Path, session_id: object
) -> None:
    """timeline.list skips the registry (a timeline outlives its session).

    So it never met the registry's refusal: a non-string id raised TypeError
    out of the timeline path builder and was filed as a logged internal_error
    incident. It must answer the same session_not_found the registry-backed
    methods give.
    """
    from dataclasses import replace

    from headless_re_mcp.config import Settings
    from headless_re_mcp.core.service import AnalysisService

    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    try:
        result = service.timeline_list(cast(Any, session_id))
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "session_not_found"
    finally:
        service.close_all()


def test_adopt_keeps_the_original_id(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary, 0x8664)
    registry = SessionRegistry()
    original = registry.create(binary)
    other = SessionRegistry()
    adopted = other.adopt(original)
    assert adopted.id == original.id
    assert other.get(original.id).locator == str(binary.resolve())
    # A second adopt must not replace a live row.
    shadow = original.model_copy(update={"metadata": {"restored": True}})
    kept = other.adopt(shadow)
    assert kept.metadata.get("restored") is not True


def test_hydrate_restores_unclean_rows_as_created(tmp_path: Path) -> None:
    from datetime import UTC, datetime

    binary = tmp_path / "keep.exe"
    _write_minimal_pe(binary, 0x8664)
    session_id = "ab" * 16
    rows = [
        {
            "id": session_id,
            "binary": str(binary),
            "sha256": "a" * 64,
            "architecture": "x64",
            "state": "ready",
            "created_at": datetime.now(UTC).isoformat(),
            "updated_at": datetime.now(UTC).isoformat(),
            "closed_cleanly": 0,
        },
        {
            "id": "cd" * 16,
            "binary": str(binary),
            "state": "closed",
            "closed_cleanly": 0,
        },
    ]

    class _Source:
        def list_unclean_sessions(
            self, *, offset: int = 0, limit: int = 100
        ) -> tuple[list[dict[str, object]], int]:
            return rows[offset : offset + limit], len(rows)

    registry = SessionRegistry()
    assert hydrate_persisted_sessions(registry, _Source()) == 1
    restored = registry.get(session_id)
    assert restored.state == SessionState.CREATED
    assert restored.metadata.get("restored") is True
    assert restored.architecture == Architecture.X64
    with pytest.raises(SessionNotFound):
        registry.get("cd" * 16)


def test_store_row_survives_a_missing_file(tmp_path: Path) -> None:
    missing = tmp_path / "gone.exe"
    session = session_from_store_row(
        {
            "id": "ef" * 16,
            "binary": str(missing),
            "architecture": "x86",
            "state": "running",
        }
    )
    assert session is not None
    assert session.binary is None
    assert session.locator == str(missing)
    assert session.metadata.get("missing_file") is True
    assert session.architecture == Architecture.X86
