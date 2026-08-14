from __future__ import annotations

from pathlib import Path

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
