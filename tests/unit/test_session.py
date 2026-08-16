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
    assert registry.closed_history() == (7, 3)
    for stale in ids[:-3]:
        with pytest.raises(KeyError):
            registry.get(stale)


def test_session_list_says_when_closed_history_was_cut(tmp_path: Path) -> None:
    """10 closures with retain=3 used to come back as count=3, unmarked.

    session.list is what an unattended agent reaches for after a night of
    analysis. A list sitting at the retained cap looked like the whole
    history, so the older closed sessions disappeared from whoever was
    supposed to reconstruct the night.
    """
    from headless_re_mcp.core.service import AnalysisService

    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary, 0x8664)
    service = AnalysisService(registry=SessionRegistry(retained_closed=3))
    try:
        for _ in range(10):
            created = service.create_session(str(binary))
            assert created.ok and created.data is not None
            closed = service.close_session(created.data["session"]["id"])
            assert closed.ok, closed.error
        listed = service.list_sessions()
        assert listed.ok and listed.data is not None
        assert listed.data["count"] == 3
        assert listed.data["closed_dropped"] == 7
        assert listed.data["retained_closed"] == 3
        assert listed.data["has_more"] is True
    finally:
        service.close_all()


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
