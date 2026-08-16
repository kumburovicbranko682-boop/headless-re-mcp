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


def test_session_list_says_when_it_stopped(tmp_path: Path) -> None:
    """session.list used to ship every session in one reply.

    Measured: the list carried only count. After the open-session cap, 64
    live plus 64 closed still looks complete without has_more.
    """
    from dataclasses import replace

    from headless_re_mcp.config import Settings
    from headless_re_mcp.core.service import AnalysisService

    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings, registry=SessionRegistry(max_open=20))
    for index in range(15):
        target = tmp_path / f"{index}.js"
        target.write_text("x", encoding="utf-8")
        created = service.create_session(str(target))
        assert created.ok
    page = service.list_sessions(offset=0, limit=5)
    assert page.ok and page.data is not None
    assert page.data["count"] == 5
    assert page.data["total"] == 15
    assert page.data["has_more"] is True
    tail = service.list_sessions(offset=10, limit=5)
    assert tail.data is not None
    assert tail.data["count"] == 5
    assert tail.data["has_more"] is False


def test_open_sessions_are_bounded(tmp_path: Path) -> None:
    """An unattended loop that never closes used to keep every session.

    Measured: 80 creates left 80 live sessions in the registry. Closed
    history was already capped at 64; the live set was not.
    """
    registry = SessionRegistry(max_open=3)
    ids = []
    for index in range(3):
        target = tmp_path / f"{index}.js"
        target.write_text("x", encoding="utf-8")
        ids.append(registry.create(target).id)
    assert len(registry.list()) == 3

    extra = tmp_path / "extra.js"
    extra.write_text("x", encoding="utf-8")
    with pytest.raises(ValueError, match="too many open sessions"):
        registry.create(extra)

    registry.transition(ids[0], SessionState.CLOSING)
    registry.transition(ids[0], SessionState.CLOSED)
    created = registry.create(extra)
    assert created.id not in ids
    assert len([item for item in registry.list() if item.state is not SessionState.CLOSED]) == 3


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
