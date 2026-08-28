from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.core.models import (
    Architecture,
    BackendHandle,
    BackendKind,
    SessionState,
    TargetKind,
)
from headless_re_mcp.core.session import (
    InvalidStateTransition,
    SessionNotFound,
    SessionRegistry,
    classify_target,
    detect_elf_architecture,
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


def _write_minimal_elf(path: Path, machine: int, *, big_endian: bool = False) -> None:
    """A header-only ELF: enough magic/class/endianness/e_machine to classify."""
    order = "big" if big_endian else "little"
    image = bytearray(0x40)
    image[:4] = b"\x7fELF"
    image[4] = 2  # ELFCLASS64
    image[5] = 2 if big_endian else 1
    image[6] = 1
    image[0x10:0x12] = (2).to_bytes(2, order)  # ET_EXEC
    image[0x12:0x14] = machine.to_bytes(2, order)
    path.write_bytes(image)


@pytest.mark.parametrize(
    ("machine", "expected"),
    [(0x014C, Architecture.X86), (0x8664, Architecture.X64)],
)
def test_detect_pe_architecture(tmp_path: Path, machine: int, expected: Architecture) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary, machine)
    assert detect_pe_architecture(binary) == expected


@pytest.mark.parametrize(
    ("machine", "expected"),
    [(3, Architecture.X86), (62, Architecture.X64)],
)
def test_detect_elf_architecture_names_x86_and_x64(
    tmp_path: Path, machine: int, expected: Architecture
) -> None:
    binary = tmp_path / "a.out"
    _write_minimal_elf(binary, machine)
    assert detect_elf_architecture(binary) == expected


def test_detect_elf_architecture_is_none_for_an_untagged_machine(tmp_path: Path) -> None:
    """AArch64 (e_machine 183) is a real ELF the two-value enum cannot name.

    It must not raise the way detect_pe_architecture does for an unknown PE
    machine: an ARM/AArch64 ELF is still a valid r2/Ghidra target, so the arch
    tag is simply absent rather than the session being rejected.
    """
    binary = tmp_path / "arm.out"
    _write_minimal_elf(binary, 183)
    assert detect_elf_architecture(binary) is None


def test_detect_elf_architecture_honours_endianness(tmp_path: Path) -> None:
    binary = tmp_path / "be.out"
    _write_minimal_elf(binary, 62, big_endian=True)
    assert detect_elf_architecture(binary) == Architecture.X64


def test_classify_target_recognises_an_elf_by_magic(tmp_path: Path) -> None:
    """An ELF used to fall through to PE and then fail create as 'not a PE file'.

    Magic-based detection makes it a first-class ELF target instead, which is
    what lets the portable backends open a native Linux binary.
    """
    binary = tmp_path / "noext"
    _write_minimal_elf(binary, 62)
    assert classify_target(binary) is TargetKind.ELF


def test_registry_creates_an_elf_session_with_its_architecture(tmp_path: Path) -> None:
    """The end-to-end payoff: an ELF binary becomes a usable ELF session.

    Before this the PE-forced classification made detect_pe_architecture raise,
    so create_session failed outright and r2/Ghidra could never open a Linux
    ELF. Now the session is ELF-kinded, keeps its binary (so require_binary --
    what the portable backends gate on -- returns it) and carries the x64 arch.
    """
    binary = tmp_path / "a.out"
    _write_minimal_elf(binary, 62)
    session = SessionRegistry().create(binary)
    assert session.target is TargetKind.ELF
    assert session.binary == binary.resolve()
    assert session.architecture is Architecture.X64


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


def test_hydrate_restores_an_elf_session_as_elf(tmp_path: Path) -> None:
    """A persisted ELF row must come back an ELF, not a PE.

    Rehydration re-derives the target from the file rather than a stored
    column, and classify_target keys an extensionless native binary off its
    magic bytes. ELF is a first-class target now, so the realistic restore
    path -- unclean shutdown, file still on disk -- must reclassify \\x7fELF as
    ELF and keep the architecture the store held, exactly as the PE row above
    does. A regression that dropped the ELF magic branch would silently
    restore every Linux session as a PE.
    """
    binary = tmp_path / "a.out"
    _write_minimal_elf(binary, 62)
    session = session_from_store_row(
        {
            "id": "e1" * 16,
            "binary": str(binary),
            "sha256": "b" * 64,
            "architecture": "x64",
            "state": "running",
        }
    )
    assert session is not None
    assert session.target == TargetKind.ELF
    assert session.architecture == Architecture.X64
    assert session.binary is not None
    assert session.metadata.get("missing_file") is not True


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
