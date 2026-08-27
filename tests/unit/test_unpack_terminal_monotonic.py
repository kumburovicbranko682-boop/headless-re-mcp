"""A terminal unpack session must not be revived by a slower, abandoned worker.

``offload`` runs each tool on a worker thread with ``abandon_on_cancel=True``:
when a slow ``unpack.dump_module``/rebuild hits the catalog timeout (or its
client disconnects) the framework returns immediately but the handler thread
keeps running. That abandoned worker and a fresh ``unpack.cancel`` then both do
a non-atomic get/mutate/put on the same session state. Without a write-side
guard the worker -- which read a pre-terminal snapshot -- can store an active
phase on top of the cancel and resurrect the session.
"""

from __future__ import annotations

import struct
from dataclasses import replace
from pathlib import Path

from headless_re_mcp.config import Settings
from headless_re_mcp.core.runtime_state import UnpackStateOwner
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.unpack.phase_bridge import note_dump_success
from headless_re_mcp.unpack.session import (
    UnpackPhase,
    UnpackSessionState,
    create_unpack_session,
    is_terminal_unpack_phase,
    transition,
)


def _is_terminal(state: UnpackSessionState) -> bool:
    return is_terminal_unpack_phase(state.phase)


def _running(session_id: str = "s1") -> UnpackSessionState:
    detected = create_unpack_session(session_id, route="x64dbg")
    return transition(
        detected,
        UnpackPhase.RUNNING,
        event="running",
        message="debuggee launched",
    )


def test_put_monotonic_rejects_reviving_a_terminal_session() -> None:
    owner: UnpackStateOwner[UnpackSessionState] = UnpackStateOwner()
    running = _running()
    cancelled = replace(running, phase=UnpackPhase.CANCELLED)
    dumped = replace(running, phase=UnpackPhase.DUMPED)

    assert owner.put_monotonic("s1", running, is_terminal=_is_terminal) is running
    assert owner.put_monotonic("s1", cancelled, is_terminal=_is_terminal) is cancelled

    # The abandoned worker's stale, active state must not land on the cancel.
    kept = owner.put_monotonic("s1", dumped, is_terminal=_is_terminal)
    assert kept is cancelled
    assert owner.get("s1") is cancelled


def test_put_monotonic_allows_terminal_to_terminal_moves() -> None:
    owner: UnpackStateOwner[UnpackSessionState] = UnpackStateOwner()
    base = _running("s2")
    reanalyzed = replace(base, phase=UnpackPhase.REANALYZED)
    failed = replace(base, phase=UnpackPhase.FAILED)

    owner.put_monotonic("s2", reanalyzed, is_terminal=_is_terminal)
    # reanalyzed -> failed is a legal terminal->terminal transition (_FORWARD).
    stored = owner.put_monotonic("s2", failed, is_terminal=_is_terminal)
    assert stored is failed
    assert owner.get("s2") is failed


def test_put_monotonic_allows_forward_progress_between_active_phases() -> None:
    owner: UnpackStateOwner[UnpackSessionState] = UnpackStateOwner()
    running = _running("s3")
    dumped = replace(running, phase=UnpackPhase.DUMPED)

    owner.put_monotonic("s3", running, is_terminal=_is_terminal)
    stored = owner.put_monotonic("s3", dumped, is_terminal=_is_terminal)
    assert stored is dumped
    assert owner.get("s3") is dumped


def test_update_if_present_never_creates_an_absent_session() -> None:
    owner: UnpackStateOwner[UnpackSessionState] = UnpackStateOwner()
    called = False

    def _update(state: UnpackSessionState) -> UnpackSessionState:
        nonlocal called
        called = True
        return state

    assert owner.update_if_present("gone", _update, is_terminal=_is_terminal) is None
    assert called is False
    assert owner.get("gone") is None


def test_update_if_present_transforms_current_state_and_keeps_terminal() -> None:
    owner: UnpackStateOwner[UnpackSessionState] = UnpackStateOwner()
    running = _running("s4")
    owner.put_monotonic("s4", running, is_terminal=_is_terminal)

    to_cancelled = owner.update_if_present(
        "s4",
        lambda s: replace(s, phase=UnpackPhase.CANCELLED),
        is_terminal=_is_terminal,
    )
    assert to_cancelled is not None and to_cancelled.phase is UnpackPhase.CANCELLED

    # A late update that would regress the terminal session is refused.
    kept = owner.update_if_present(
        "s4",
        lambda s: replace(s, phase=UnpackPhase.DUMPED),
        is_terminal=_is_terminal,
    )
    assert kept is not None and kept.phase is UnpackPhase.CANCELLED
    assert owner.get("s4").phase is UnpackPhase.CANCELLED


def _write_verified_clr_pe(path: Path) -> None:
    image = bytearray(0x800)
    pe_offset = 0x80
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    file_header = pe_offset + 4
    struct.pack_into("<HHIIIHH", image, file_header, 0x8664, 1, 0, 0, 0, 0xF0, 0x2022)
    optional = file_header + 20
    struct.pack_into("<HBB", image, optional, 0x20B, 14, 0)
    struct.pack_into("<I", image, optional + 16, 0x1000)
    struct.pack_into("<Q", image, optional + 24, 0x140000000)
    struct.pack_into("<II", image, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", image, optional + 56, 0x2000, 0x200)
    struct.pack_into("<HH", image, optional + 68, 3, 0x8160)
    struct.pack_into("<I", image, optional + 108, 16)
    dir_base = optional + 112
    struct.pack_into("<II", image, dir_base + 14 * 8, 0x1100, 72)
    section = optional + 0xF0
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x400, 0x1000, 0x400, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    cor_off = 0x300
    struct.pack_into("<I", image, cor_off, 72)
    struct.pack_into("<HH", image, cor_off + 4, 2, 5)
    struct.pack_into("<II", image, cor_off + 8, 0x1200, 0x40)
    struct.pack_into("<I", image, cor_off + 16, 0x1)
    struct.pack_into("<I", image, cor_off + 20, 0x06000001)
    meta_off = 0x400
    version = b"v4.0.30319\0"
    version_padded = version + b"\0" * ((4 - (len(version) % 4)) % 4)
    image[meta_off : meta_off + 4] = b"BSJB"
    struct.pack_into("<HH", image, meta_off + 4, 1, 1)
    struct.pack_into("<I", image, meta_off + 8, 0)
    struct.pack_into("<I", image, meta_off + 12, len(version))
    image[meta_off + 16 : meta_off + 16 + len(version_padded)] = version_padded
    cursor = meta_off + 16 + len(version_padded)
    struct.pack_into("<HH", image, cursor, 0, 0)
    path.write_bytes(image)


def test_abandoned_dump_worker_cannot_resurrect_a_cancelled_session(tmp_path: Path) -> None:
    """End-to-end: cancel wins even when a stale dump advance stores afterwards."""
    binary = tmp_path / "managed.exe"
    _write_verified_clr_pe(binary)
    service = AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
        )
    )
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]

        service._store_unpack_session(_running(session_id))

        # A slow dump handler reads the RUNNING snapshot, then gets abandoned.
        stale = service._unpack_owner.get(session_id)
        assert stale is not None and stale.phase is UnpackPhase.RUNNING

        cancelled = service.unpack_cancel(session_id)
        assert cancelled.ok, cancelled.error
        assert service._unpack_owner.get(session_id).phase is UnpackPhase.CANCELLED

        # The abandoned worker now finishes and advances its stale snapshot.
        resurrection = note_dump_success(
            stale,
            output_path=str(tmp_path / "dump.bin"),
            sha256="ab" * 32,
            module_base=0x140000000,
        )
        assert resurrection.phase is UnpackPhase.DUMPED

        effective = service._store_unpack_session(resurrection)
        assert effective.phase is UnpackPhase.CANCELLED
        assert service._unpack_owner.get(session_id).phase is UnpackPhase.CANCELLED
    finally:
        service.close_all()


def test_unpack_cancel_racing_close_does_not_recreate_state(tmp_path: Path) -> None:
    """If close clears the session while cancel runs, cancel must not re-create it.

    unpack.cancel reads the session, then does a best-effort debuggee pause before
    storing. close clears the unpack owner in that window; storing the cancel back
    afterwards would resurrect unpack state for a closed session. The atomic
    update_if_present must return None instead of writing.
    """
    binary = tmp_path / "managed.exe"
    _write_verified_clr_pe(binary)
    service = AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
        )
    )
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        service._store_unpack_session(_running(session_id))

        # Inject the race: close clears the owner right after cancel's presence
        # check, standing in for a close that lands during the pause window.
        original_signal = service._signal_unpack_cancel

        def clear_then_signal(sid: str) -> None:
            service._unpack_owner.clear(sid)
            original_signal(sid)

        service._signal_unpack_cancel = clear_then_signal  # type: ignore[method-assign]

        result = service.unpack_cancel(session_id)

        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "unpack_not_started"
        assert service._unpack_owner.get(session_id) is None
    finally:
        service.close_all()
