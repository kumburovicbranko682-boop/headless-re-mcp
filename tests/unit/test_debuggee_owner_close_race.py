"""A debuggee observation landing after close must not resurrect its snapshot.

Observations arrive after debugger RPCs (debug.state, wait_for_state) that
block for up to their 30s timeout while holding only runtime.lock. close does
not need that lock: it can transition the session and clear the debuggee owner
inside the RPC. The unconditional snapshot write that used to follow
re-inserted an entry for a session that never reopens -- one retained snapshot
per lost race, the very leak clear() exists to prevent.
"""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import SessionState
from headless_re_mcp.core.service import AnalysisService


def _write_pe(path: Path) -> None:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = (0x8664).to_bytes(2, "little")
    image[0x94:0x96] = (0xF0).to_bytes(2, "little")
    optional = 0x98
    image[optional : optional + 2] = (0x20B).to_bytes(2, "little")
    image[optional + 24 : optional + 32] = (0x140000000).to_bytes(8, "little")
    image[optional + 56 : optional + 60] = (0x5000).to_bytes(4, "little")
    path.write_bytes(image)


def _service(tmp_path: Path) -> AnalysisService:
    return AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
        )
    )


def test_an_observation_landing_after_close_does_not_resurrect_the_snapshot(
    tmp_path: Path,
) -> None:
    binary = tmp_path / "target.exe"
    _write_pe(binary)
    service = _service(tmp_path)
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        closed = service.close_session(session_id)
        assert closed.ok, closed.error

        annotated = service._observe_debuggee_state(
            session_id,
            {"state": "paused", "process_id": 123},
        )

        # The caller still gets its annotated reply -- the RPC did complete --
        # but nothing is re-inserted for a session that never reopens.
        assert annotated["debuggee_pid"] == 123
        assert service._debuggee_owner.snapshot(session_id) is None
    finally:
        service.close_all()


def test_a_live_session_still_records_observations(tmp_path: Path) -> None:
    binary = tmp_path / "target.exe"
    _write_pe(binary)
    service = _service(tmp_path)
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]

        service._observe_debuggee_state(
            session_id,
            {"state": "paused", "process_id": 321},
        )

        snapshot = service._debuggee_owner.snapshot(session_id)
        assert snapshot is not None
        assert snapshot.debuggee_pid == 321
        assert snapshot.state == "paused"
    finally:
        service.close_all()


def test_a_failed_session_still_records_its_final_state(tmp_path: Path) -> None:
    """FAILED is not CLOSED: close has not cleared the owner yet.

    A worker that dies mid-operation still reports a last debuggee state, and
    that final observation is worth keeping until close reaps the session.
    """
    binary = tmp_path / "target.exe"
    _write_pe(binary)
    service = _service(tmp_path)
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        service.registry.transition(session_id, SessionState.FAILED)

        service._observe_debuggee_state(
            session_id,
            {"state": "stopped", "process_id": 0},
        )

        snapshot = service._debuggee_owner.snapshot(session_id)
        assert snapshot is not None
        assert snapshot.state == "stopped"
    finally:
        service.close_all()


def test_an_observation_for_a_retired_session_does_not_raise(
    tmp_path: Path,
) -> None:
    """A session reaped from the registry mid-operation ends quietly.

    The projection used to raise SessionNotFound after the snapshot had
    already been written, so the caller got an error and the leak both.
    """
    service = _service(tmp_path)
    try:
        annotated = service._debuggee_owner.observe(
            "no-such-session",
            {"state": "running", "process_id": 7},
            debugger_pid=99,
        )

        assert annotated["debuggee_pid"] == 7
        assert annotated["debugger_pid"] == 99
        assert service._debuggee_owner.snapshot("no-such-session") is None
    finally:
        service.close_all()
