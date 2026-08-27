"""Every artifact-path builder must reject a ``..`` session segment.

The campaign introduced ``_is_safe_session_segment`` because
``Path("..").name == ".."`` slips past the ``Path(sid).name != sid`` check --
``<category>/..`` then resolves one level up onto the artifact root. Several
builders still carried the naive check (or none): the trace and unpack artifact
paths, the x64dbg module-dump / runtime-PE-header dirs, the jadx/apktool work
dir, and the sessions.db restore path that decides which ids come back to life.
registry.get backstops the live tool flow, but a guard that concedes ``..`` is
one refactor away from a real escape and lies about what it enforces. These
tests pin each builder to reject the dot segments at the guard itself.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService, _is_safe_session_segment
from headless_re_mcp.core.session import session_from_store_row

_HOSTILE_SEGMENTS = ["..", ".", "a/b", ""]


def test_is_safe_session_segment_rejects_the_dot_segments() -> None:
    assert _is_safe_session_segment("deadbeef" * 4) is True
    for bad in _HOSTILE_SEGMENTS:
        assert _is_safe_session_segment(bad) is False


def test_trace_artifact_path_refuses_a_dotdot_segment(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    service = AnalysisService(replace(Settings.load(), artifact_root=root))
    try:
        for bad in _HOSTILE_SEGMENTS:
            with pytest.raises(ValueError):
                service._new_trace_artifact_path(bad)
            # The guard fires before registry.get and before any mkdir.
            assert not (root / "trace").exists()
    finally:
        service.close_all()


def test_unpack_session_dir_refuses_a_dotdot_segment(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    service = AnalysisService(replace(Settings.load(), artifact_root=root))
    try:
        for bad in _HOSTILE_SEGMENTS:
            with pytest.raises(ValueError):
                service._unpack_session_dir(bad)
    finally:
        service.close_all()


def test_session_work_dir_yields_nothing_for_a_dotdot_segment(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    service = AnalysisService(replace(Settings.load(), artifact_root=root))
    try:
        for bad in _HOSTILE_SEGMENTS:
            assert service._session_work_dir("jadx", bad) is None
        # A real id still resolves to a contained work dir.
        good = "f" * 32
        resolved = service._session_work_dir("jadx", good)
        assert resolved is not None
        assert resolved == (root / "jadx" / good).resolve()
    finally:
        service.close_all()


def test_module_dump_dir_is_not_created_for_a_dotdot_segment(tmp_path: Path) -> None:
    """modules.dump builds ``dump/<id>`` with no registry.get in front of it.

    A lone ``..`` would resolve ``dump/..`` onto the artifact root and drop the
    dump image there. The call must fail at the segment guard, before the dir
    is made.
    """
    root = tmp_path / "artifacts"
    service = AnalysisService(replace(Settings.load(), artifact_root=root))
    try:
        result = service.modules_dump("..", 0x1000)
        assert result.ok is False
        assert not (root / "dump").exists()

        header = service.pe_headers_runtime("..", 0x1000, save_artifact=True)
        assert header.ok is False
        assert not (root / "dump").exists()
    finally:
        service.close_all()


def test_store_restore_skips_a_dotdot_session_id() -> None:
    """Hydration is the one place the UUID invariant is re-established.

    A ``..`` row (a corrupted or planted sessions.db) must not come back as a
    live session: that id then flows into every artifact builder as a "valid"
    session and unlocks the one-level escape the builders guard against.
    """
    for bad in ("..", ".", "../../elsewhere", ""):
        row = {
            "id": bad,
            "state": "created",
            "binary": "/tmp/whatever.bin",
            "sha256": "0" * 64,
            "architecture": "x64",
        }
        assert session_from_store_row(row) is None


def test_store_restore_accepts_an_ordinary_uuid_row(tmp_path: Path) -> None:
    """The guard must not reject a legitimate, single-component session id."""
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"MZ\x90\x00")
    row = {
        "id": "abcdef01" * 4,
        "state": "created",
        "binary": str(binary),
        "sha256": "0" * 64,
        "architecture": "x64",
    }
    restored = session_from_store_row(row)
    assert restored is not None
    assert restored.id == "abcdef01" * 4
