"""M12 Gate: SQLite artifacts/timeline/audit and unclean session marking.

Everything here is pure Python over the session store -- no debugger, IDA, or
Win32 surface -- so the gate runs on any platform. It used to sit on the
Windows-only skip list and require the locally built ``headless_fixture.exe``,
which meant the persistence semantics it pins (rows surviving a service
restart, unclean marking for a session nobody closed) were only ever exercised
on a machine with the full Windows toolchain. Any committed PE works as the
session target, so the built fixture is preferred but the checkout's own
UPX fixture keeps the gate running everywhere else.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _session_fixture() -> Path:
    built = _PROJECT_ROOT / "artifacts" / "fixtures-x64" / "headless_fixture.exe"
    if built.is_file():
        return built
    committed = _PROJECT_ROOT / "fixtures" / "upx" / "console_fixture-x64.pre-upx.exe"
    if committed.is_file():
        return committed
    pytest.skip("no PE fixture available (neither built nor committed)")


@pytest.mark.integration
def test_m12_session_artifact_timeline_roundtrip(tmp_path: Path) -> None:
    fixture = _session_fixture()
    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )
    service = AnalysisService(settings)
    created = service.create_session(str(fixture))
    assert created.ok and created.data is not None
    session_id = str(created.data["session"]["id"])

    # Register a synthetic artifact under artifact_root.
    art_dir = settings.artifact_root / "manual" / session_id
    art_dir.mkdir(parents=True)
    blob = art_dir / "note.bin"
    blob.write_bytes(b"headless-re-m12")
    import hashlib

    sha = hashlib.sha256(blob.read_bytes()).hexdigest()
    registered = service.repository.register_artifact(
        session_id=session_id,
        kind="manual_note",
        path=blob,
        sha256=sha,
        source="test_m12",
    )
    listed = service.artifacts_list(session_id)
    assert listed.ok and listed.data is not None
    assert listed.data["count"] >= 1
    described = service.artifacts_describe(registered["id"])
    assert described.ok
    read = service.artifacts_read(registered["id"], offset=0, limit=64)
    assert read.ok and read.data is not None
    assert read.data["data"] == blob.read_bytes().hex()

    timeline = service.timeline_list(session_id)
    assert timeline.ok and timeline.data is not None
    assert timeline.data["total"] >= 1

    # Force audit entry via store and expose through audit.list.
    service.repository.append_audit(
        session_id=session_id,
        action="test.action",
        params_summary={"k": 1},
        ok=True,
        result_summary={"v": 2},
    )
    audited = service.audit_list(session_id)
    assert audited.ok and audited.data is not None
    assert audited.data["count"] >= 1

    # GC: create an oversized pressure by capping total bytes low.
    gc = service.artifacts_gc(max_total_bytes=1)
    assert gc.ok and gc.data is not None
    assert "removed" in gc.data

    closed = service.close_session(session_id)
    assert closed.ok

    # New service instance should still see closed session metadata.
    service2 = AnalysisService(settings)
    unclean = service2.sessions_unclean()
    assert unclean.ok and unclean.data is not None
    unclean_ids = {str(item.get('id')) for item in unclean.data.get('sessions') or []}
    assert session_id not in unclean_ids

    # Crash/restart path: open session left unclean.
    created2 = service2.create_session(str(fixture))
    assert created2.ok and created2.data is not None
    dirty_id = str(created2.data['session']['id'])
    service3 = AnalysisService(settings)
    unclean2 = service3.sessions_unclean()
    assert unclean2.ok and unclean2.data is not None
    dirty_ids = {str(item.get('id')) for item in unclean2.data.get('sessions') or []}
    assert dirty_id in dirty_ids
    service3.close_session(dirty_id)
