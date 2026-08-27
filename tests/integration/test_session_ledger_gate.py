"""Live Gate for the session ledger: artifacts, timeline, and audit surfaces.

Every capture the product makes -- reports, unpacked binaries, HAR files,
process dumps -- lands as a registered artifact, and ``artifacts.list`` /
``artifacts.describe`` / ``artifacts.read`` are how an agent finds and inspects
them without shell access. ``artifacts.gc`` is the retention loop that keeps
the artifact root from growing forever. Next to that sit the two ledgers:
``timeline.list`` (the per-session diagnostic log, file-backed) and
``audit.list`` (the store-backed action log). All of it is pure Python over
the session store -- no debugger, device, or external CLI -- yet none of it had
a dedicated end-to-end gate; a regression in content integrity, the
newest-artifact GC guarantee, or the lifecycle bookkeeping would only surface
through the agent misreading its own history.

This gate drives the real service against a committed PE fixture, using
``report.generate`` as the artifact producer so the bytes on disk are real:
describe metadata must match the file (size and sha256), ``artifacts.read``
must return the exact bytes and reassemble across pages, GC must evict
oldest-first while never touching the newest artifact, the timeline must
record ``session.created``/``session.closed`` and answer ``session_not_found``
for ids it never saw, and the audit log must record ``session.create``/
``session.close`` with the asymmetry pinned: audit is a filter over a global
log (unknown id reads as empty), the timeline is per-session (unknown id is an
error). No toolchain, so it never skips.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_REPO = Path(__file__).resolve().parents[2]
_PE = _REPO / "fixtures" / "upx" / "console_fixture-x64.pre-upx.exe"


def _service(tmp_path: Path) -> AnalysisService:
    return AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
            diec=None,
        )
    )


def _require(path: Path) -> None:
    if not path.is_file():
        pytest.skip(f"fixture missing: {path}")


def _open(service: AnalysisService, path: Path) -> str:
    created = service.create_session(str(path))
    assert created.ok and created.data is not None, created.error
    return str(created.data["session"]["id"])


def _report(service: AnalysisService, session_id: str, **kwargs: object) -> tuple[str, Path]:
    generated = service.report_generate(session_id, **kwargs)
    assert generated.ok and generated.data is not None, generated.error
    return str(generated.data["artifact_id"]), Path(str(generated.data["path"]))


@pytest.mark.integration
def test_artifact_describe_matches_bytes_on_disk(tmp_path: Path) -> None:
    _require(_PE)
    service = _service(tmp_path)
    session_id = _open(service, _PE)
    artifact_id, path = _report(service, session_id)
    raw = path.read_bytes()

    listed = service.artifacts_list(session_id)
    assert listed.ok and listed.data is not None, listed.error
    assert listed.data["total"] == 1
    assert listed.data["has_more"] is False
    row = listed.data["artifacts"][0]
    assert row["id"] == artifact_id
    assert row["kind"] == "report_markdown"

    # The global listing (no session filter) reaches the same artifact.
    everywhere = service.artifacts_list(None)
    assert everywhere.ok and everywhere.data is not None, everywhere.error
    assert artifact_id in {item["id"] for item in everywhere.data["artifacts"]}

    described = service.artifacts_describe(artifact_id)
    assert described.ok and described.data is not None, described.error
    artifact = described.data["artifact"]
    assert artifact["session_id"] == session_id
    assert artifact["kind"] == "report_markdown"
    assert artifact["source"] == "report.generate"
    assert Path(str(artifact["path"])) == path
    # Metadata must describe the file as it is, not as it was registered.
    assert artifact["size"] == len(raw)
    assert artifact["sha256"] == hashlib.sha256(raw).hexdigest()
    assert str(artifact["created_at"])


@pytest.mark.integration
def test_artifacts_read_returns_exact_bytes_and_paginates(tmp_path: Path) -> None:
    _require(_PE)
    service = _service(tmp_path)
    session_id = _open(service, _PE)
    artifact_id, path = _report(service, session_id)
    raw = path.read_bytes()
    assert len(raw) > 16

    whole = service.artifacts_read(artifact_id, offset=0, limit=256 * 1024)
    assert whole.ok and whole.data is not None, whole.error
    assert whole.data["encoding"] == "hex"
    assert whole.data["size"] == len(raw)
    assert bytes.fromhex(str(whole.data["data"])) == raw

    # Two windows reassemble the file exactly; each page still reports the
    # whole file's size so a caller can plan the next offset.
    half = len(raw) // 2
    first = service.artifacts_read(artifact_id, offset=0, limit=half)
    second = service.artifacts_read(artifact_id, offset=half, limit=len(raw))
    assert first.ok and first.data is not None, first.error
    assert second.ok and second.data is not None, second.error
    assert first.data["size"] == len(raw)
    reassembled = bytes.fromhex(str(first.data["data"])) + bytes.fromhex(str(second.data["data"]))
    assert reassembled == raw

    # limit is clamped to at least one byte, and reading past EOF answers
    # honestly: empty data, real size, no error.
    one = service.artifacts_read(artifact_id, offset=0, limit=0)
    assert one.ok and one.data is not None, one.error
    assert bytes.fromhex(str(one.data["data"])) == raw[:1]
    beyond = service.artifacts_read(artifact_id, offset=len(raw) + 64, limit=64)
    assert beyond.ok and beyond.data is not None, beyond.error
    assert beyond.data["data"] == ""
    assert beyond.data["size"] == len(raw)


@pytest.mark.integration
def test_gc_evicts_oldest_and_never_the_newest(tmp_path: Path) -> None:
    _require(_PE)
    service = _service(tmp_path)
    session_id = _open(service, _PE)
    old_id, old_path = _report(service, session_id)
    new_id, new_path = _report(service, session_id, title="second report")
    assert old_id != new_id

    # A one-byte budget cannot hold either file, yet the newest artifact is
    # never collected: the caller who just produced it still holds its path.
    collected = service.artifacts_gc(max_total_bytes=1)
    assert collected.ok and collected.data is not None, collected.error
    assert collected.data["removed"] == [old_id]
    assert collected.data["count"] == 1
    assert collected.data["skipped_count"] == 0
    assert collected.data["invalid_path_count"] == 0
    assert collected.data["bytes_remaining_estimate"] == new_path.stat().st_size

    assert not old_path.exists()
    gone = service.artifacts_describe(old_id)
    assert not gone.ok and gone.error is not None
    assert gone.error.code == "not_found"

    kept = service.artifacts_describe(new_id)
    assert kept.ok, kept.error
    assert new_path.is_file()

    # A comfortable budget is a no-op, not a re-collection.
    idle = service.artifacts_gc(max_total_bytes=512 * 1024 * 1024)
    assert idle.ok and idle.data is not None, idle.error
    assert idle.data["removed"] == []
    assert idle.data["count"] == 0


@pytest.mark.integration
def test_timeline_records_session_lifecycle(tmp_path: Path) -> None:
    _require(_PE)
    service = _service(tmp_path)
    session_id = _open(service, _PE)

    opened = service.timeline_list(session_id)
    assert opened.ok and opened.data is not None, opened.error
    assert [event["event"] for event in opened.data["events"]] == ["session.created"]

    closed = service.close_session(session_id)
    assert closed.ok, closed.error

    full = service.timeline_list(session_id)
    assert full.ok and full.data is not None, full.error
    assert [event["event"] for event in full.data["events"]] == [
        "session.created",
        "session.closed",
    ]
    assert full.data["total"] == 2
    assert full.data["events"][1]["details"] == {"ok": True}

    # Pagination walks the same file: one entry per page, oldest first.
    page_one = service.timeline_list(session_id, offset=0, limit=1)
    assert page_one.ok and page_one.data is not None, page_one.error
    assert [event["event"] for event in page_one.data["events"]] == ["session.created"]
    assert page_one.data["has_more"] is True
    page_two = service.timeline_list(session_id, offset=1, limit=1)
    assert page_two.ok and page_two.data is not None, page_two.error
    assert [event["event"] for event in page_two.data["events"]] == ["session.closed"]
    assert page_two.data["has_more"] is False

    # No timeline file means no such session -- a different answer from a
    # session that has not done anything yet.
    unknown = service.timeline_list("0" * 32)
    assert not unknown.ok and unknown.error is not None
    assert unknown.error.code == "session_not_found"


@pytest.mark.integration
def test_audit_scopes_by_session_and_reads_globally(tmp_path: Path) -> None:
    _require(_PE)
    service = _service(tmp_path)
    first_id = _open(service, _PE)

    scoped = service.audit_list(first_id)
    assert scoped.ok and scoped.data is not None, scoped.error
    assert scoped.data["total"] == 1
    entry = scoped.data["entries"][0]
    assert entry["action"] == "session.create"
    assert bool(entry["ok"]) is True
    assert entry["params_summary"]["binary"] == str(_PE)
    assert entry["result_summary"]["session_id"] == first_id

    closed = service.close_session(first_id)
    assert closed.ok, closed.error
    after_close = service.audit_list(first_id)
    assert after_close.ok and after_close.data is not None, after_close.error
    # Newest first: the close lands on top of the create.
    assert [item["action"] for item in after_close.data["entries"]] == [
        "session.close",
        "session.create",
    ]

    # The global view spans sessions; the scoped view never leaks a neighbour.
    second_id = _open(service, _PE)
    everywhere = service.audit_list(None)
    assert everywhere.ok and everywhere.data is not None, everywhere.error
    assert everywhere.data["total"] == 3
    assert {item["session_id"] for item in everywhere.data["entries"]} == {first_id, second_id}
    second_only = service.audit_list(second_id)
    assert second_only.ok and second_only.data is not None, second_only.error
    assert {item["session_id"] for item in second_only.data["entries"]} == {second_id}

    # Audit is a filter over a global log, so an unknown id is an empty page,
    # not an error -- the documented asymmetry with timeline.list above.
    unknown = service.audit_list("0" * 32)
    assert unknown.ok and unknown.data is not None, unknown.error
    assert unknown.data["entries"] == []
    assert unknown.data["total"] == 0


@pytest.mark.integration
def test_ledger_guards_fail_closed(tmp_path: Path) -> None:
    _require(_PE)
    service = _service(tmp_path)
    session_id = _open(service, _PE)
    _report(service, session_id)

    missing = service.artifacts_describe("f" * 32)
    assert not missing.ok and missing.error is not None
    assert missing.error.code == "not_found"

    unreadable = service.artifacts_read("f" * 32)
    assert not unreadable.ok and unreadable.error is not None
    assert unreadable.error.code == "not_found"

    # The GC budget must be a positive integer; zero would mean "collect
    # everything" and a bool is a type confusion, not a byte count.
    zero = service.artifacts_gc(max_total_bytes=0)
    assert not zero.ok and zero.error is not None
    assert zero.error.code == "invalid_request"
    coerced = service.artifacts_gc(max_total_bytes=True)
    assert not coerced.ok and coerced.error is not None
    assert coerced.error.code == "invalid_request"

    # A hostile session id must not become a path under the artifact root.
    hostile = service.timeline_list("../escape")
    assert not hostile.ok and hostile.error is not None
    assert hostile.error.code == "invalid_request"
