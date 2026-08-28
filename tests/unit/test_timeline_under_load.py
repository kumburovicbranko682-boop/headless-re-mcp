"""What the session timeline does when the volume or a sibling thread fights it.

The timeline is a diagnostic log that every tool call writes to. Nothing
serialises those writes and nothing above them treats a failed write as
survivable, so both properties are load bearing for a deployment that runs for
days without anyone reading the output.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any, cast

import pytest

import headless_re_mcp.core.store.timeline as timeline_module
from headless_re_mcp.core.store.timeline import (
    append_session_timeline,
    list_session_timeline,
    session_timeline_path,
)


def test_a_timeline_that_cannot_be_written_does_not_fail_the_call(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A dump already on disk must not be reported as an internal error.

    Every tool call records what it did here after doing it, so raising on a
    full volume turned finished work into a failure the caller would retry. One
    call site guarded this and the shared one did not, which made the answer
    depend on which path reached the log.
    """
    path = tmp_path / "sessions" / "abc" / "timeline.jsonl"

    def refuse(*args: object, **kwargs: object) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(Path, "mkdir", refuse)

    entry = append_session_timeline(path, event="modules.dump", message="dumped")

    assert entry["event"] == "modules.dump", "the caller still gets its entry"
    assert "No space left" in str(entry["write_failed"]), "and is told it was not stored"


@pytest.mark.parametrize("session_id", ["", ".", "..", "../outside", "nested/session"])
def test_session_timeline_path_rejects_non_child_session_ids(
    tmp_path: Path,
    session_id: str,
) -> None:
    root = tmp_path / "artifacts"
    outside = root / "timeline.jsonl"
    outside.parent.mkdir()
    outside.write_text('{"event": "private"}\n', encoding="utf-8")

    with pytest.raises(ValueError, match="session id"):
        session_timeline_path(root, session_id)

    assert outside.read_text(encoding="utf-8") == '{"event": "private"}\n'


def test_unserializable_timeline_details_do_not_fail_the_completed_operation(
    tmp_path: Path,
) -> None:
    path = tmp_path / "sessions" / "abc" / "timeline.jsonl"

    entry = append_session_timeline(
        path,
        event="completed",
        message="the operation already succeeded",
        details={"not_json": object()},
    )

    assert entry["event"] == "timeline.entry.write_failed"
    assert entry["details"] == {"error_type": "TypeError"}
    assert "TypeError" in str(entry["write_failed"])
    json.dumps(entry)
    assert not path.exists()


def test_one_oversized_timeline_entry_cannot_break_the_file_cap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(timeline_module, "_MAX_BYTES", 1024)
    monkeypatch.setattr(timeline_module, "_TRIM_TO_BYTES", 768)
    path = tmp_path / "sessions" / "abc" / "timeline.jsonl"

    entry = append_session_timeline(
        path,
        event="huge.result",
        message="completed",
        details={"payload": "x" * 5000},
    )

    assert entry["event"] == "timeline.entry.truncated"
    assert entry["details"]["original_event"] == "huge.result"
    assert entry["details"]["original_bytes"] > 1024
    assert path.stat().st_size <= 1024
    listed = list_session_timeline(path)
    assert listed["events"] == [entry]


def test_paging_walks_bytes_without_changing_a_single_answer(tmp_path: Path) -> None:
    """Reading counts separators and decodes only the page asked for.

    Decoding the whole file under the lock cost 13ms at the 8 MB cap, and every
    append landing behind a reader waited it out; this halved the tail. The
    answers have to be identical, including the last page and a file whose last
    line was never terminated, which is what a crash mid-append leaves.
    """
    path = tmp_path / "sessions" / "abc" / "timeline.jsonl"
    for index in range(250):
        append_session_timeline(path, event="entry", message=f"line {index}")

    whole = path.read_text(encoding="utf-8").splitlines()
    for offset, limit in ((0, 100), (100, 100), (240, 100), (249, 10), (400, 10)):
        page = list_session_timeline(path, offset=offset, limit=limit)
        assert page["total"] == len(whole), f"total wrong at offset {offset}"
        expected = [json.loads(line) for line in whole[offset : offset + limit]]
        assert page["events"] == expected, f"page wrong at offset {offset}"

    with path.open("a", encoding="utf-8") as stream:
        stream.write('{"at": "now", "event": "cut"')  # no newline, as a crash leaves it
    torn = list_session_timeline(path, offset=250, limit=10)
    assert torn["total"] == len(whole) + 1, "an unterminated last line still counts"
    assert torn["events"] == [], "and is skipped rather than breaking the page"
    assert torn["has_more"] is False, "a malformed last line was still consumed"


def test_a_session_that_never_existed_is_not_reported_as_a_quiet_one(
    tmp_path: Path,
) -> None:
    """An empty answer and a missing session are different things.

    Creating a session writes its first timeline entry, so no file at all means
    no such session. Answering ok with an empty list reads as "that analysis did
    nothing", and an agent holding an id from before a restart would take it for
    one. Every other session-scoped call reports session_not_found.
    """
    page = list_session_timeline(tmp_path / "sessions" / "ghost" / "timeline.jsonl")

    assert page["exists"] is False
    assert page["events"] == []


def test_a_session_with_no_events_yet_is_not_mistaken_for_a_missing_one(
    tmp_path: Path,
) -> None:
    """The distinction has to hold in the other direction too."""
    path = tmp_path / "sessions" / "real" / "timeline.jsonl"
    append_session_timeline(path, event="session.created", message="opened")

    page = list_session_timeline(path, offset=50)

    assert "exists" not in page, "a real session must not look missing"
    assert page["total"] == 1


def test_a_traversing_session_id_is_refused_end_to_end(tmp_path: Path) -> None:
    """The read path takes a client-supplied session id; it must not read out.

    session.timeline forwards its session_id argument here unchanged. Plant a
    timeline.jsonl outside the artifact root, make the sessions directory exist
    (as it does once anything has run), then ask for it via ``..``. The service
    must answer with an invalid_request envelope, never the file's contents.
    """
    from headless_re_mcp.config import Settings
    from headless_re_mcp.core.service import AnalysisService

    root = tmp_path / "artifacts"
    (root / "sessions").mkdir(parents=True)
    outside = tmp_path / "outside" / "timeline.jsonl"
    outside.parent.mkdir(parents=True)
    outside.write_text(
        json.dumps({"at": "t", "event": "secret.event", "message": "OUT OF ROOT"}) + "\n",
        encoding="utf-8",
    )

    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=root,
    )
    service = AnalysisService(settings)
    try:
        result = service.timeline_list("../../outside")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
        assert "OUT OF ROOT" not in json.dumps(result.error.model_dump(), default=str)
    finally:
        service.close_all()


@pytest.mark.parametrize(
    ("offset", "limit"),
    [("1", 10), (0, "10"), (1.5, 10), (0, 1.5), (None, 10), (0, None), (0, True)],
)
def test_non_integer_page_arguments_are_refused_end_to_end(
    tmp_path: Path, offset: object, limit: object
) -> None:
    """session.timeline forwards offset/limit unchanged to the file-backed reader.

    The MCP tool schema types them as integers, but the agent transport binds
    raw model output, so a str/float/None/bool used to reach the reader's
    clamps and range() walks and surface as an internal_error incident. The
    service must answer invalid_request instead.
    """
    from headless_re_mcp.config import Settings
    from headless_re_mcp.core.service import AnalysisService

    root = tmp_path / "artifacts"
    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=root,
    )
    service = AnalysisService(settings)
    try:
        result = service.timeline_list(
            "deadbeef" * 4, offset=cast(Any, offset), limit=cast(Any, limit)
        )
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
    finally:
        service.close_all()


def test_closed_session_cleanup_skips_a_traversing_id(tmp_path: Path) -> None:
    """Cleanup unlinks the timeline of a closed session; a bad id must be skipped.

    Stored ids are uuids, but the unlink path once followed a traversing id and
    could have deleted a timeline.jsonl outside the root. Prove the guard: a
    sibling file survives an attempt to forget a ``..`` id.
    """
    from headless_re_mcp.core.store.sqlite_store import SessionStore

    meta = tmp_path / "artifacts" / "meta"
    meta.mkdir(parents=True)
    (tmp_path / "artifacts" / "sessions").mkdir()
    victim = tmp_path / "outside" / "timeline.jsonl"
    victim.parent.mkdir(parents=True)
    victim.write_text("keep me\n", encoding="utf-8")

    store = SessionStore(meta / "store.db")
    store._forget_closed_session_files("../../outside")
    assert victim.is_file(), "cleanup followed a traversing id out of the root"


def test_the_service_reports_a_missing_session_rather_than_an_empty_log() -> None:
    """The store says which it is; this is the layer that turns that into an error.

    SessionNotFound specifically, not a bare KeyError: the envelope maps only
    that type to session_not_found, so a missing dictionary key somewhere else
    cannot tell a caller its session disappeared.
    """
    from headless_re_mcp.core.application_services import ArtifactApplicationService
    from headless_re_mcp.core.session import SessionNotFound

    class Missing:
        def list_timeline(self, session_id: str, *, offset: int, limit: int) -> dict[str, object]:
            return {"events": [], "count": 0, "total": 0, "exists": False}

    class Quiet:
        def list_timeline(self, session_id: str, *, offset: int, limit: int) -> dict[str, object]:
            return {"events": [], "count": 0, "total": 0}

    absent = ArtifactApplicationService(facade=cast(Any, None), repository=cast(Any, Missing()))
    with pytest.raises(SessionNotFound):
        absent.list_timeline("ghost")

    empty = ArtifactApplicationService(facade=cast(Any, None), repository=cast(Any, Quiet()))
    assert empty.list_timeline("real")["total"] == 0, "an empty log is still an answer"


def test_reading_the_timeline_does_not_collide_with_trimming_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every timeline.list call and every monitor frame is a reader.

    Trimming replaces the whole file, and on Windows a reader holding it open
    makes that replace fail. Measured with four readers and four writers over
    twelve seconds before the readers took the lock: 8,420 appends refused and
    119 reads raised PermissionError at their caller.
    """
    monkeypatch.setattr(timeline_module, "_MAX_BYTES", 4096)
    monkeypatch.setattr(timeline_module, "_TRIM_TO_BYTES", 3072)
    path = tmp_path / "sessions" / "abc" / "timeline.jsonl"
    stop = threading.Event()
    write_failures: list[str] = []
    read_failures: list[str] = []
    reads = [0]

    def writer(worker: int) -> None:
        while not stop.is_set():
            entry = append_session_timeline(path, event="probe", message=f"{worker}:" + "x" * 200)
            if "write_failed" in entry:
                write_failures.append(str(entry["write_failed"]))

    def reader() -> None:
        while not stop.is_set():
            try:
                page = list_session_timeline(path, limit=64)
            except BaseException as exc:  # noqa: BLE001 - the point of the test
                read_failures.append(f"raised {type(exc).__name__}: {exc}")
                continue
            reads[0] += 1
            if "read_failed" in page:
                read_failures.append(str(page["read_failed"]))

    # Daemon threads plus an aliveness check: a worker wedged on a Windows
    # sharing violation would otherwise outlive its timed join silently and
    # then hang interpreter shutdown after the suite has passed -- the one
    # phase no per-test watchdog covers.
    threads = [threading.Thread(target=writer, args=(i,), daemon=True) for i in range(3)]
    threads += [threading.Thread(target=reader, daemon=True) for _ in range(3)]
    for thread in threads:
        thread.start()
    time.sleep(3)
    stop.set()
    for thread in threads:
        thread.join(timeout=30)

    assert not any(thread.is_alive() for thread in threads), "a timeline worker wedged"
    assert reads[0] > 0, "the readers must actually have run"
    assert not write_failures, f"{len(write_failures)} appends lost, first: {write_failures[0]}"
    assert not read_failures, f"{len(read_failures)} reads failed, first: {read_failures[0]}"


def test_appends_that_trim_at_the_same_time_do_not_fail_each_other(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Trimming rewrites the file, and nothing serialises two appends.

    Sharing one scratch path means the second writer replaces a file the first
    still holds open, which on Windows is a sharing violation. A session long
    enough to reach the cap is exactly the unattended one.
    """
    monkeypatch.setattr(timeline_module, "_MAX_BYTES", 4096)
    monkeypatch.setattr(timeline_module, "_TRIM_TO_BYTES", 3072)
    path = tmp_path / "sessions" / "abc" / "timeline.jsonl"
    failures: list[str] = []
    start = threading.Barrier(6)

    def hammer(worker: int) -> None:
        start.wait()
        for index in range(80):
            entry = append_session_timeline(
                path,
                event="probe",
                message=f"{worker}:{index}" + "x" * 200,
            )
            if "write_failed" in entry:
                failures.append(str(entry["write_failed"]))

    threads = [
        threading.Thread(target=hammer, args=(i,), name=f"tl-{i}", daemon=True) for i in range(6)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)

    assert not any(thread.is_alive() for thread in threads), "an append worker wedged"
    assert not failures, f"{len(failures)} appends failed, first: {failures[0]}"
    assert path.stat().st_size <= 4096 + 4096, "the cap must still hold under contention"
    listed = list_session_timeline(path, limit=256)
    assert listed["total"] > 0, "the log must still be readable"
    strays = [item.name for item in path.parent.iterdir() if item.name != path.name]
    assert strays == [], f"trimming left scratch files behind: {strays}"


def test_closing_a_session_that_is_not_there_does_not_invent_one(tmp_path: Path) -> None:
    """session.close on an unknown id used to create the session it could not find.

    Measured: the close wrote sessions/<id>/timeline.jsonl and a failed sqlite
    row, timeline.list then answered ok with one "close failed" event, and
    sessions.unclean offered the ghost as leftover work. Closing an evicted
    real session afterwards blanked its binary and marked it unclean.
    """
    from dataclasses import replace

    from headless_re_mcp.config import Settings
    from headless_re_mcp.core.models import Result, RpcError
    from headless_re_mcp.core.repository import SqliteAnalysisRepository
    from headless_re_mcp.core.service import AnalysisService

    repository = SqliteAnalysisRepository(tmp_path / "repo")
    ghost = "deadbeefdeadbeefdeadbeefdeadbeef"
    repository.note_session_closed(
        ghost,
        None,
        Result(ok=False, error=RpcError(code="session_not_found", message="session not found")),
    )

    page = repository.list_timeline(ghost)
    assert page.get("exists") is False
    assert repository.list_unclean_sessions() == ([], 0)
    assert repository.store.get_session(ghost) is None
    assert not (tmp_path / "repo" / "sessions" / ghost).exists()

    pe = tmp_path / "f.exe"
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = (0x8664).to_bytes(2, "little")
    pe.write_bytes(image)

    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    try:
        missing = "cafebabecafebabecafebabecafebabe"
        closed = service.close_session(missing)
        assert closed.ok is False
        assert closed.error is not None
        assert closed.error.code == "session_not_found"
        listed = service.timeline_list(missing)
        assert listed.ok is False
        assert listed.error is not None
        assert listed.error.code == "session_not_found"
        unclean = service.sessions_unclean()
        assert unclean.data is not None
        assert unclean.data["total"] == 0
        assert not (tmp_path / "artifacts" / "sessions" / missing).exists()

        created = service.create_session(str(pe))
        assert created.data is not None
        session_id = str(created.data["session"]["id"])
        row_before = service.repository.store.get_session(session_id)
        assert row_before is not None
        assert service.close_session(session_id).ok
        service.registry.remove_closed(session_id)
        again = service.close_session(session_id)
        assert again.ok is False
        assert again.error is not None
        assert again.error.code == "session_not_found"
        row_after = service.repository.store.get_session(session_id)
        assert row_after is not None
        assert row_after["binary"] == row_before["binary"]
        assert row_after["closed_cleanly"] == 1
        assert row_after["state"] == "closed"
    finally:
        service.close_all()
