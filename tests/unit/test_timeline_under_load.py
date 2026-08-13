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
from headless_re_mcp.core.store.timeline import append_session_timeline, list_session_timeline


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
            entry = append_session_timeline(
                path, event="probe", message=f"{worker}:" + "x" * 200
            )
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

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(3)]
    threads += [threading.Thread(target=reader) for _ in range(3)]
    for thread in threads:
        thread.start()
    time.sleep(3)
    stop.set()
    for thread in threads:
        thread.join(timeout=30)

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

    threads = [threading.Thread(target=hammer, args=(i,), name=f"tl-{i}") for i in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)

    assert not failures, f"{len(failures)} appends failed, first: {failures[0]}"
    assert path.stat().st_size <= 4096 + 4096, "the cap must still hold under contention"
    listed = list_session_timeline(path, limit=256)
    assert listed["total"] > 0, "the log must still be readable"
    strays = [item.name for item in path.parent.iterdir() if item.name != path.name]
    assert strays == [], f"trimming left scratch files behind: {strays}"
