"""What the session timeline does when the volume or a sibling thread fights it.

The timeline is a diagnostic log that every tool call writes to. Nothing
serialises those writes and nothing above them treats a failed write as
survivable, so both properties are load bearing for a deployment that runs for
days without anyone reading the output.
"""

from __future__ import annotations

import threading
from pathlib import Path

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
