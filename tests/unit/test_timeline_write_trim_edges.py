"""Edge coverage for the timeline append/trim write path.

``test_timeline_store.py`` and ``test_timeline_under_load.py`` cover the common
append, the byte cap and the read path. These pin three write-side arcs the
wider suite does not reach: the fallback when even the truncated entry will not
fit the byte cap, a trim whose surviving tail fits entirely (the loop exits
without breaking), and the atomic-replace cleanup that removes the partial and
re-raises when the rename fails. A separate file keeps this off the
concurrently edited ``test_timeline_store.py``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import headless_re_mcp.core.store.timeline as timeline
from headless_re_mcp.core.store.timeline import (
    _dropped_sidecar,
    _read_dropped,
    _trim_timeline,
    append_session_timeline,
    list_session_timeline,
)


def test_append_reports_write_failure_when_even_a_truncated_entry_is_too_big(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Shrink the byte cap below the size of the truncated fallback entry itself,
    # so the second length check fails and append reports the failure rather
    # than writing an entry that would blow the cap on its own.
    monkeypatch.setattr(timeline, "_MAX_BYTES", 10)
    path = tmp_path / "timeline.jsonl"

    entry = append_session_timeline(
        path, event="dump.finished", message="x" * 200, details={"k": "v" * 50}
    )

    assert entry["event"] == "timeline.entry.truncated"
    assert "too small" in entry["write_failed"]
    # Nothing is written when the entry cannot be made to fit.
    assert not path.exists()


def test_trim_keeps_a_tail_that_fits_entirely(tmp_path: Path) -> None:
    path = tmp_path / "timeline.jsonl"
    lines = [b'{"n": 1}\n', b'{"n": 2}\n', b'{"n": 3}\n']
    path.write_bytes(b"".join(lines))

    # A generous budget and a tiny file: every line fits, so the loop runs to
    # completion instead of breaking on the budget or the line ceiling.
    new_size = _trim_timeline(path, reserve=0)

    assert new_size == sum(len(line) for line in lines)
    assert path.read_bytes() == b"".join(lines)
    # A trim that dropped nothing must leave no counter behind: dropped_total
    # stays zero and no sidecar is created.
    assert not _dropped_sidecar(path).exists()
    assert _read_dropped(path) == 0


def test_trim_records_dropped_entries_and_the_list_reports_them(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The count trimming removed is the count the reader gets back.

    total is only what the file still holds, so on its own it cannot say a
    session ever had more. The cumulative dropped_total is how a reader tells a
    capped log from a complete one, and it survives across successive trims.
    """
    monkeypatch.setattr(timeline, "_TRIM_TO_BYTES", 25)
    path = tmp_path / "timeline.jsonl"
    # Five 8-byte lines. A 25-byte budget keeps the newest three (24 bytes); the
    # fourth would reach 32, so two of the five fall off.
    path.write_bytes(b'{"n":1}\n{"n":2}\n{"n":3}\n{"n":4}\n{"n":5}\n')

    _trim_timeline(path, reserve=0)

    assert _read_dropped(path) == 2
    listed = list_session_timeline(path)
    assert listed["total"] == 3
    assert listed["dropped_total"] == 2
    assert [event["n"] for event in listed["events"]] == [3, 4, 5]

    # Trimming again with everything already fitting drops nothing more: the
    # cumulative count holds rather than double-counting a no-op trim.
    _trim_timeline(path, reserve=0)
    assert _read_dropped(path) == 2

    # New marks arrive and push the window again; the counter accumulates.
    path.write_bytes(path.read_bytes() + b'{"n":6}\n{"n":7}\n')
    _trim_timeline(path, reserve=0)
    assert _read_dropped(path) == 4
    assert list_session_timeline(path)["dropped_total"] == 4


def test_trim_cleans_up_the_partial_and_reraises_when_replace_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "timeline.jsonl"
    path.write_bytes(b'{"n": 1}\n{"n": 2}\n')

    real_replace = Path.replace
    captured: dict[str, Path] = {}

    def _boom(self: Path, target: object) -> Path:
        # Record the partial the trim created, then fail the atomic rename the
        # way a cross-device or permission error would.
        captured["partial"] = self
        raise OSError("rename refused")

    monkeypatch.setattr(Path, "replace", _boom)

    with pytest.raises(OSError, match="rename refused"):
        _trim_timeline(path, reserve=0)

    monkeypatch.setattr(Path, "replace", real_replace)
    partial = captured["partial"]
    assert not partial.exists(), "the failed trim must not leave its .partial behind"
    # The original file is untouched: a failed trim raises rather than losing it.
    assert path.read_bytes() == b'{"n": 1}\n{"n": 2}\n'
