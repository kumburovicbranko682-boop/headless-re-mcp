from __future__ import annotations

import json
from pathlib import Path

import pytest

from headless_re_mcp.core.store import timeline as store


@pytest.fixture
def small_caps(monkeypatch: pytest.MonkeyPatch) -> None:
    """Shrink the quotas so trimming is reachable, keeping the real headroom ratio."""
    monkeypatch.setattr(store, "_MAX_BYTES", 20_000)
    monkeypatch.setattr(store, "_TRIM_TO_BYTES", 12_000)


def _append(path: Path, index: int) -> None:
    store.append_session_timeline(
        path,
        event=f"e{index:04d}",
        message="m",
        details={"note": "x" * 200},
    )


def test_appending_does_not_read_the_whole_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The whole file used to be read and rewritten per entry.

    That made each append cost the size of the log, and every tool call writes
    one: 4000 appends onto a 2 MB timeline took nine seconds, the last thousand
    of those taking three. Counting reads rather than watching for the temporary
    file, because the rewrite renames it away before the next assertion runs.
    """
    path = tmp_path / "timeline.jsonl"
    reads: list[Path] = []
    original = Path.read_bytes

    def counting_read_bytes(self: Path) -> bytes:
        reads.append(self)
        return original(self)

    monkeypatch.setattr(Path, "read_bytes", counting_read_bytes)
    for index in range(50):
        _append(path, index)

    # Scoped to the timeline file on purpose: the patch is on Path itself, so an
    # unrelated background thread reading any file would otherwise fail a test
    # that is only making a claim about how this log is appended to.
    assert [item for item in reads if item == path] == []
    entries = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert [item["event"] for item in entries] == [f"e{index:04d}" for index in range(50)]


def test_the_cap_holds_without_rewriting_on_every_append(
    tmp_path: Path,
    small_caps: None,
) -> None:
    path = tmp_path / "timeline.jsonl"
    peak = 0
    previous = 0
    rewrites = 0
    for index in range(200):
        _append(path, index)
        size = path.stat().st_size
        if size < previous:
            rewrites += 1
        previous = size
        peak = max(peak, size)

    assert peak <= store._MAX_BYTES
    # Cutting back to a low-water mark buys many appends per rewrite. Without
    # that headroom every append past the cap would rewrite the whole file.
    assert rewrites < 200 // 10


def test_trimming_keeps_the_newest_entries_and_leaves_valid_jsonl(
    tmp_path: Path,
    small_caps: None,
) -> None:
    path = tmp_path / "timeline.jsonl"
    for index in range(200):
        _append(path, index)

    lines = path.read_text(encoding="utf-8").splitlines()
    entries = [json.loads(line) for line in lines]
    assert len(entries) == len(lines)
    assert entries[-1]["event"] == "e0199"
    # Contiguous newest window: trimming drops from the front, never the middle.
    events = [item["event"] for item in entries]
    assert events == sorted(events)
    assert int(events[0][1:]) + len(events) - 1 == 199


def test_a_torn_final_line_does_not_corrupt_the_next_append(tmp_path: Path) -> None:
    """Appending gives up whole-file atomicity, so a torn line must stay local.

    Without the newline guard the next entry would be glued onto the broken one
    and take a second line down with it.
    """
    path = tmp_path / "timeline.jsonl"
    _append(path, 0)
    with path.open("ab") as stream:
        stream.write(b'{"at": "truncated"')

    _append(path, 1)

    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3
    assert json.loads(lines[0])["event"] == "e0000"
    with pytest.raises(json.JSONDecodeError):
        json.loads(lines[1])
    assert json.loads(lines[2])["event"] == "e0001"
    # The reader already skips what will not parse.
    listed = store.list_session_timeline(path)
    assert [item["event"] for item in listed["events"]] == ["e0000", "e0001"]
    assert listed["skipped"] == 1
    assert listed["has_more"] is False


def test_skipped_lines_do_not_invent_another_page(tmp_path: Path) -> None:
    """5 lines, 2 corrupt: count=3, total=5, has_more=True after the whole file."""
    path = tmp_path / "timeline.jsonl"
    path.write_text(
        '{"event":"a"}\nnot-json\n{"event":"b"}\n{bad\n{"event":"c"}\n',
        encoding="utf-8",
    )
    page = store.list_session_timeline(path, offset=0, limit=100)
    assert [item["event"] for item in page["events"]] == ["a", "b", "c"]
    assert page["count"] == 3
    assert page["total"] == 5
    assert page["skipped"] == 2
    assert page["has_more"] is False