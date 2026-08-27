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


@pytest.mark.parametrize("hostile", ["../../outside", "..", "/etc/passwd", "../sibling"])
def test_a_traversing_session_id_cannot_escape_the_sessions_root(
    tmp_path: Path, hostile: str
) -> None:
    """A session id is a uuid; a client-supplied ``..`` must not leave the root.

    Once any session exists the ``sessions`` directory exists too, so before
    the guard ``session_timeline_path(root, "../../x")`` resolved to a real
    ``timeline.jsonl`` outside the artifact root -- read by timeline.list and
    unlinked by closed-session cleanup. Fail closed on the escape, but still
    allow a plain uuid and an in-root nested id (which never leaves the root).
    """
    root = tmp_path / "artifacts"
    (root / "sessions").mkdir(parents=True)
    with pytest.raises(ValueError, match="invalid session id"):
        store.session_timeline_path(root, hostile)

    ok = store.session_timeline_path(root, "deadbeef" * 4)
    assert ok.relative_to((root / "sessions").resolve())
    assert ok.name == "timeline.jsonl"


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


def test_a_torn_line_in_the_page_is_reported_as_skipped(tmp_path: Path) -> None:
    """A dropped torn entry is disclosed, not silently absorbed into the page.

    The reader drops a line that will not parse, so on a settled page (has_more
    false) count comes back less than total with nothing to explain the gap --
    which reads as a paging quirk. skipped names it: an entry was unreadable and
    dropped, so a lost mark is not mistaken for a mark that was never made.
    """
    path = tmp_path / "timeline.jsonl"
    _append(path, 0)
    with path.open("ab") as stream:
        stream.write(b'{"at": "truncated"\n')
    _append(path, 1)

    listed = store.list_session_timeline(path)

    assert [item["event"] for item in listed["events"]] == ["e0000", "e0001"]
    assert listed["count"] == 2
    assert listed["total"] == 3
    assert listed["has_more"] is False
    assert listed["skipped"] == 1


def test_a_clean_page_reports_no_skipped_key(tmp_path: Path) -> None:
    """A page with nothing dropped stays clean: no skipped field at all."""
    path = tmp_path / "timeline.jsonl"
    for index in range(3):
        _append(path, index)

    listed = store.list_session_timeline(path)

    assert listed["count"] == 3
    assert listed["total"] == 3
    assert "skipped" not in listed


def test_an_oversized_external_timeline_is_rejected_after_a_bounded_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(store, "_MAX_BYTES", 64)
    path = tmp_path / "timeline.jsonl"
    path.write_bytes(b'{"event":"external"}\n' * 100)

    listed = store.list_session_timeline(path)

    assert listed["events"] == []
    assert listed["read_failed"] == "timeline exceeds 64 bytes"


def test_trimming_an_oversized_external_timeline_reads_only_its_tail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(store, "_MAX_BYTES", 1024)
    monkeypatch.setattr(store, "_TRIM_TO_BYTES", 640)
    path = tmp_path / "timeline.jsonl"
    path.write_bytes(
        b"".join(
            json.dumps({"event": f"external-{index}", "message": "x" * 20}).encode()
            + b"\n"
            for index in range(100)
        )
    )

    def unbounded_read_forbidden(_path: Path) -> bytes:
        raise AssertionError("timeline trimming must not call read_bytes()")

    monkeypatch.setattr(Path, "read_bytes", unbounded_read_forbidden)
    _append(path, 999)

    lines = path.read_text(encoding="utf-8").splitlines()
    assert json.loads(lines[-1])["event"] == "e0999"
    assert path.stat().st_size <= store._MAX_BYTES