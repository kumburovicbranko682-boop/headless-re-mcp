"""Timeline store: symlink escapes, cap pathologies, and trim/read failures."""

from __future__ import annotations

from pathlib import Path
from typing import NoReturn

import pytest

from headless_re_mcp.core.store import timeline
from headless_re_mcp.core.store.timeline import (
    append_session_timeline,
    list_session_timeline,
    session_timeline_path,
)


def _sessions_root(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "artifacts"
    sessions = root / "sessions"
    sessions.mkdir(parents=True)
    return root, sessions


def test_a_session_id_symlinked_out_of_the_root_is_rejected(tmp_path: Path) -> None:
    # The lexical check on the id itself passes ("evil" is a plain name), but a
    # planted symlink makes the resolved path land outside the sessions root.
    # resolve() follows it, so the containment check is what stands in the way
    # of writing a "timeline" into an arbitrary directory.
    root, sessions = _sessions_root(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (sessions / "evil").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="invalid session id"):
        session_timeline_path(root, "evil")


def test_a_symlink_that_stays_inside_but_changes_depth_is_rejected(
    tmp_path: Path,
) -> None:
    # A link to a deeper directory inside the root passes the containment
    # check, but the file would no longer sit at sessions/<id>/timeline.jsonl.
    # That shape is what pruning and listing walk, so a nested landing spot is
    # refused rather than silently misfiled under another session's tree.
    root, sessions = _sessions_root(tmp_path)
    (sessions / "a" / "b").mkdir(parents=True)
    (sessions / "nest").symlink_to(sessions / "a" / "b", target_is_directory=True)

    with pytest.raises(ValueError, match="escaped the sessions directory"):
        session_timeline_path(root, "nest")


def test_a_cap_too_small_for_the_truncation_notice_reports_not_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # When the oversize notice itself cannot fit the cap there is nothing left
    # to persist; the entry must come back marked failed with no file created,
    # rather than looping or writing a notice that violates the cap.
    monkeypatch.setattr(timeline, "_MAX_BYTES", 10)
    path = tmp_path / "timeline.jsonl"

    entry = append_session_timeline(path, event="dump.write", message="hello world")

    assert entry["event"] == "timeline.entry.truncated"
    assert entry["write_failed"] == "ValueError: timeline persistence limit is too small"
    assert not path.exists()


def test_a_tail_with_no_complete_line_trims_to_empty_and_appends(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # One giant line filling the whole window means no entry boundary survives
    # the seek: everything before the cut is discarded as a torn line and the
    # keep-loop has nothing to walk. The rewrite must still happen (an empty
    # file) so the new entry lands under the cap instead of on top of it.
    monkeypatch.setattr(timeline, "_MAX_BYTES", 150)
    path = tmp_path / "timeline.jsonl"
    path.write_bytes(b"x" * 299 + b"\n")

    entry = append_session_timeline(path, event="e", message="m")

    assert "write_failed" not in entry
    lines = path.read_bytes().splitlines()
    assert len(lines) == 1
    assert b'"event": "e"' in lines[0]


def test_a_failed_trim_rewrite_cleans_its_partial_and_reports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The rewrite goes through a uniquely named partial file swapped into
    # place. If the swap fails (full disk, Windows sharing violation), the
    # partial must not be left behind, the original must survive untouched,
    # and the append reports the failure instead of raising it.
    monkeypatch.setattr(timeline, "_MAX_BYTES", 150)
    path = tmp_path / "timeline.jsonl"
    original = b"x" * 299 + b"\n"
    path.write_bytes(original)

    def refuse(self: Path, target: str | Path) -> Path:
        raise OSError("no space left on device")

    monkeypatch.setattr(Path, "replace", refuse)

    entry = append_session_timeline(path, event="e", message="m")

    assert str(entry["write_failed"]).startswith("OSError")
    assert path.read_bytes() == original
    assert list(tmp_path.glob("*.partial")) == []


def test_an_unreadable_timeline_reports_the_read_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The file exists but another process holds it (or permissions changed
    # under us). A diagnostic log read must degrade to an empty page carrying
    # the reason, never surface as an internal error to the caller.
    path = tmp_path / "timeline.jsonl"
    path.write_text('{"event": "x"}\n', encoding="utf-8")

    def refuse(self: Path, *args: object, **kwargs: object) -> NoReturn:
        raise OSError("timeline held by another process")

    monkeypatch.setattr(Path, "open", refuse)

    page = list_session_timeline(path)

    assert page["events"] == []
    assert str(page["read_failed"]).startswith("OSError")
    assert page["path"] == str(path)
