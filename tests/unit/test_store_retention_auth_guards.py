"""Filesystem-failure guards in the artifact stores and the web token.

``measure_usage`` feeds the health probe and the retention decision, so a walk
that hits the file cap, an unstatable entry, or a directory that vanishes
mid-walk must return a floor marked ``truncated`` rather than stall or raise.
``session_timeline_path`` is the choke point that keeps a client-supplied
session id inside the sessions root -- including ids that pass the name check
but resolve through a symlink -- and ``list_session_timeline`` reports a log it
cannot read instead of failing the tool call that only asked for diagnostics.
The web token writer owns the file it just created with O_EXCL, so a failed
write must remove that empty husk: leaving it makes every later start read a
truncated token and refuse, with nothing left pointing at why.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.core.retention import measure_usage
from headless_re_mcp.core.store.timeline import (
    append_session_timeline,
    list_session_timeline,
    session_timeline_path,
)
from headless_re_mcp.web import auth as web_auth

_POSIX_ONLY = pytest.mark.skipif(
    os.name == "nt", reason="symlink creation needs privileges on Windows (skip != pass)"
)


# ---------------------------------------------------------------------------
# measure_usage: every early exit is a floor marked truncated.
# ---------------------------------------------------------------------------
def test_usage_walk_stops_at_the_file_cap_and_says_so(tmp_path: Path) -> None:
    (tmp_path / "a.bin").write_bytes(b"aa")
    (tmp_path / "b.bin").write_bytes(b"bb")
    usage = measure_usage(tmp_path, file_limit=1)
    assert usage.truncated is True
    assert usage.files == 1
    assert usage.bytes == 2


def test_usage_walk_skips_a_file_it_cannot_stat(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "good.bin").write_bytes(b"good")
    (tmp_path / "bad.bin").write_bytes(b"bad")
    original = Path.stat

    def _stat(self: Path, *, follow_symlinks: bool = True) -> Any:
        if self.name == "bad.bin":
            raise OSError("stat denied")
        return original(self, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(Path, "stat", _stat)
    usage = measure_usage(tmp_path)
    assert usage.truncated is False
    assert usage.files == 1
    assert usage.bytes == 4


def test_usage_walk_keeps_its_partial_total_when_the_walk_itself_dies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    counted = tmp_path / "counted.bin"
    counted.write_bytes(b"12345")

    def _rglob(self: Path, pattern: str) -> Any:
        yield counted
        raise OSError("directory vanished mid-walk")

    monkeypatch.setattr(Path, "rglob", _rglob)
    usage = measure_usage(tmp_path)
    assert usage.truncated is True
    assert usage.files == 1
    assert usage.bytes == 5


# ---------------------------------------------------------------------------
# session_timeline_path: a symlinked session id cannot leave the sessions root.
# ---------------------------------------------------------------------------
@_POSIX_ONLY
def test_a_session_symlinked_outside_the_root_is_rejected(tmp_path: Path) -> None:
    # The id itself looks clean; only resolution reveals the escape. resolve()
    # follows the link, so the containment check is what stands between a
    # planted symlink and reading /timeline.jsonl from anywhere on disk.
    root = tmp_path / "artifacts"
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    sessions = root / "sessions"
    sessions.mkdir(parents=True)
    (sessions / "evil").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="invalid session id"):
        session_timeline_path(root, "evil")


@_POSIX_ONLY
def test_a_session_symlinked_deeper_inside_the_root_is_rejected(tmp_path: Path) -> None:
    # Still inside the sessions root after resolution, but no longer one level
    # deep -- so it would shadow another session's subtree. Rejected too.
    root = tmp_path / "artifacts"
    sessions = root / "sessions"
    nested = sessions / "real" / "deep"
    nested.mkdir(parents=True)
    (sessions / "sneaky").symlink_to(nested, target_is_directory=True)
    with pytest.raises(ValueError, match="escaped the sessions directory"):
        session_timeline_path(root, "sneaky")


# ---------------------------------------------------------------------------
# list_session_timeline: an unreadable log is an answer, not an exception.
# ---------------------------------------------------------------------------
def test_an_unreadable_timeline_reports_read_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "timeline.jsonl"
    append_session_timeline(path, event="probe", message="hello")
    original = Path.open

    def _open(self: Path, *args: Any, **kwargs: Any) -> Any:
        if self == path:
            raise OSError("permission denied")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", _open)
    listing = list_session_timeline(path)
    assert listing["events"] == []
    assert listing["read_failed"].startswith("OSError")
    assert listing["path"] == str(path)


# ---------------------------------------------------------------------------
# load_or_create_web_token: a failed first write leaves no husk behind.
# ---------------------------------------------------------------------------
def test_a_failed_token_write_removes_the_empty_file_and_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    token_path = tmp_path / "web-token.json"

    def _explode(fd: int, payload: bytes) -> None:
        os.close(fd)
        raise OSError("disk full")

    monkeypatch.setattr(web_auth, "_write_token_fd", _explode)
    with pytest.raises(OSError, match="disk full"):
        web_auth.load_or_create_web_token(path=token_path)
    # The O_EXCL create left a zero-byte file; keeping it would make every
    # later start read a truncated token and refuse with no cause in sight.
    assert not token_path.exists()
