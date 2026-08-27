"""Reachable edges of the shared SQLite persistence layer.

Every track -- PE, APK, web -- creates sessions, registers backends and
artifacts, and stores knowledge and audit rows through this one store, so its
guards and degradation paths are load-bearing for all of them. This file drives
the branches the happy-path suites leave: an in-place session update that must
not clobber the clean-close flag, the closed-session file cleanup that only runs
under a ``meta`` layout, the all-sessions listings, tolerance of a corrupt
non-string summary or value, and the artifact collector's refusal of a bad
budget and its handling of a row whose file is already gone.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from headless_re_mcp.core.store.sqlite_store import SessionStore


def _store(tmp_path: Path) -> SessionStore:
    """A store laid out as the service builds it: <root>/meta/store.db."""
    return SessionStore(tmp_path / "meta" / "store.db")


# --------------------------------------------------------------------------- #
# upsert_session: an update must not clobber the clean-close flag             #
# --------------------------------------------------------------------------- #
def test_updating_a_session_without_a_clean_flag_leaves_it_untouched(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    sid = "a" * 32
    store.upsert_session(
        session_id=sid, binary="/b.exe", sha256="s", architecture="x64", state="ready"
    )
    # A later state change that says nothing about clean-close must keep the
    # existing flag and only move the state.
    store.upsert_session(
        session_id=sid, binary="/b.exe", sha256="s", architecture="x64", state="closing"
    )
    row = store.get_session(sid)
    assert row is not None
    assert row["state"] == "closing"
    assert row["closed_cleanly"] == 0


# --------------------------------------------------------------------------- #
# _forget_closed_session_files                                                #
# --------------------------------------------------------------------------- #
def test_closed_session_cleanup_is_a_noop_outside_a_meta_layout(
    tmp_path: Path,
) -> None:
    # A store whose database does not live under a ``meta`` directory cannot
    # know where the artifact root is, so cleanup refuses to guess.
    store = SessionStore(tmp_path / "store.db")
    store._forget_closed_session_files("b" * 32)  # returns without touching disk


def test_closed_session_cleanup_removes_the_timeline_and_event_dir(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    root = tmp_path
    sid = "c" * 32
    timeline = root / "sessions" / sid / "timeline.jsonl"
    timeline.parent.mkdir(parents=True)
    timeline.write_text("{}\n", encoding="utf-8")
    events = root / "debug-events" / sid
    events.mkdir(parents=True)
    (events / "0001.json").write_text("{}", encoding="utf-8")

    store._forget_closed_session_files(sid)

    assert not timeline.exists()
    assert not events.exists()
    # The emptied per-session timeline directory is pruned as well.
    assert not timeline.parent.exists()


# --------------------------------------------------------------------------- #
# list_backends across every session                                         #
# --------------------------------------------------------------------------- #
def test_listing_backends_with_no_session_returns_them_all(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.upsert_backend(session_id="s1", kind="web", worker_id="w1")
    store.upsert_backend(session_id="s2", kind="frida", worker_id="w2")
    everything = store.list_backends()
    pairs = {(row["session_id"], row["kind"]) for row in everything}
    assert pairs == {("s1", "web"), ("s2", "frida")}


# --------------------------------------------------------------------------- #
# corrupt rows are tolerated, not fatal                                       #
# --------------------------------------------------------------------------- #
def test_listing_audit_tolerates_a_non_string_summary(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.append_audit(
        session_id="s1",
        action="web.open",
        params_summary={"url": "http://x/"},
        ok=True,
        result_summary={"opened": True},
    )
    # Simulate a legacy/corrupt row whose summary is stored as an opaque blob
    # rather than a JSON string; the reader must return the row, not raise.
    with sqlite3.connect(store.db_path) as conn:
        conn.execute("UPDATE audit SET params_summary=?", (sqlite3.Binary(b"raw"),))
        conn.commit()
    listed = store.list_audit()
    assert listed["count"] == 1
    assert listed["entries"][0]["params_summary"] == b"raw"


def test_listing_knowledge_tolerates_a_non_string_value(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.record_knowledge(session_id="s1", kind="finding", key="k", value={"v": 1})
    with sqlite3.connect(store.db_path) as conn:
        conn.execute("UPDATE knowledge SET value=?", (sqlite3.Binary(b"raw"),))
        conn.commit()
    listed = store.list_knowledge("s1")
    assert listed["count"] == 1
    assert listed["entries"][0]["value"] == b"raw"


# --------------------------------------------------------------------------- #
# gc_artifacts                                                                #
# --------------------------------------------------------------------------- #
def test_gc_refuses_a_non_positive_budget(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with pytest.raises(ValueError, match="positive integer"):
        store.gc_artifacts(max_total_bytes=0)


def test_gc_drops_the_row_when_its_file_is_already_gone(tmp_path: Path) -> None:
    store = _store(tmp_path)
    root = tmp_path
    blobs = root / "blobs"
    blobs.mkdir()
    old = blobs / "old.bin"
    old.write_bytes(b"x" * 100)
    new = blobs / "new.bin"
    new.write_bytes(b"y" * 100)
    first = store.register_artifact(
        session_id="s1", kind="dump", path=old, sha256="a", source="test"
    )
    store.register_artifact(
        session_id="s1", kind="dump", path=new, sha256="b", source="test"
    )
    # The oldest artifact's file vanishes before collection reaches it; its row
    # is still dropped so it stops counting against the budget.
    old.unlink()

    result = store.gc_artifacts(max_total_bytes=50)

    assert first["id"] in result["removed"]
    assert store.describe_artifact(first["id"]) is None
    # The newest artifact is never collected, even under a tight budget.
    assert new.exists()
