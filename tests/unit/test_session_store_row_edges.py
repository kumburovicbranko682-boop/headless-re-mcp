"""Row-level edge coverage for the sqlite session store.

``test_knowledge_store.py`` and ``test_timeline_under_load.py`` cover the write
APIs, retention trims and the traversal guards. These pin the row shapes the
wider suite does not produce: an update that must not touch the close flag, the
non-meta-root guard on closed-session file cleanup, the debug-events directory
sweep, and the list readers tolerating non-string column values written outside
the API (TEXT affinity converts numbers to text, but a BLOB is stored as-is
even in a TEXT NOT NULL column) instead of crashing every later listing.
"""

from __future__ import annotations

import sqlite3
import uuid
from pathlib import Path

from headless_re_mcp.core.store.sqlite_store import SessionStore


def _store(tmp_path: Path) -> SessionStore:
    return SessionStore(tmp_path / "meta" / "analysis.db")


def _upsert(store: SessionStore, session_id: str, **overrides: object) -> None:
    fields: dict[str, object] = {
        "binary": "C:/app.exe",
        "sha256": "ab" * 32,
        "architecture": "x64",
        "state": "ready",
    }
    fields.update(overrides)
    store.upsert_session(session_id=session_id, **fields)  # type: ignore[arg-type]


def test_updating_a_session_without_a_close_flag_preserves_it(tmp_path: Path) -> None:
    store = _store(tmp_path)
    session_id = uuid.uuid4().hex
    _upsert(store, session_id, state="closed", closed_cleanly=True)

    # A later update that says nothing about closing must not flip the flag.
    _upsert(store, session_id, state="ready", binary="C:/other.exe")

    row = store.get_session(session_id)
    assert row is not None
    assert row["state"] == "ready"
    assert row["binary"] == "C:/other.exe"
    assert row["closed_cleanly"] == 1


def test_forget_files_is_inert_outside_a_meta_root(tmp_path: Path) -> None:
    # The database was placed somewhere that is not an artifact root's meta/
    # directory, so the store cannot know what its siblings are; cleanup must
    # refuse to delete anything rather than guess.
    store = SessionStore(tmp_path / "elsewhere" / "analysis.db")
    session_id = uuid.uuid4().hex
    events = tmp_path / "debug-events" / session_id
    events.mkdir(parents=True)
    (events / "ring.bin").write_bytes(b"\0")

    store._forget_closed_session_files(session_id)

    assert (events / "ring.bin").is_file(), "a non-meta root must never be swept"


def test_forget_files_removes_the_timeline_and_debug_events(tmp_path: Path) -> None:
    store = _store(tmp_path)
    session_id = uuid.uuid4().hex
    timeline = tmp_path / "sessions" / session_id / "timeline.jsonl"
    timeline.parent.mkdir(parents=True)
    timeline.write_text("{}\n", encoding="utf-8")
    events = tmp_path / "debug-events" / session_id
    events.mkdir(parents=True)
    (events / "ring.bin").write_bytes(b"\0")

    store._forget_closed_session_files(session_id)

    assert not timeline.exists()
    assert not timeline.parent.exists(), "the emptied session directory is pruned"
    assert not events.exists(), "the session's debug-events directory is swept"


def test_list_audit_tolerates_a_row_with_non_string_summaries(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with sqlite3.connect(store.db_path) as conn:
        # TEXT affinity converts numbers to text on storage, but a BLOB is
        # stored as-is even in a TEXT NOT NULL column; a row a foreign writer
        # left this way must not crash every later listing.
        conn.execute(
            "INSERT INTO audit(id,session_id,at,action,params_summary,ok,result_summary)"
            " VALUES(?,?,?,?,?,1,?)",
            (
                uuid.uuid4().hex,
                None,
                "2026-01-01T00:00:00+00:00",
                "legacy.action",
                b"\x07",
                b"\x08",
            ),
        )

    listing = store.list_audit()

    assert listing["count"] == 1
    entry = listing["entries"][0]
    assert entry["action"] == "legacy.action"
    # Non-string summaries are passed through untouched, not json-parsed.
    assert entry["params_summary"] == b"\x07"
    assert entry["result_summary"] == b"\x08"


def test_list_knowledge_tolerates_a_row_with_a_non_string_value(tmp_path: Path) -> None:
    store = _store(tmp_path)
    session_id = uuid.uuid4().hex
    with sqlite3.connect(store.db_path) as conn:
        conn.execute(
            "INSERT INTO knowledge(session_id,kind,key,value,created_at,updated_at)"
            " VALUES(?,?,?,?,?,?)",
            (
                session_id,
                "note",
                "k",
                b"\x09",
                "2026-01-01T00:00:00+00:00",
                "2026-01-01T00:00:00+00:00",
            ),
        )

    listing = store.list_knowledge(session_id)

    assert listing["count"] == 1
    entry = listing["entries"][0]
    assert entry["kind"] == "note"
    assert entry["value"] == b"\x09"
