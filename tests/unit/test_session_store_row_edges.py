"""Row-level edge coverage for the sqlite session store.

``test_knowledge_store.py`` and ``test_timeline_under_load.py`` cover the write
APIs, retention trims and the traversal guards. These pin the row shapes the
wider suite does not produce: an update that must not touch the close flag, the
non-meta-root guard on closed-session file cleanup, the debug-events directory
sweep, the list readers tolerating non-string column values written outside
the API (TEXT affinity converts numbers to text, but a BLOB is stored as-is
even in a TEXT NOT NULL column) instead of crashing every later listing, and
garbage collection dropping a row whose payload already vanished from disk.
"""

from __future__ import annotations

import sqlite3
import time
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


def test_hostile_influenced_text_with_a_lone_surrogate_still_makes_rows(
    tmp_path: Path,
) -> None:
    """json.loads accepts a lone \\ud800 escape and NTFS filenames are arbitrary
    UTF-16, so a hostile sample's path, an audit summary of tool params or
    results, and a finding quoting the binary's strings can all carry an
    unpaired surrogate. SQLite's TEXT bind raises UnicodeEncodeError on one:
    opening a session for such a file -- which Python opens and hashes fine --
    died as an incident-labelled codec error, and an audit or knowledge write
    did the same after the operation it was recording had already succeeded.
    Same replace policy as the transport's byte decode: lossy but alive.
    """
    store = _store(tmp_path)
    session_id = uuid.uuid4().hex

    _upsert(store, session_id, binary="C:/mal\ud800ware.exe")
    row = store.get_session(session_id)
    assert row is not None
    assert "\ud800" not in row["binary"]
    assert "ware.exe" in row["binary"]

    # The update branch binds the same column.
    _upsert(store, session_id, binary="C:/re\ud800named.exe", state="ready")
    row = store.get_session(session_id)
    assert row is not None and "\ud800" not in row["binary"]

    store.append_audit(
        session_id=session_id,
        action="strings.read",
        params_summary={"needle": "mal\ud800"},
        ok=True,
        result_summary={"matched": "yes\ud800"},
    )
    entry = store.list_audit(session_id)["entries"][0]
    assert "\ud800" not in str(entry["params_summary"])
    assert "\ud800" not in str(entry["result_summary"])

    store.record_knowledge(
        session_id=session_id,
        kind="stri\ud800ng",
        key="quote\ud800",
        value={"text": "from the binary \ud800"},
    )
    fact = store.list_knowledge(session_id)["entries"][0]
    assert "\ud800" not in str(fact)


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


def test_gc_drops_the_row_of_an_artifact_already_gone_from_disk(tmp_path: Path) -> None:
    # A payload deleted outside the store (an operator freeing space by hand, a
    # crashed copy) leaves a row that points at nothing. GC must drop that row
    # and stop counting its bytes against the budget, not skip it forever.
    store = _store(tmp_path)
    session_id = uuid.uuid4().hex
    ghost = store.register_artifact(
        session_id=session_id,
        kind="dump",
        path=tmp_path / "dumps" / "gone.bin",
        sha256="ab" * 32,
        source="test",
        size=600,
    )
    # created_at is the collection order; a distinct timestamp keeps the real
    # file strictly newest so the never-collect-the-newest rule protects it.
    time.sleep(0.002)
    keep_path = tmp_path / "dumps" / "keep.bin"
    keep_path.parent.mkdir(parents=True, exist_ok=True)
    keep_path.write_bytes(b"\0" * 500)
    keep = store.register_artifact(
        session_id=session_id,
        kind="dump",
        path=keep_path,
        sha256="cd" * 32,
        source="test",
    )

    result = store.gc_artifacts(max_total_bytes=100)

    assert result["removed"] == [ghost["id"]]
    assert result["skipped"] == []
    assert result["invalid_paths"] == []
    # Only the surviving newest artifact still counts against the budget.
    assert result["bytes_remaining_estimate"] == 500
    assert keep_path.is_file(), "the newest artifact is never collected"
    listing = store.list_artifacts(session_id)
    assert [item["id"] for item in listing["artifacts"]] == [keep["id"]]


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
