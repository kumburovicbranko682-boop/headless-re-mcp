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
from typing import Any

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


# Five ids whose descending sort is neither the insertion order nor its reverse.
# A listing that lands them in _TIE_ID_DESC order can only have sorted by id; a
# reader missing the id tie-breaker falls back to the scan/rowid order, which is
# one of the other two. So asserting _TIE_ID_DESC deterministically separates the
# fixed reader from the buggy one, regardless of which scan the planner picks.
_TIE_INSERT_ORDER = ["c3", "a1", "e5", "b2", "d4"]
_TIE_ID_DESC = ["e5", "d4", "c3", "b2", "a1"]
_SAME_TS = "2026-01-01T00:00:00+00:00"


def _paged_ids(page: Any, key: str, id_of: Any) -> list[str]:
    """Walk a paginated reader two at a time and collect the ids it hands back."""
    seen: list[str] = []
    offset = 0
    while True:
        window = page(offset=offset, limit=2)
        rows = window[key] if isinstance(window, dict) else window[0]
        seen.extend(id_of(row) for row in rows)
        if isinstance(window, dict):
            if not window["has_more"]:
                break
        elif offset + len(rows) >= window[1]:
            break
        offset += 2
    return seen


def test_list_audit_breaks_timestamp_ties_by_id(tmp_path: Path) -> None:
    """Rows sharing an `at` must page in a deterministic id-ordered total.

    append_audit's trim deletes by (at DESC, id DESC) and its comment claims a
    caller reads the same order -- but list_audit ordered by `at` alone, so among
    rows minted in the same microsecond (an easy tie under an ISO clock) the scan
    order decided the result. That order can differ between the OFFSET queries of
    adjacent pages, duplicating a row onto one page and skipping it from the next,
    and it disagreed with what the trim kept. Ordering by (at DESC, id DESC) makes
    the read a stable total and finally matches the trim.
    """
    store = _store(tmp_path)
    with sqlite3.connect(store.db_path) as conn:
        for audit_id in _TIE_INSERT_ORDER:
            conn.execute(
                "INSERT INTO audit(id,session_id,at,action,params_summary,ok,result_summary)"
                " VALUES(?,?,?,?,?,1,?)",
                (audit_id, None, _SAME_TS, "act", "{}", "{}"),
            )

    listing = store.list_audit()
    assert [entry["id"] for entry in listing["entries"]] == _TIE_ID_DESC

    # And paging never duplicates or drops a tied row: the concatenated windows
    # reproduce the same total, in the same order.
    paged = _paged_ids(store.list_audit, "entries", lambda row: row["id"])
    assert paged == _TIE_ID_DESC


def test_list_artifacts_breaks_created_at_ties_by_id(tmp_path: Path) -> None:
    """Artifacts registered in one microsecond must page in an id-ordered total.

    Without the id tie-breaker the scan order among equal created_at rows leaks
    into the page window, so an artifact is duplicated onto one page and skipped
    from the next as the OFFSET advances.
    """
    store = _store(tmp_path)
    session_id = uuid.uuid4().hex
    with sqlite3.connect(store.db_path) as conn:
        for artifact_id in _TIE_INSERT_ORDER:
            conn.execute(
                "INSERT INTO artifacts(id,session_id,kind,path,size,sha256,source,created_at)"
                " VALUES(?,?,?,?,?,?,?,?)",
                (
                    artifact_id,
                    session_id,
                    "dump",
                    f"/tmp/{artifact_id}.bin",
                    0,
                    "ab" * 32,
                    "t",
                    _SAME_TS,
                ),
            )

    listing = store.list_artifacts(session_id)
    assert [item["id"] for item in listing["artifacts"]] == _TIE_ID_DESC

    paged = _paged_ids(
        lambda **kw: store.list_artifacts(session_id, **kw), "artifacts", lambda row: row["id"]
    )
    assert paged == _TIE_ID_DESC


def test_list_unclean_sessions_breaks_updated_at_ties_by_id(tmp_path: Path) -> None:
    """Unclean sessions sharing an updated_at must page in an id-ordered total.

    This reader is what a caller reaches for right after a crash, when many
    sessions can carry the same last-touched instant, so a scan-order-dependent
    page that skips or repeats a session is exactly the wrong time for it.
    """
    store = _store(tmp_path)
    with sqlite3.connect(store.db_path) as conn:
        for session_id in _TIE_INSERT_ORDER:
            conn.execute(
                "INSERT INTO sessions"
                "(id,binary,sha256,architecture,state,created_at,updated_at,closed_cleanly)"
                " VALUES(?,?,?,?,?,?,?,0)",
                (session_id, "C:/app.exe", "ab" * 32, "x64", "ready", _SAME_TS, _SAME_TS),
            )

    rows, total = store.list_unclean_sessions()
    assert total == len(_TIE_ID_DESC)
    assert [row["id"] for row in rows] == _TIE_ID_DESC

    paged = _paged_ids(store.list_unclean_sessions, "", lambda row: row["id"])
    assert paged == _TIE_ID_DESC


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
