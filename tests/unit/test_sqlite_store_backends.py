"""Coverage for the backend registry rows of the session store.

The session-filtered ``list_backends(session_id)`` path is exercised by the
wider suite, but the unfiltered ``list_backends()`` -- the cross-session view a
diagnostic or reaper uses to see every live backend at once -- was not. Pin its
ordering contract alongside the upsert-in-place behaviour so a future change to
either query is caught. Also pins the ``gc_artifacts`` budget guard, which must
refuse a non-positive budget before it ever opens the database.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.core.store.sqlite_store import SessionStore


def test_list_backends_without_a_session_returns_every_row_ordered(tmp_path: Path) -> None:
    store = SessionStore(tmp_path / "store.db")
    store.upsert_backend(session_id="sess-b", kind="ida")
    store.upsert_backend(session_id="sess-a", kind="x64dbg", pid=1234, endpoint="tcp://x")
    store.upsert_backend(session_id="sess-a", kind="ida")

    everything = store.list_backends()

    assert [(row["session_id"], row["kind"]) for row in everything] == [
        ("sess-a", "ida"),
        ("sess-a", "x64dbg"),
        ("sess-b", "ida"),
    ]


def test_list_backends_for_one_session_is_scoped_and_kind_ordered(tmp_path: Path) -> None:
    store = SessionStore(tmp_path / "store.db")
    store.upsert_backend(session_id="sess-a", kind="x64dbg")
    store.upsert_backend(session_id="sess-a", kind="ida")
    store.upsert_backend(session_id="sess-b", kind="ida")

    scoped = store.list_backends("sess-a")

    assert [row["kind"] for row in scoped] == ["ida", "x64dbg"]
    assert all(row["session_id"] == "sess-a" for row in scoped)


def test_upsert_backend_replaces_the_row_for_the_same_session_and_kind(
    tmp_path: Path,
) -> None:
    store = SessionStore(tmp_path / "store.db")
    store.upsert_backend(session_id="sess-a", kind="ida", pid=1, endpoint="first")
    store.upsert_backend(session_id="sess-a", kind="ida", pid=2, endpoint="second")

    rows = store.list_backends("sess-a")

    assert len(rows) == 1, "the same (session, kind) must update in place, not duplicate"
    assert rows[0]["pid"] == 2
    assert rows[0]["endpoint"] == "second"


@pytest.mark.parametrize("bad", [0, -1, 1.5, "100"])
def test_gc_artifacts_refuses_a_non_positive_integer_budget(
    tmp_path: Path, bad: object
) -> None:
    """A zero, negative, float, or string budget is a caller error, not a sweep.

    The guard runs before the connection opens, so a bad budget can never delete
    rows on the strength of a value that was never a positive byte count.
    """
    store = SessionStore(tmp_path / "store.db")

    with pytest.raises(ValueError, match="max_total_bytes must be a positive integer"):
        store.gc_artifacts(max_total_bytes=bad)  # type: ignore[arg-type]
