"""SessionStore edges: unfiltered backend listing, GC budget guard, ghost rows.

These exercise the SQLite store directly rather than through the repository
wrapper, because the wrapper re-validates the GC budget before delegating and
would hide the store's own guard.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.core.store.sqlite_store import SessionStore


def _store(tmp_path: Path) -> SessionStore:
    # The artifact root is the grandparent of the database file; files placed
    # directly under it (outside meta/) are collectable payloads.
    return SessionStore(tmp_path / "root" / "meta" / "sessions.db")


def test_listing_backends_without_a_session_filter_returns_every_row(
    tmp_path: Path,
) -> None:
    # Supervisor-side sweeps ask for the whole table, not one session's slice.
    # The unfiltered query must return rows across sessions in a stable order
    # so the sweep sees every live backend exactly once.
    store = _store(tmp_path)
    store.upsert_backend(session_id="s2", kind="frida", pid=11)
    store.upsert_backend(session_id="s1", kind="x64dbg", pid=22, endpoint="tcp://1")

    rows = store.list_backends()

    assert [(row["session_id"], row["kind"]) for row in rows] == [
        ("s1", "x64dbg"),
        ("s2", "frida"),
    ]
    # And the filtered form still narrows to the one session.
    assert [row["kind"] for row in store.list_backends("s2")] == ["frida"]


@pytest.mark.parametrize("budget", [0, -1, True])
def test_the_store_gc_rejects_a_non_positive_or_boolean_budget(
    tmp_path: Path, budget: object
) -> None:
    # A budget of 0 would mean "collect everything but the newest file";
    # True coerces to 1 byte and does nearly the same. Both are caller bugs
    # the store must refuse before touching a single row.
    store = _store(tmp_path)

    with pytest.raises(ValueError, match="positive integer"):
        store.gc_artifacts(max_total_bytes=budget)  # type: ignore[arg-type]


def test_gc_drops_the_row_for_a_file_already_gone_from_disk(tmp_path: Path) -> None:
    # A crash between unlink and row delete -- or an operator removing a dump
    # by hand -- leaves a row pointing at nothing. Its recorded size still
    # counts against the budget, so GC must retire the row (not report a
    # skip) or the phantom bytes squeeze out real files forever.
    store = _store(tmp_path)
    root = tmp_path / "root" / "s1"
    root.mkdir(parents=True)
    ghost = root / "ghost.bin"
    keeper = root / "keep.bin"
    ghost.write_bytes(b"G" * 64)
    keeper.write_bytes(b"K" * 64)

    ghost_row = store.register_artifact(
        session_id="s1", kind="dump", path=ghost, sha256="0" * 64, source="test"
    )
    store.register_artifact(
        session_id="s1", kind="dump", path=keeper, sha256="1" * 64, source="test"
    )
    ghost.unlink()

    result = store.gc_artifacts(max_total_bytes=64)

    assert ghost_row["id"] in result["removed"]
    assert result["skipped"] == []
    assert store.list_artifacts()["total"] == 1
    assert keeper.is_file()
