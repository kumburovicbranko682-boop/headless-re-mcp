"""A blank session_id / kind filter must mean "all rows" in BOTH repositories.

``InMemoryAnalysisRepository`` is a production port that documents "the same
observable contract as SQLite", but it systematically filtered with ``X is not
None`` where the SQLite store uses truthiness (``if session_id:`` / ``if kind:``).
The two disagree on exactly one input -- an empty string, which the tool schemas
allow and the agent / OpenAI transports can pass straight to the port: SQLite
reads a blank filter as "no filter, every row", while the in-memory port filtered
for a literal ``session_id == ""`` / ``kind == ""`` and returned nothing (no row
ever carries an empty session id, and a knowledge kind is always a non-empty
label). It surfaced first in ``list_audit`` / ``list_knowledge`` and again in
``list_artifacts`` / ``list_backends`` -- four readers, one bug shape.

This pins the whole class in one place so it cannot creep back and a fifth
filter-taking reader cannot quietly reintroduce it: for every such reader, a
blank filter must return the same row set as ``None`` (all rows), a real filter
must still narrow it, and both repositories must agree -- the parity the
in-memory port promises. A sibling test already treats a SQLite-vs-memory
disagreement as a bug to fix.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.core.repository import (
    InMemoryAnalysisRepository,
    SqliteAnalysisRepository,
)

_REPO_TYPES = [SqliteAnalysisRepository, InMemoryAnalysisRepository]

# (blank filter, no filter / all, a real filter) for each filter-taking reader.
_READERS: dict[str, tuple[Callable[[Any], Any], Callable[[Any], Any], Callable[[Any], Any]]] = {
    "artifacts": (
        lambda r: r.list_artifacts(session_id=""),
        lambda r: r.list_artifacts(session_id=None),
        lambda r: r.list_artifacts(session_id="s1"),
    ),
    "backends": (
        lambda r: r.list_backends(session_id=""),
        lambda r: r.list_backends(session_id=None),
        lambda r: r.list_backends(session_id="s1"),
    ),
    "audit": (
        lambda r: r.list_audit(session_id=""),
        lambda r: r.list_audit(session_id=None),
        lambda r: r.list_audit(session_id="s1"),
    ),
    "knowledge": (
        lambda r: r.list_knowledge("s1", kind=""),
        lambda r: r.list_knowledge("s1"),
        lambda r: r.list_knowledge("s1", kind="function"),
    ),
}


def _seed(repo: Any, tmp_path: Path) -> None:
    """Give every reader more than one row, so a blank filter that wrongly
    narrowed to nothing (or to one) is distinguishable from "all"."""
    file_a = tmp_path / "a.bin"
    file_a.write_bytes(b"x")
    file_b = tmp_path / "b.bin"
    file_b.write_bytes(b"y")
    repo.register_artifact(session_id="s1", kind="dump", path=str(file_a), sha256="h1", source="t")
    repo.register_artifact(session_id="s2", kind="dump", path=str(file_b), sha256="h2", source="t")
    repo.record_backend("s1", "web", pid=1, endpoint="127.0.0.1:1")
    repo.record_backend("s2", "web", pid=2, endpoint="127.0.0.1:2")
    repo.append_audit(session_id="s1", action="x", params_summary={}, ok=True, result_summary={})
    repo.append_audit(session_id=None, action="y", params_summary={}, ok=True, result_summary={})
    repo.record_knowledge(session_id="s1", kind="function", key="k1", value={})
    repo.record_knowledge(session_id="s1", kind="api", key="k2", value={})


def _count(result: Any) -> int:
    """Row count for either shape: list_backends returns a list, the rest a page."""
    return len(result) if isinstance(result, list) else int(result["total"])


@pytest.mark.parametrize("repository_type", _REPO_TYPES)
@pytest.mark.parametrize("reader", sorted(_READERS))
def test_blank_filter_lists_every_row_like_none_in_both_stores(
    repository_type: type[SqliteAnalysisRepository] | type[InMemoryAnalysisRepository],
    reader: str,
    tmp_path: Path,
) -> None:
    repo = repository_type(tmp_path / "artifacts")
    _seed(repo, tmp_path)
    blank, all_rows, real = _READERS[reader]

    all_count = _count(all_rows(repo))
    blank_count = _count(blank(repo))
    real_count = _count(real(repo))

    assert all_count >= 2, f"{reader}: seed must give the reader more than one row"
    assert blank_count == all_count, (
        f"{reader}: a blank filter must list every row (like None), not filter to "
        f"nothing -- SQLite returns {all_count} but this store returned {blank_count}"
    )
    assert real_count < all_count, f"{reader}: a real filter must still narrow the set"
