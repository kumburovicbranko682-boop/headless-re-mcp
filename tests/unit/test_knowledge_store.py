from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.core.repository import (
    InMemoryAnalysisRepository,
    SqliteAnalysisRepository,
)


@pytest.fixture(params=["sqlite", "memory"])
def repository(request: pytest.FixtureRequest, tmp_path: Path) -> Any:
    root = tmp_path / "artifacts"
    if request.param == "sqlite":
        return SqliteAnalysisRepository(root)
    return InMemoryAnalysisRepository(root)


def test_knowledge_record_is_idempotent_per_key(repository: Any) -> None:
    first = repository.record_knowledge(
        session_id="s1",
        kind="function",
        key="0x401000",
        value={"name": "main"},
    )
    second = repository.record_knowledge(
        session_id="s1",
        kind="function",
        key="0x401000",
        value={"name": "start"},
    )

    assert first["replaced"] is False
    assert second["replaced"] is True
    assert second["created_at"] == first["created_at"]

    listing = repository.list_knowledge("s1")
    assert listing["total"] == 1
    assert listing["entries"][0]["value"] == {"name": "start"}


def test_knowledge_filters_by_kind_and_session(repository: Any) -> None:
    repository.record_knowledge(session_id="s1", kind="function", key="a", value={})
    repository.record_knowledge(
        session_id="s1",
        kind="api",
        key="b",
        value={"module": "kernel32"},
    )
    repository.record_knowledge(session_id="s2", kind="function", key="c", value={})

    everything = repository.list_knowledge("s1")
    assert everything["total"] == 2
    assert everything["kinds"] == {"api": 1, "function": 1}

    only_api = repository.list_knowledge("s1", kind="api")
    assert only_api["total"] == 1
    assert only_api["entries"][0]["key"] == "b"
    assert only_api["entries"][0]["value"] == {"module": "kernel32"}


def test_knowledge_paginates(repository: Any) -> None:
    for index in range(5):
        repository.record_knowledge(
            session_id="s1",
            kind="function",
            key=f"{index:04d}",
            value={"index": index},
        )

    page = repository.list_knowledge("s1", offset=2, limit=2)

    assert page["total"] == 5
    assert page["count"] == 2
    assert page["has_more"] is True
    assert [entry["key"] for entry in page["entries"]] == ["0002", "0003"]


def test_an_oversized_finding_is_refused_not_silently_cut(repository: Any) -> None:
    """The store used to slice the JSON and still answer success.

    Measured through SqliteAnalysisRepository: 9012 characters in, a successful
    write, and a read-back that was an 8000-character string
    ``json.loads`` rejected as Unterminated string. The in-memory repository
    kept the object, so the two stores disagreed about what a finding is.
    """
    from headless_re_mcp.core.store.sqlite_store import KNOWLEDGE_VALUE_MAX_CHARS

    oversized = {"note": "x" * 9000}
    with pytest.raises(ValueError, match=str(KNOWLEDGE_VALUE_MAX_CHARS)):
        repository.record_knowledge(
            session_id="s1",
            kind="function",
            key="too-big",
            value=oversized,
        )
    listing = repository.list_knowledge("s1")
    assert listing["total"] == 0
