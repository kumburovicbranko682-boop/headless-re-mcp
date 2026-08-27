from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.core.repository import (
    InMemoryAnalysisRepository,
    SqliteAnalysisRepository,
)
from headless_re_mcp.core.store.sqlite_store import (
    KNOWLEDGE_VALUE_MAX_CHARS,
    encode_knowledge_value,
)


def test_encode_knowledge_value_round_trips_and_keeps_unicode() -> None:
    value = {"name": "内核函数", "addr": "0x401000", "tags": ["oep", "iat"]}
    encoded = encode_knowledge_value(value)
    assert json.loads(encoded) == value
    assert "内核函数" in encoded, "ensure_ascii=False keeps the finding readable"


def test_encode_knowledge_value_refuses_an_oversized_finding() -> None:
    """A finding over the cap must be refused whole, not cut into invalid JSON.

    The store column holds a serialized finding; truncating to fit would write a
    string that no longer parses as JSON, so the reader would raise on every
    later query. Refuse at the boundary and tell the caller to keep the bulk as
    an artifact and store only the reference.
    """
    at_cap = {"blob": "x" * (KNOWLEDGE_VALUE_MAX_CHARS - len('{"blob": ""}'))}
    encoded = encode_knowledge_value(at_cap)
    assert len(encoded) == KNOWLEDGE_VALUE_MAX_CHARS
    assert json.loads(encoded) == at_cap

    over_cap = {"blob": "x" * KNOWLEDGE_VALUE_MAX_CHARS}
    with pytest.raises(ValueError, match="record the bulk as an artifact"):
        encode_knowledge_value(over_cap)


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


def test_knowledge_kinds_tally_covers_every_match_not_just_the_page(
    repository: Any,
) -> None:
    """kinds must be the whole-set breakdown, matching total, across pages.

    kinds sits next to total, so a caller reads it as "how many findings of
    each kind does this session hold". It used to be built from the page's
    rows, so a paged reply under-reported every kind: page two of a session
    with eight functions and three apis reported a handful, not 8 + 3. The
    tally now counts every matching row and sums to total on any page.
    """
    for index in range(8):
        repository.record_knowledge(
            session_id="s1", kind="function", key=f"f{index:04d}", value={}
        )
    for index in range(3):
        repository.record_knowledge(
            session_id="s1", kind="api", key=f"a{index:04d}", value={}
        )

    whole = repository.list_knowledge("s1")
    assert whole["total"] == 11
    assert whole["kinds"] == {"api": 3, "function": 8}

    # A page that carries only api rows still reports the full breakdown, and
    # the tally keeps summing to total rather than to this page's count.
    page = repository.list_knowledge("s1", offset=0, limit=2)
    assert page["count"] == 2
    assert page["has_more"] is True
    assert page["kinds"] == {"api": 3, "function": 8}
    assert sum(page["kinds"].values()) == page["total"]

    # Filtering by kind scopes both total and kinds to that kind.
    only_fn = repository.list_knowledge("s1", kind="function", limit=2)
    assert only_fn["total"] == 8
    assert only_fn["kinds"] == {"function": 8}


def test_a_finding_too_large_to_store_is_refused_not_silently_cut(repository: Any) -> None:
    """The store used to slice JSON text at 8000 characters.

    Measured: a 31021-character finding was recorded as success, then read
    back as an 8000-character string that json.loads rejected (unterminated
    string). SQLite cut and Memory kept the object, so the two repositories
    disagreed. The write must fail and leave nothing behind.
    """
    from headless_re_mcp.core.store.sqlite_store import KNOWLEDGE_VALUE_MAX_CHARS

    oversized = {"decompilation": "int main(void) { return 0; }\n" * 1000}

    with pytest.raises(ValueError, match=str(KNOWLEDGE_VALUE_MAX_CHARS)):
        repository.record_knowledge(
            session_id="s1",
            kind="finding",
            key="big",
            value=oversized,
        )

    listing = repository.list_knowledge("s1")
    assert listing["total"] == 0
    assert [item for item in listing["entries"] if item["key"] == "big"] == []


def test_a_session_does_not_keep_every_finding_it_ever_recorded(repository: Any) -> None:
    """knowledge.query is paged; the table itself kept every unique key.

    800 small facts were 201 KB and still climbing, and each value may be
    8000 characters. A long-lived session that records one key per function
    never finishes, so the file grew with facts nobody pages in one reply.
    """
    if hasattr(repository, "store"):
        repository.store.retained_knowledge_per_session = 3
    else:
        repository.retained_knowledge_per_session = 3

    repository.record_knowledge(session_id="other", kind="function", key="keep", value={})
    for index in range(6):
        repository.record_knowledge(
            session_id="s1",
            kind="function",
            key=f"{index:04d}",
            value={"index": index},
        )

    listing = repository.list_knowledge("s1")
    assert listing["total"] == 3
    assert [entry["key"] for entry in listing["entries"]] == ["0003", "0004", "0005"]
    other = repository.list_knowledge("other")
    assert other["total"] == 1
    assert other["entries"][0]["key"] == "keep"


def test_inmemory_timeline_does_not_keep_every_entry_ever_appended(tmp_path: Path) -> None:
    """The in-memory repository trimmed audit and knowledge but not the timeline.

    Every lifecycle event and tool note appends one entry per session, so a
    long-lived composition on this port grew one Python list per session for
    the life of the process. The file-backed timeline caps itself at 10,000
    lines; the in-memory port now keeps the newest entries the same way.
    """
    repo = InMemoryAnalysisRepository(tmp_path / "artifacts")
    repo.retained_timeline_per_session = 3

    repo.append_timeline("other", "event.keep", "unrelated session is untouched")
    for index in range(6):
        repo.append_timeline("s1", f"event.{index}", f"message {index}")

    page = repo.list_timeline("s1")
    assert page["total"] == 3
    assert [event["event"] for event in page["events"]] == ["event.3", "event.4", "event.5"]

    other = repo.list_timeline("other")
    assert other["total"] == 1
    assert other["events"][0]["event"] == "event.keep"


def test_audit_json_cap_stays_valid_json() -> None:
    from headless_re_mcp.core.store.sqlite_store import encode_audit_json

    clipped = encode_audit_json({"note": "x" * 8000})
    assert len(clipped) <= 4000
    parsed = json.loads(clipped)
    assert parsed["truncated"] is True


@pytest.mark.parametrize("limit", (1, 2, 32, 64, 100))
def test_audit_json_cap_never_slices_invalid_json(limit: int) -> None:
    from headless_re_mcp.core.store.sqlite_store import encode_audit_json

    clipped = encode_audit_json(
        {"note": ('quote:" slash:\\ nul:\x00 界' * 1000)},
        limit=limit,
    )

    assert len(clipped) <= limit
    json.loads(clipped)
