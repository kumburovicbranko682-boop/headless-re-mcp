from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.core.repository import (
    InMemoryAnalysisRepository,
    SqliteAnalysisRepository,
)


@pytest.mark.parametrize(
    "repository_type",
    [SqliteAnalysisRepository, InMemoryAnalysisRepository],
)
def test_audit_recursively_redacts_credentials_from_params_and_results(
    tmp_path: Path,
    repository_type: type[SqliteAnalysisRepository] | type[InMemoryAnalysisRepository],
) -> None:
    repository = repository_type(tmp_path / "artifacts")
    repository.append_audit(
        session_id="session",
        action="provider.configure",
        params_summary={
            "api_key": "provider-secret",
            "nested": {
                "authorization": "Bearer nested-secret",
                "metadata_token": 0x06000001,
            },
            "note": "send Bearer inline-secret",
        },
        ok=False,
        result_summary={
            "error": {
                "password": "result-secret",
                "credential": "another-secret",
            }
        },
    )

    entry = repository.list_audit("session")["entries"][0]
    assert entry["params_summary"] == {
        "api_key": "***",
        "nested": {
            "authorization": "***",
            "metadata_token": 0x06000001,
        },
        "note": "send Bearer ***",
    }
    assert entry["result_summary"] == {
        "error": {
            "password": "***",
            "credential": "***",
        }
    }


@pytest.mark.parametrize(
    "repository_type",
    [SqliteAnalysisRepository, InMemoryAnalysisRepository],
)
def test_audit_blank_session_filter_means_all_rows_in_both_stores(
    tmp_path: Path,
    repository_type: type[SqliteAnalysisRepository] | type[InMemoryAnalysisRepository],
) -> None:
    """A blank session_id filter must behave the same in both repositories.

    The two stores filter with different predicates -- SQLite's ``if session_id:``
    (truthiness) versus the in-memory port's earlier ``if session_id is not
    None:`` -- so an empty-string session id, which the schema allows and the
    agent / OpenAI transports can pass directly, diverged: SQLite treated "" as
    "no filter" and returned every row, while the in-memory port filtered for a
    literal ``session_id == ""`` and returned nothing (no row ever has an empty
    id; session-less rows carry None). The InMemory repository documents "the
    same observable contract as SQLite", and a sibling test already treats a
    SQLite-vs-memory disagreement as a bug, so this pins the blank filter to the
    sensible, matching behaviour: "" means every row, exactly like None.
    """
    repository = repository_type(tmp_path / "artifacts")
    repository.append_audit(
        session_id="s1", action="a", params_summary={}, ok=True, result_summary={}
    )
    repository.append_audit(
        session_id=None, action="b", params_summary={}, ok=True, result_summary={}
    )

    both = repository.list_audit(session_id=None)["total"]
    blank = repository.list_audit(session_id="")["total"]
    scoped = repository.list_audit(session_id="s1")["total"]

    assert both == 2, "None must see the session-scoped and the session-less row"
    assert blank == both, "a blank filter must match None (all rows), not filter to nothing"
    assert scoped == 1, "a real id still filters to that session's rows"
