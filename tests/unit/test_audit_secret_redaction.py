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
