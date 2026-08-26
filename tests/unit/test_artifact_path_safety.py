from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.core.repository import (
    InMemoryAnalysisRepository,
    SqliteAnalysisRepository,
)
from headless_re_mcp.core.store.sqlite_store import SessionStore


@pytest.mark.parametrize(
    "repository_type",
    [SqliteAnalysisRepository, InMemoryAnalysisRepository],
)
def test_repository_refuses_artifacts_outside_its_root(
    tmp_path: Path,
    repository_type: type[SqliteAnalysisRepository] | type[InMemoryAnalysisRepository],
) -> None:
    root = tmp_path / "artifacts"
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"do not register")
    repository = repository_type(root)

    with pytest.raises(ValueError, match="escapes artifact_root"):
        repository.register_artifact(
            session_id="session",
            kind="dump",
            path=outside,
            sha256="0" * 64,
            source="test",
        )

    assert repository.list_artifacts()["total"] == 0
    assert outside.read_bytes() == b"do not register"


def test_sqlite_gc_never_unlinks_an_outside_path_from_a_corrupt_row(
    tmp_path: Path,
) -> None:
    root = tmp_path / "artifacts"
    store = SessionStore(root / "meta" / "sessions.db")
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"keep")
    outside_row = store.register_artifact(
        session_id="session",
        kind="corrupt",
        path=outside,
        sha256="0" * 64,
        source="test",
        size=4,
    )
    newest = root / "newest.bin"
    newest.write_bytes(b"newest")
    store.register_artifact(
        session_id="session",
        kind="newest",
        path=newest,
        sha256="1" * 64,
        source="test",
        size=6,
    )

    collected = store.gc_artifacts(max_total_bytes=1)

    assert outside.is_file()
    assert newest.is_file()
    assert outside_row["id"] not in collected["removed"]
    assert collected["skipped"] == [
        {
            "id": outside_row["id"],
            "reason": "artifact path escapes artifact_root",
        }
    ]
