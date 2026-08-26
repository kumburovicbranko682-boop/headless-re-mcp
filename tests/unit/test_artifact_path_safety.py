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
def test_artifact_gc_never_unlinks_a_registered_path_outside_its_root(
    tmp_path: Path,
    repository_type: type[SqliteAnalysisRepository] | type[InMemoryAnalysisRepository],
) -> None:
    root = tmp_path / "artifacts"
    repository = repository_type(root)
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"keep")
    outside_row = repository.register_artifact(
        session_id="session",
        kind="external",
        path=outside,
        sha256="0" * 64,
        source="test",
        size=4,
    )
    newest = root / "newest.bin"
    newest.parent.mkdir(parents=True, exist_ok=True)
    newest.write_bytes(b"newest")
    repository.register_artifact(
        session_id="session",
        kind="newest",
        path=newest,
        sha256="1" * 64,
        source="test",
        size=6,
    )

    collected = repository.gc_artifacts(max_total_bytes=1)

    assert outside.is_file()
    assert newest.is_file()
    assert outside_row["id"] not in collected["removed"]
    assert collected["skipped"] == [
        {
            "id": outside_row["id"],
            "reason": "artifact path escapes artifact_root",
        }
    ]
