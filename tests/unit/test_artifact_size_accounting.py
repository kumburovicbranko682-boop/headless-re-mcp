from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from headless_re_mcp.core import repository as repository_module
from headless_re_mcp.core.repository import (
    InMemoryAnalysisRepository,
    SqliteAnalysisRepository,
)
from headless_re_mcp.core.store import sqlite_store as sqlite_store_module


@pytest.mark.parametrize(
    "repository_type",
    [SqliteAnalysisRepository, InMemoryAnalysisRepository],
)
def test_artifact_registration_uses_the_file_size_not_an_untrusted_hint(
    tmp_path: Path,
    repository_type: type[SqliteAnalysisRepository] | type[InMemoryAnalysisRepository],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # gc protects whichever row sorts last by created_at, so back-to-back
    # registrations stamped identically by a coarse Windows clock would make
    # "which artifact is newest" unspecified; tick the clock explicitly.
    ticks = iter(range(100))
    base = datetime(2024, 1, 1, tzinfo=UTC)
    fake_clock = SimpleNamespace(now=lambda tz=UTC: base + timedelta(seconds=next(ticks)))
    monkeypatch.setattr(sqlite_store_module, "datetime", fake_clock)
    monkeypatch.setattr(repository_module, "datetime", fake_clock)
    root = tmp_path / "artifacts"
    repository = repository_type(root)
    oldest = root / "oldest.bin"
    newest = root / "newest.bin"
    oldest.parent.mkdir(parents=True, exist_ok=True)
    oldest.write_bytes(b"O" * 64)
    newest.write_bytes(b"N" * 64)

    recorded = repository.register_artifact(
        session_id="session",
        kind="dump",
        path=oldest,
        sha256="0" * 64,
        source="test",
        size=1,
    )
    repository.register_artifact(
        session_id="session",
        kind="dump",
        path=newest,
        sha256="1" * 64,
        source="test",
        size=1,
    )

    assert recorded["size"] == 64
    collected = repository.gc_artifacts(max_total_bytes=64)
    assert recorded["id"] in collected["removed"]
    assert not oldest.exists()
    assert newest.is_file()


@pytest.mark.parametrize(
    "repository_type",
    [SqliteAnalysisRepository, InMemoryAnalysisRepository],
)
def test_artifact_registration_rejects_negative_size_for_a_missing_file(
    tmp_path: Path,
    repository_type: type[SqliteAnalysisRepository] | type[InMemoryAnalysisRepository],
) -> None:
    repository = repository_type(tmp_path / "artifacts")

    with pytest.raises(ValueError, match="cannot be negative"):
        repository.register_artifact(
            session_id="session",
            kind="missing",
            path=tmp_path / "missing.bin",
            sha256="0" * 64,
            source="test",
            size=-1,
        )

    assert repository.list_artifacts()["total"] == 0
