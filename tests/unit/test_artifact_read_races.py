from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.repository import InMemoryAnalysisRepository
from headless_re_mcp.core.service import AnalysisService


def test_artifact_read_uses_the_open_handle_for_its_size(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "artifacts"
    repository = InMemoryAnalysisRepository(root)
    settings = replace(Settings.load(), artifact_root=root)
    service = AnalysisService(settings, repository=repository)
    artifact_path = root / "capture.bin"
    payload = b"stable-open-handle"
    artifact_path.write_bytes(payload)
    artifact = repository.register_artifact(
        session_id="session",
        kind="capture",
        path=artifact_path,
        sha256="a" * 64,
        source="test",
    )

    real_stat = Path.stat
    path_stats = 0

    def disappearing_stat(
        path: Path, *, follow_symlinks: bool = True
    ) -> os.stat_result:
        nonlocal path_stats
        if path == artifact_path:
            path_stats += 1
            if path_stats > 1:
                raise FileNotFoundError(path)
        return real_stat(path, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(Path, "stat", disappearing_stat)
    try:
        result = service.artifacts_read(str(artifact["id"]))

        assert result.ok and result.data is not None, result.error
        assert bytes.fromhex(str(result.data["data"])) == payload
        assert result.data["size"] == len(payload)
        assert path_stats == 1
    finally:
        service.close_all()
