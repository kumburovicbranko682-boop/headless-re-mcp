from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import IO, Any, cast

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

    real_open = Path.open
    real_stat = Path.stat
    opened = False

    def disappearing_open(path: Path, *args: Any, **kwargs: Any) -> IO[Any]:
        nonlocal opened
        stream = cast(IO[Any], real_open(path, *args, **kwargs))
        if path == artifact_path:
            opened = True
        return stream

    def disappearing_stat(path: Path, *args: Any, **kwargs: Any) -> Any:
        if path == artifact_path and opened:
            raise FileNotFoundError(path)
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", disappearing_open)
    monkeypatch.setattr(Path, "stat", disappearing_stat)
    try:
        result = service.artifacts_read(str(artifact["id"]))

        assert result.ok and result.data is not None, result.error
        assert bytes.fromhex(str(result.data["data"])) == payload
        assert result.data["size"] == len(payload)
    finally:
        service.close_all()
