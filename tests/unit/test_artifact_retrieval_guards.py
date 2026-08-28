"""The artifact retrieval and session peek guards, device-free.

Every line's outputs come back through the same service methods -- web captures,
proxy flows, APK decompiles and native exports are all rows that
artifacts_describe names and artifacts_read pages out. The read path re-checks
containment on every call because the row's path is data from the store, not a
path the reader constructed: a poisoned or stale row must not turn the pager
into an arbitrary-file read. These pin the three guards that had no device-free
cover -- the describe success envelope, the containment refusal (including the
classic prefix-collision sibling directory), the vanished-file not_found -- and
the peek fallback's not_found for an id neither live nor stored.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from headless_re_mcp.config import Settings
from headless_re_mcp.core.repository import InMemoryAnalysisRepository
from headless_re_mcp.core.service import AnalysisService


def _service(tmp_path: Path) -> tuple[AnalysisService, InMemoryAnalysisRepository, Path]:
    root = tmp_path / "artifacts"
    repository = InMemoryAnalysisRepository(root)
    settings = replace(Settings.load(), artifact_root=root)
    return AnalysisService(settings, repository=repository), repository, root


def _register(repository: InMemoryAnalysisRepository, path: Path) -> str:
    artifact = repository.register_artifact(
        session_id="session",
        kind="capture",
        path=path,
        sha256="a" * 64,
        source="test",
    )
    return str(artifact["id"])


def test_artifacts_describe_returns_the_registered_row(tmp_path: Path) -> None:
    service, repository, root = _service(tmp_path)
    try:
        stored = root / "capture.bin"
        stored.write_bytes(b"payload")
        artifact_id = _register(repository, stored)
        result = service.artifacts_describe(artifact_id)
        assert result.ok and result.data is not None, result.error
        artifact = result.data["artifact"]
        assert isinstance(artifact, dict)
        assert str(artifact["id"]) == artifact_id
        assert str(artifact["path"]) == str(stored)
    finally:
        service.close_all()


def test_artifacts_read_refuses_a_row_that_escapes_the_artifact_root(tmp_path: Path) -> None:
    # The stored path sits in a sibling directory whose name extends the root's
    # (artifacts vs artifacts-evil): a startswith check would wave it through,
    # the parents check must not. The file exists and is readable, so the
    # refusal is containment, not a missing file.
    service, repository, _root = _service(tmp_path)
    try:
        outside = tmp_path / "artifacts-evil" / "loot.bin"
        outside.parent.mkdir(parents=True)
        outside.write_bytes(b"secret")
        artifact_id = _register(repository, outside)
        result = service.artifacts_read(artifact_id)
        assert result.ok is False and result.error is not None
        assert result.error.code == "permission_denied", result.error
        assert "escapes artifact_root" in result.error.message
        assert result.data is None
    finally:
        service.close_all()


def test_artifacts_read_reports_a_vanished_file_as_not_found(tmp_path: Path) -> None:
    # The row is well-formed and inside the root, but the bytes are gone (a gc
    # or an operator delete raced the read): not_found, not an OSError escape.
    service, repository, root = _service(tmp_path)
    try:
        gone = root / "reaped.bin"
        artifact_id = _register(repository, gone)
        result = service.artifacts_read(artifact_id)
        assert result.ok is False and result.error is not None
        assert result.error.code == "not_found", result.error
        assert "artifact file missing" in result.error.message
    finally:
        service.close_all()


def test_peek_session_record_is_not_found_for_an_id_neither_live_nor_stored(
    tmp_path: Path,
) -> None:
    # Not in the registry and no stored row either: the fallback raises the
    # same SessionNotFound a live lookup would, mapped to the structured
    # session_not_found failure rather than a fabricated empty record.
    service, _repository, _root = _service(tmp_path)
    try:
        result = service.peek_session_record("session-that-never-existed")
        assert result.ok is False and result.error is not None
        assert result.error.code == "session_not_found", result.error
        assert result.error.details["session_id"] == "session-that-never-existed"
    finally:
        service.close_all()
