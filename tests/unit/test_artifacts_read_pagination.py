"""artifacts.read must say when a page is not the whole artifact.

Every other paginated reader on the surface returns has_more so a page that
filled the limit is not read as complete. artifacts.read returned only size,
leaving a caller to decode the hex, count the bytes and compare against size to
notice a 4 KiB page was the head of a 200 MB dump. These pin the explicit
has_more/bytes_returned signals and the corrected description.
"""

from __future__ import annotations

import ast
from dataclasses import replace
from pathlib import Path

from headless_re_mcp.config import Settings
from headless_re_mcp.core.repository import InMemoryAnalysisRepository
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.tools.meta import build_meta_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_meta_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            for keyword in decorator.keywords:
                if (
                    keyword.arg == "name"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value == name
                ):
                    return ast.get_docstring(node) or ""
    return ""


def _service_with_artifact(tmp_path: Path, payload: bytes) -> tuple[AnalysisService, str]:
    root = tmp_path / "artifacts"
    repository = InMemoryAnalysisRepository(root)
    settings = replace(Settings.load(), artifact_root=root)
    service = AnalysisService(settings, repository=repository)
    artifact_path = root / "capture.bin"
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    artifact_path.write_bytes(payload)
    artifact = repository.register_artifact(
        session_id="session",
        kind="capture",
        path=artifact_path,
        sha256="a" * 64,
        source="test",
    )
    return service, str(artifact["id"])


def test_artifacts_read_flags_has_more_until_the_last_page(tmp_path: Path) -> None:
    service, artifact_id = _service_with_artifact(tmp_path, b"A" * 100)
    try:
        first = service.artifacts_read(artifact_id, offset=0, limit=40)
        assert first.ok and first.data is not None, first.error
        assert first.data["size"] == 100
        assert first.data["bytes_returned"] == 40
        assert first.data["has_more"] is True

        mid = service.artifacts_read(artifact_id, offset=40, limit=40)
        assert mid.data is not None
        assert mid.data["bytes_returned"] == 40
        assert mid.data["has_more"] is True

        # The last page is shorter than the requested limit; has_more clears.
        last = service.artifacts_read(artifact_id, offset=80, limit=40)
        assert last.data is not None
        assert last.data["bytes_returned"] == 20
        assert last.data["has_more"] is False
    finally:
        service.close_all()


def test_artifacts_read_at_or_past_eof_is_not_flagged_incomplete(tmp_path: Path) -> None:
    service, artifact_id = _service_with_artifact(tmp_path, b"A" * 100)
    try:
        at_end = service.artifacts_read(artifact_id, offset=100, limit=40)
        assert at_end.data is not None
        assert at_end.data["bytes_returned"] == 0
        assert at_end.data["has_more"] is False

        past = service.artifacts_read(artifact_id, offset=250, limit=40)
        assert past.data is not None
        assert past.data["bytes_returned"] == 0
        assert past.data["has_more"] is False
    finally:
        service.close_all()


def test_artifacts_read_whole_file_in_one_page_is_complete(tmp_path: Path) -> None:
    service, artifact_id = _service_with_artifact(tmp_path, b"A" * 100)
    try:
        whole = service.artifacts_read(artifact_id, offset=0, limit=100)
        assert whole.data is not None
        assert whole.data["bytes_returned"] == 100
        assert whole.data["has_more"] is False
    finally:
        service.close_all()


def test_artifacts_read_docstring_names_has_more_and_bytes_returned() -> None:
    doc = _tool_docstring("artifacts.read")
    assert "has_more" in doc
    assert "bytes_returned" in doc
