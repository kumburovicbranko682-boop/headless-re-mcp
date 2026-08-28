"""A retained CLOSED session must not write a new analysis report."""

from __future__ import annotations

import struct
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core import service_ext
from headless_re_mcp.core.service import AnalysisService


def _write_pe(path: Path) -> None:
    image = bytearray(0x400)
    pe_offset = 0x80
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    file_header = pe_offset + 4
    struct.pack_into("<HHIIIHH", image, file_header, 0x8664, 1, 0, 0, 0, 0xF0, 0x2022)
    optional = file_header + 20
    struct.pack_into("<HBB", image, optional, 0x20B, 14, 0)
    struct.pack_into("<I", image, optional + 16, 0x1000)
    struct.pack_into("<Q", image, optional + 24, 0x140000000)
    struct.pack_into("<II", image, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", image, optional + 56, 0x2000, 0x200)
    struct.pack_into("<HH", image, optional + 68, 3, 0x8160)
    struct.pack_into("<I", image, optional + 108, 16)
    section = optional + 0xF0
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x100, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    image[0x200:0x202] = b"\xC3\x90"
    path.write_bytes(image)


def test_report_generate_on_a_closed_session_does_not_write(tmp_path: Path) -> None:
    """A retained CLOSED session still resolved, so a late report wrote a file.

    Measured: after close_session, report.generate returned ok=True and wrote
    artifact_root/reports/<id>/report-*.md. session.close does not forget
    report trees, so overnight retries grow an unreclaimable markdown pile
    and the model treats the dead session as reported.
    """
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        closed = service.close_session(session_id)
        assert closed.ok, closed.error

        result = service.report_generate(session_id, title="late")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
        assert "closed" in result.error.message
        reports = settings.artifact_root.expanduser().resolve() / "reports" / session_id
        assert not reports.exists()
    finally:
        service.close_all()


def test_report_generate_renders_a_web_session_from_its_url(tmp_path: Path) -> None:
    """A web session has a URL, not a file, and the report must still render.

    report.generate summarises knowledge, artifacts and audit -- none of which
    need a local binary -- yet it called require_binary(), which refuses a web
    session outright because no file backs it. A web analyst who captured
    traffic and recorded findings could therefore never produce a report. The
    target reference falls back to the locator, so the report names the URL and
    a real finding lands in the Markdown instead of a target_mismatch.
    """
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    url = "https://example.com/app.js"
    try:
        created = service.create_session(url)
        assert created.ok and created.data is not None, created.error
        session_id = str(created.data["session"]["id"])
        assert created.data["session"]["target"] == "web"

        recorded = service.knowledge_record(session_id, "note", "captured-xhr", {"text": "x"})
        assert recorded.ok, recorded.error

        result = service.report_generate(session_id, title="web report")

        assert result.ok and result.data is not None, result.error
        markdown = str(result.data["markdown"])
        assert url in markdown
        assert "captured-xhr" in markdown
        assert Path(str(result.data["path"])).is_file()
    finally:
        service.close_all()


def test_reports_generated_in_the_same_second_use_distinct_artifact_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    fixed = datetime(2026, 8, 26, 4, 0, 0, tzinfo=UTC)
    monkeypatch.setattr(
        service_ext,
        "datetime",
        SimpleNamespace(now=lambda timezone: fixed),
    )
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]

        first = service.report_generate(session_id, title="first")
        second = service.report_generate(session_id, title="second")

        assert first.ok and first.data is not None, first.error
        assert second.ok and second.data is not None, second.error
        first_path = Path(str(first.data["path"]))
        second_path = Path(str(second.data["path"]))
        assert first_path != second_path
        assert first_path.is_file()
        assert second_path.is_file()
        assert service.repository.list_artifacts(session_id)["total"] == 2
    finally:
        service.close_all()


def test_large_report_returns_bounded_preview_and_keeps_full_artifact(tmp_path: Path) -> None:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = str(created.data["session"]["id"])
        for index in range(250):
            recorded = service.knowledge_record(
                session_id,
                "note",
                f"{index:03d}-" + "é" * 200,
                {"text": "é" * 200},
            )
            assert recorded.ok, recorded.error

        result = service.report_generate(session_id, title="large")

        assert result.ok and result.data is not None, result.error
        assert result.data["truncated"] is True
        assert result.data["hint"] == "full_markdown_in_artifact"
        preview = str(result.data["markdown"]).encode("utf-8")
        artifact = Path(str(result.data["path"])).read_bytes()
        assert len(preview) <= 64 * 1024
        assert len(artifact) == result.data["bytes"]
        assert len(artifact) > len(preview)
        assert artifact.startswith(preview)
        assert result.data["artifact_id"]
    finally:
        service.close_all()