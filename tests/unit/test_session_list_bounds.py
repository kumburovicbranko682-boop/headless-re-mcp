"""session.list used to dump every session this process still held."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService


def _write_minimal_pe(path: Path, machine: int = 0x8664) -> None:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = machine.to_bytes(2, "little")
    path.write_bytes(image)


def _service(tmp_path: Path) -> AnalysisService:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    return AnalysisService(settings)


def _open_many(service: AnalysisService, binary: Path, count: int) -> None:
    for _ in range(count):
        created = service.create_session(str(binary))
        assert created.ok, created.error


class TestSessionListIsPaged:
    """A soak that opens one session per binary used to get the whole table.

    Measured: 80 sessions, count=80, 29.4 KiB, no has_more -- so a caller
    that only looks at the page thinks this process holds nothing else.
    """

    def test_hitting_the_default_page_is_reported(self, tmp_path: Path) -> None:
        binary = tmp_path / "fixture.exe"
        _write_minimal_pe(binary, 0x8664)
        service = _service(tmp_path)
        try:
            _open_many(service, binary, 80)
            result = service.list_sessions()
            assert result.ok and result.data is not None
            assert result.data["count"] == 50
            assert result.data["total"] == 80
            assert result.data["offset"] == 0
            assert result.data["has_more"] is True
            dumped = json.dumps(result.data, default=str)
            assert len(dumped.encode("utf-8")) < 25_000
        finally:
            service.close_all()

    def test_the_tail_says_it_ended(self, tmp_path: Path) -> None:
        binary = tmp_path / "fixture.exe"
        _write_minimal_pe(binary, 0x8664)
        service = _service(tmp_path)
        try:
            _open_many(service, binary, 80)
            tail = service.list_sessions(offset=50, limit=50)
            assert tail.ok and tail.data is not None
            assert tail.data["count"] == 30
            assert tail.data["total"] == 80
            assert tail.data["has_more"] is False
        finally:
            service.close_all()

    def test_a_short_list_is_complete(self, tmp_path: Path) -> None:
        binary = tmp_path / "fixture.exe"
        _write_minimal_pe(binary, 0x8664)
        service = _service(tmp_path)
        try:
            _open_many(service, binary, 3)
            result = service.list_sessions()
            assert result.ok and result.data is not None
            assert result.data["count"] == 3
            assert result.data["total"] == 3
            assert result.data["has_more"] is False
        finally:
            service.close_all()

    def test_a_result_that_exactly_fills_the_page_is_complete(self, tmp_path: Path) -> None:
        binary = tmp_path / "fixture.exe"
        _write_minimal_pe(binary, 0x8664)
        service = _service(tmp_path)
        try:
            _open_many(service, binary, 50)
            result = service.list_sessions()
            assert result.ok and result.data is not None
            assert result.data["count"] == 50
            assert result.data["has_more"] is False
        finally:
            service.close_all()

    def test_a_huge_limit_is_capped(self, tmp_path: Path) -> None:
        binary = tmp_path / "fixture.exe"
        _write_minimal_pe(binary, 0x8664)
        service = _service(tmp_path)
        try:
            _open_many(service, binary, 80)
            result = service.list_sessions(limit=10_000)
            assert result.ok and result.data is not None
            assert result.data["count"] == 80
            assert result.data["has_more"] is False
        finally:
            service.close_all()


class TestSessionListDescriptionMatchesTheCut:
    """session.list now pages with has_more, but the tool text hid that.

    Measured: 80 sessions, default page 50, has_more=true, while the
    description said "list all sessions" -- so a model treats a page as every
    session this process still holds.
    """

    def test_the_tool_text_says_to_check_has_more(self) -> None:
        from headless_re_mcp.tools.core import build_core_session_tools

        service = AnalysisService()
        try:
            tools = {item.name: item for item in build_core_session_tools(service)}
            doc = tools["session.list"].handler.__doc__ or ""
        finally:
            service.close_all()
        assert "has_more" in doc
