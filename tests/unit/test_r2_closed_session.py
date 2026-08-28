"""A retained CLOSED session must not start radare2."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService


def _write_minimal_pe(path: Path) -> None:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = (0x8664).to_bytes(2, "little")
    path.write_bytes(image)


class _TrackingR2:
    def __init__(self, *args: object, **kwargs: object) -> None:
        self.opens = 0
        self.runs = 0

    def open(self, binary: Path, *, timeout: float = 30.0) -> dict[str, Any]:
        del binary, timeout
        self.opens += 1
        return {"opened": True, "binary": "x", "info": "i", "note": "tracked"}

    def run(
        self, binary: Path, commands: list[str], *, timeout: float = 30.0
    ) -> dict[str, Any]:
        del binary, commands, timeout
        self.runs += 1
        return {"raw": "ok", "commands": []}

    def disasm(
        self, binary: Path, address: int, *, count: int = 32, timeout: float = 30.0
    ) -> dict[str, Any]:
        del binary, address, count, timeout
        self.runs += 1
        return {"raw": "[]", "commands": ["pdj"]}

    def xrefs(self, binary: Path, address: int, *, timeout: float = 30.0) -> dict[str, Any]:
        del binary, address, timeout
        self.runs += 1
        return {"raw": "[]", "commands": ["axtj"]}


def test_r2_open_on_a_closed_session_does_not_start_r2(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A retained CLOSED session still resolved, so a late r2.open started r2.

    Measured: after close_session, r2.open returned ok=True with opened=True
    and the client open() ran once. session.close cannot reap an r2 process
    that started after it returned. The model then treats the dead session as
    opened in radare2.
    """
    tracker = _TrackingR2()
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.R2Client",
        lambda *args, **kwargs: tracker,
    )
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        closed = service.close_session(session_id)
        assert closed.ok, closed.error

        result = service.r2_open(session_id)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
        assert "closed" in result.error.message
        assert tracker.opens == 0
        assert tracker.runs == 0
    finally:
        service.close_all()


def test_r2_open_does_not_report_success_if_the_session_closes_during_run(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A close mid-open used to record radare2 on a session that cannot use it."""
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)

    class _CloseThenOpen(_TrackingR2):
        def open(self, binary: Path, *, timeout: float = 30.0) -> dict[str, Any]:
            service.close_session(session_id)
            return super().open(binary, timeout=timeout)

    tracker = _CloseThenOpen()
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.R2Client",
        lambda *args, **kwargs: tracker,
    )
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        result = service.r2_open(session_id)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
        assert "closed" in result.error.message
    finally:
        service.close_all()


def test_r2_functions_on_a_closed_session_does_not_start_r2(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """r2.functions goes through the same unguarded request path as r2.open."""
    tracker = _TrackingR2()
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.R2Client",
        lambda *args, **kwargs: tracker,
    )
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        closed = service.close_session(session_id)
        assert closed.ok, closed.error

        result = service.r2_functions(session_id)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
        assert "closed" in result.error.message
        assert tracker.runs == 0
    finally:
        service.close_all()


def _closed_session_id(service: AnalysisService, binary: Path) -> str:
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None, created.error
    session_id = created.data["session"]["id"]
    closed = service.close_session(session_id)
    assert closed.ok, closed.error
    return session_id


def test_r2_disasm_on_a_closed_session_does_not_start_r2(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """r2.disasm carries its own state guard, distinct from the request helper.

    disasm and xrefs each open a fresh pipe rather than routing through
    _r2_request, so their pre-call checks are the only thing standing between a
    retained CLOSED session and a radare2 process the closed session can never
    reap.
    """
    tracker = _TrackingR2()
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.R2Client",
        lambda *args, **kwargs: tracker,
    )
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    try:
        session_id = _closed_session_id(service, binary)
        result = service.r2_disasm(session_id, 0x1000)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
        assert "closed" in result.error.message
        assert tracker.runs == 0
    finally:
        service.close_all()


def test_r2_disasm_does_not_report_success_if_the_session_closes_during_run(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A close landing mid-disasm must not hand back rows for a dead session."""
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)

    class _CloseThenDisasm(_TrackingR2):
        def disasm(
            self, binary: Path, address: int, *, count: int = 32, timeout: float = 30.0
        ) -> dict[str, Any]:
            service.close_session(session_id)
            return super().disasm(binary, address, count=count, timeout=timeout)

    tracker = _CloseThenDisasm()
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.R2Client",
        lambda *args, **kwargs: tracker,
    )
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        result = service.r2_disasm(session_id, 0x1000)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
        assert "closed" in result.error.message
    finally:
        service.close_all()


def test_r2_xrefs_on_a_closed_session_does_not_start_r2(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """r2.xrefs mirrors disasm: its own pre-call guard, not the shared helper."""
    tracker = _TrackingR2()
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.R2Client",
        lambda *args, **kwargs: tracker,
    )
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    try:
        session_id = _closed_session_id(service, binary)
        result = service.r2_xrefs(session_id, 0x1000)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
        assert "closed" in result.error.message
        assert tracker.runs == 0
    finally:
        service.close_all()


def test_r2_xrefs_does_not_report_success_if_the_session_closes_during_run(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The post-call guard rejects xrefs collected for a session that just closed."""
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)

    class _CloseThenXrefs(_TrackingR2):
        def xrefs(self, binary: Path, address: int, *, timeout: float = 30.0) -> dict[str, Any]:
            service.close_session(session_id)
            return super().xrefs(binary, address, timeout=timeout)

    tracker = _CloseThenXrefs()
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.R2Client",
        lambda *args, **kwargs: tracker,
    )
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        result = service.r2_xrefs(session_id, 0x1000)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
        assert "closed" in result.error.message
    finally:
        service.close_all()