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


def test_r2_disasm_does_not_report_success_if_the_session_closes_during_run(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A close mid-disasm must not return disassembly for a session that is gone.

    r2.disasm carries the same post-run state re-check as r2.open -- session.close
    cannot reap the one-shot r2 process that started after it returned, so without
    the re-check a disasm finishing just after a concurrent close comes back ok on
    a dead session. r2.open pins this window; r2.disasm has the identical inline
    guard but no test, so a refactor that dropped its second state check would go
    unnoticed. The r2 live gate drives client.disasm directly, never the service
    method's guard.
    """
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)

    class _CloseThenDisasm(_TrackingR2):
        def disasm(
            self, binary: Path, address: int, *, count: int = 32, timeout: float = 30.0
        ) -> dict[str, Any]:
            del binary, address, count, timeout
            service.close_session(session_id)
            self.runs += 1
            return {"raw": "ok", "commands": [], "items": []}

    tracker = _CloseThenDisasm()
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.R2Client",
        lambda *args, **kwargs: tracker,
    )
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        result = service.r2_disasm(session_id, 0x1000, count=8)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
        assert "closed" in result.error.message
    finally:
        service.close_all()


def test_r2_xrefs_does_not_report_success_if_the_session_closes_during_run(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The r2.xrefs twin of the disasm race: a mid-run close must not report ok.

    Same inline post-run re-check, same untested window. Kept beside disasm so
    the pair reads as one contract: every r2 service method that re-checks state
    after the run is proven to discard a result whose session went terminal
    mid-flight, not just r2.open.
    """
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)

    class _CloseThenXrefs(_TrackingR2):
        def xrefs(
            self, binary: Path, address: int, *, timeout: float = 30.0
        ) -> dict[str, Any]:
            del binary, address, timeout
            service.close_session(session_id)
            self.runs += 1
            return {"raw": "[]", "commands": [], "items": []}

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


def test_r2_functions_does_not_report_success_if_the_session_closes_during_run(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The shared _r2_request path (functions/info/strings/imports/exports) too.

    r2.functions and its siblings all run through _r2_request, which has its own
    post-run re-check plus a _record_backend the inline disasm/xrefs paths skip.
    Without the re-check a request finishing just after a concurrent close would
    record radare2 as a backend on a terminal session and return ok. Only the
    pre-run guard was tested (r2.functions on an already-closed session); this
    pins the mid-run window for the whole family that shares the helper.
    """
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)

    class _CloseThenRun(_TrackingR2):
        def run(
            self, binary: Path, commands: list[str], *, timeout: float = 30.0
        ) -> dict[str, Any]:
            del binary, commands, timeout
            service.close_session(session_id)
            self.runs += 1
            return {"raw": "ok", "commands": []}

    tracker = _CloseThenRun()
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.R2Client",
        lambda *args, **kwargs: tracker,
    )
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        result = service.r2_functions(session_id)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
        assert "closed" in result.error.message
        # The backend must not have been recorded on the terminal session.
        record = service.peek_session_record(session_id)
        assert record.ok, record.error
        assert "radare2" not in (record.data.get("backends") or [])
    finally:
        service.close_all()