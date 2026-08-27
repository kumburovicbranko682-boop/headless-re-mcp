"""r2.disasm and r2.xrefs must record the radare2 backend they actually spawn."""

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


class _StubR2:
    """A radare2 stand-in whose disasm/xrefs return a minimal payload."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs

    def disasm(
        self, binary: Path, address: int, *, count: int = 32, timeout: float = 30.0
    ) -> dict[str, Any]:
        del binary, address, count, timeout
        return {"items": [], "count": 0, "address_va": 0}

    def xrefs(self, binary: Path, address: int, *, timeout: float = 30.0) -> dict[str, Any]:
        del binary, address, timeout
        return {"items": [], "count": 0, "address_va": 0}


def _radare2_backends(service: AnalysisService, session_id: str) -> list[dict[str, Any]]:
    return [
        row
        for row in service.repository.list_backends(session_id)
        if row.get("kind") == "radare2"
    ]


def test_r2_disasm_records_the_radare2_backend(tmp_path: Path, monkeypatch: Any) -> None:
    """A session that only ran r2.disasm used to show no radare2 backend.

    r2.open and the r2.info/functions/strings/imports/exports path both call
    _record_backend, but r2.disasm (a separate method) only appended a timeline
    entry -- so list_backends, the audit of which engines touched a session,
    omitted radare2 for a caller that reached only for a disassembly. That reads
    as "radare2 was never used" for a session that in fact ran it.
    """
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.R2Client",
        lambda *args, **kwargs: _StubR2(),
    )
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        assert _radare2_backends(service, session_id) == []

        result = service.r2_disasm(session_id, 0x140001000)
        assert result.ok, result.error

        recorded = _radare2_backends(service, session_id)
        assert len(recorded) == 1
        assert recorded[0]["endpoint"] == "pipe"
    finally:
        service.close_all()


def test_r2_xrefs_records_the_radare2_backend(tmp_path: Path, monkeypatch: Any) -> None:
    """r2.xrefs had the same gap as r2.disasm: it spawned r2 without recording it."""
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.R2Client",
        lambda *args, **kwargs: _StubR2(),
    )
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        assert _radare2_backends(service, session_id) == []

        result = service.r2_xrefs(session_id, 0x140001000)
        assert result.ok, result.error

        recorded = _radare2_backends(service, session_id)
        assert len(recorded) == 1
        assert recorded[0]["endpoint"] == "pipe"
    finally:
        service.close_all()


def test_repeated_r2_disasm_upserts_a_single_radare2_backend(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """record_backend keys on (session_id, kind), so repeat calls stay one row.

    This is why adding the call to the per-op disasm/xrefs path is safe: a busy
    session that disassembles many addresses keeps a single radare2 entry rather
    than one per call.
    """
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.R2Client",
        lambda *args, **kwargs: _StubR2(),
    )
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]

        for address in (0x140001000, 0x140001010, 0x140001020):
            result = service.r2_disasm(session_id, address)
            assert result.ok, result.error

        assert len(_radare2_backends(service, session_id)) == 1
    finally:
        service.close_all()
