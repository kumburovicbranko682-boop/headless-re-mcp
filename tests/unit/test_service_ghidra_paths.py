"""Success and error-envelope coverage for the Ghidra service methods.

``core/service_ext`` exposes ``ghidra_analyze`` plus the export helper
``_ghidra_export`` (behind ``ghidra_functions`` / ``ghidra_symbols`` /
``ghidra_xrefs`` / ``ghidra_decompile``). The closed-session gate in
``test_ghidra_closed_session`` only reaches the pre-run state check and the
mid-run re-check, so each method's happy path (record backend + timeline +
``_success`` envelope), the export-artifact registration branch, the
address-required guards for xrefs/decompile, the unknown-mode guard, and the
``GhidraError`` -> structured-envelope mapping were never run.

Ghidra headless is a portable, non-PE backend, so these fake ``GhidraClient``
and drive the service the way the ghidra closed-session gate already does.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.ghidra.client import GhidraError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.service_ext import _ghidra_export


def _write_minimal_pe(path: Path) -> None:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = (0x8664).to_bytes(2, "little")
    path.write_bytes(image)


class _FakeGhidra:
    """Records each call and returns a fixed payload for the happy path."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        self.calls: list[str] = []

    def analyze_binary(
        self, binary: Path, project_dir: Path, *, timeout: float = 120.0, **kwargs: object
    ) -> dict[str, Any]:
        project_dir.mkdir(parents=True, exist_ok=True)
        self.calls.append("analyze")
        return {"project_dir": str(project_dir), "note": "fake"}

    def functions(
        self,
        binary: Path,
        project_dir: Path,
        *,
        limit: int = 256,
        timeout: float = 180.0,
        **kwargs: object,
    ) -> dict[str, Any]:
        project_dir.mkdir(parents=True, exist_ok=True)
        self.calls.append("functions")
        return {"items": [{"name": "main", "entry": "0x1000"}], "count": 1, "has_more": False}

    def symbols(
        self,
        binary: Path,
        project_dir: Path,
        *,
        limit: int = 256,
        timeout: float = 180.0,
        **kwargs: object,
    ) -> dict[str, Any]:
        project_dir.mkdir(parents=True, exist_ok=True)
        self.calls.append("symbols")
        return {"items": [{"name": "puts"}], "count": 1, "has_more": False}

    def xrefs(
        self,
        binary: Path,
        project_dir: Path,
        address: str | int,
        *,
        limit: int = 256,
        timeout: float = 180.0,
        **kwargs: object,
    ) -> dict[str, Any]:
        project_dir.mkdir(parents=True, exist_ok=True)
        self.calls.append("xrefs")
        return {"items": [], "count": 0, "address": address}

    def decompile(
        self,
        binary: Path,
        project_dir: Path,
        address: str | int,
        *,
        timeout: float = 180.0,
        **kwargs: object,
    ) -> dict[str, Any]:
        project_dir.mkdir(parents=True, exist_ok=True)
        self.calls.append("decompile")
        return {"c": "int main(void){return 0;}", "address": address}


class _FakeGhidraWithExport(_FakeGhidra):
    """functions() writes a real export file so the artifact branch registers it."""

    def functions(
        self,
        binary: Path,
        project_dir: Path,
        *,
        limit: int = 256,
        timeout: float = 180.0,
        **kwargs: object,
    ) -> dict[str, Any]:
        project_dir.mkdir(parents=True, exist_ok=True)
        export = project_dir / "functions.json"
        export.write_text(json.dumps({"items": []}), encoding="utf-8")
        self.calls.append("functions")
        return {
            "items": [{"name": "main"}],
            "count": 1,
            "has_more": False,
            "export_path": str(export),
        }


class _BoomGhidra:
    """Every op raises the same GhidraError so the envelope mapping is uniform."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        pass

    def __getattr__(self, name: str) -> Any:
        def _fn(*args: Any, **kwargs: Any) -> Any:
            raise GhidraError("process_failed", "analyzeHeadless exited non-zero", log="boom")

        return _fn


class _CrashGhidra:
    def __init__(self, *args: object, **kwargs: object) -> None:
        pass

    def __getattr__(self, name: str) -> Any:
        def _fn(*args: Any, **kwargs: Any) -> Any:
            raise RuntimeError("ghidra wrapper blew up")

        return _fn


def _service(tmp_path: Path) -> AnalysisService:
    return AnalysisService(replace(Settings.load(), artifact_root=tmp_path / "artifacts"))


def _pe_session(service: AnalysisService, tmp_path: Path) -> str:
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None, created.error
    return str(created.data["session"]["id"])


def _patch_ghidra(monkeypatch: Any, factory: Any) -> None:
    monkeypatch.setattr("headless_re_mcp.core.service_ext.GhidraClient", factory)


# --------------------------------------------------------------------------- #
# ghidra_analyze                                                               #
# --------------------------------------------------------------------------- #
def test_ghidra_analyze_reports_success(tmp_path: Path, monkeypatch: Any) -> None:
    fake = _FakeGhidra()
    _patch_ghidra(monkeypatch, lambda *a, **k: fake)
    service = _service(tmp_path)
    try:
        session_id = _pe_session(service, tmp_path)
        result = service.ghidra_analyze(session_id)
        assert result.ok, result.error
        assert result.data is not None and result.data["note"] == "fake"
        assert result.meta["backend"] == "ghidra"
        assert fake.calls == ["analyze"]
    finally:
        service.close_all()


def test_ghidra_analyze_maps_a_ghidra_error(tmp_path: Path, monkeypatch: Any) -> None:
    _patch_ghidra(monkeypatch, _BoomGhidra)
    service = _service(tmp_path)
    try:
        session_id = _pe_session(service, tmp_path)
        result = service.ghidra_analyze(session_id)
        assert result.ok is False and result.error is not None
        assert result.error.code == "process_failed"
        assert result.error.details.get("log") == "boom"
    finally:
        service.close_all()


def test_ghidra_analyze_wraps_an_unexpected_error(tmp_path: Path, monkeypatch: Any) -> None:
    _patch_ghidra(monkeypatch, _CrashGhidra)
    service = _service(tmp_path)
    try:
        session_id = _pe_session(service, tmp_path)
        result = service.ghidra_analyze(session_id)
        assert result.ok is False and result.error is not None
        assert result.error.code == "internal_error"
    finally:
        service.close_all()


# --------------------------------------------------------------------------- #
# _ghidra_export happy paths                                                   #
# --------------------------------------------------------------------------- #
def test_ghidra_functions_reports_success(tmp_path: Path, monkeypatch: Any) -> None:
    fake = _FakeGhidra()
    _patch_ghidra(monkeypatch, lambda *a, **k: fake)
    service = _service(tmp_path)
    try:
        session_id = _pe_session(service, tmp_path)
        result = service.ghidra_functions(session_id)
        assert result.ok, result.error
        assert result.data is not None and result.data["count"] == 1
        assert "artifact_id" not in result.data  # no export_path -> no artifact
        assert result.meta["backend"] == "ghidra"
        assert fake.calls == ["functions"]
    finally:
        service.close_all()


def test_ghidra_symbols_reports_success(tmp_path: Path, monkeypatch: Any) -> None:
    fake = _FakeGhidra()
    _patch_ghidra(monkeypatch, lambda *a, **k: fake)
    service = _service(tmp_path)
    try:
        session_id = _pe_session(service, tmp_path)
        result = service.ghidra_symbols(session_id)
        assert result.ok, result.error
        assert result.data is not None and result.data["items"][0]["name"] == "puts"
        assert fake.calls == ["symbols"]
    finally:
        service.close_all()


def test_ghidra_xrefs_reports_success(tmp_path: Path, monkeypatch: Any) -> None:
    fake = _FakeGhidra()
    _patch_ghidra(monkeypatch, lambda *a, **k: fake)
    service = _service(tmp_path)
    try:
        session_id = _pe_session(service, tmp_path)
        result = service.ghidra_xrefs(session_id, "0x1000")
        assert result.ok, result.error
        assert result.data is not None and result.data["address"] == "0x1000"
        assert fake.calls == ["xrefs"]
    finally:
        service.close_all()


def test_ghidra_decompile_reports_success(tmp_path: Path, monkeypatch: Any) -> None:
    fake = _FakeGhidra()
    _patch_ghidra(monkeypatch, lambda *a, **k: fake)
    service = _service(tmp_path)
    try:
        session_id = _pe_session(service, tmp_path)
        result = service.ghidra_decompile(session_id, 0x1000)
        assert result.ok, result.error
        assert result.data is not None and "main" in result.data["c"]
        assert fake.calls == ["decompile"]
    finally:
        service.close_all()


def test_ghidra_export_registers_an_artifact_when_a_file_lands(
    tmp_path: Path, monkeypatch: Any
) -> None:
    _patch_ghidra(monkeypatch, lambda *a, **k: _FakeGhidraWithExport())
    service = _service(tmp_path)
    try:
        session_id = _pe_session(service, tmp_path)
        result = service.ghidra_functions(session_id)
        assert result.ok, result.error
        assert result.data is not None
        assert isinstance(result.data.get("artifact_id"), str)
    finally:
        service.close_all()


# --------------------------------------------------------------------------- #
# _ghidra_export guards                                                        #
# --------------------------------------------------------------------------- #
def test_ghidra_xrefs_requires_an_address(tmp_path: Path, monkeypatch: Any) -> None:
    _patch_ghidra(monkeypatch, lambda *a, **k: _FakeGhidra())
    service = _service(tmp_path)
    try:
        session_id = _pe_session(service, tmp_path)
        result = service.ghidra_xrefs(session_id, None)  # type: ignore[arg-type]
        assert result.ok is False and result.error is not None
        assert result.error.code == "invalid_params"
    finally:
        service.close_all()


def test_ghidra_decompile_requires_an_address(tmp_path: Path, monkeypatch: Any) -> None:
    _patch_ghidra(monkeypatch, lambda *a, **k: _FakeGhidra())
    service = _service(tmp_path)
    try:
        session_id = _pe_session(service, tmp_path)
        result = service.ghidra_decompile(session_id, None)  # type: ignore[arg-type]
        assert result.ok is False and result.error is not None
        assert result.error.code == "invalid_params"
    finally:
        service.close_all()


def test_ghidra_export_rejects_an_unknown_mode(tmp_path: Path, monkeypatch: Any) -> None:
    _patch_ghidra(monkeypatch, lambda *a, **k: _FakeGhidra())
    service = _service(tmp_path)
    try:
        session_id = _pe_session(service, tmp_path)
        result = _ghidra_export(service, session_id, "bogus")
        assert result.ok is False and result.error is not None
        assert result.error.code == "invalid_params"
    finally:
        service.close_all()


def test_ghidra_functions_maps_a_ghidra_error(tmp_path: Path, monkeypatch: Any) -> None:
    _patch_ghidra(monkeypatch, _BoomGhidra)
    service = _service(tmp_path)
    try:
        session_id = _pe_session(service, tmp_path)
        result = service.ghidra_functions(session_id)
        assert result.ok is False and result.error is not None
        assert result.error.code == "process_failed"
    finally:
        service.close_all()
