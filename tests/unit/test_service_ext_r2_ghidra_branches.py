"""Branch coverage for the r2 and Ghidra service mixins (the static-analysis
non-PE backends).

Every other non-PE service layer -- web, apk, device, jsre, proxy, and the
device-aware Frida mixin -- has a fake-backend branch test that drives its
success path and its error mapping without the real tool. r2 and Ghidra were
the exception: the only service-level tests they had (`test_r2_closed_session`,
`test_ghidra_closed_session`) drive the *refusal* branches, so a fully
successful call, the ``R2Error``/``GhidraError`` -> structured-failure mapping,
and (for Ghidra) the export-artifact registration were never exercised through
the service.

These fakes stand in for ``R2Client``/``GhidraClient`` (both module-level
imports in ``service_ext``, so monkeypatching the name reaches every call site).
They pin: a successful call reports ``backend`` and passes the backend payload
through; a backend error becomes a structured failure carrying the backend's
code; an unexpected error is still captured; and a Ghidra export that lands a
file on disk is registered and answered with an ``artifact_id`` while one that
does not is not.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.ghidra.client import GhidraError
from headless_re_mcp.backends.r2.client import R2Error
from headless_re_mcp.config import Settings
from headless_re_mcp.core import service_ext
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.service_ext import _ghidra_export

MP = pytest.MonkeyPatch


def _write_minimal_pe(path: Path) -> None:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = (0x8664).to_bytes(2, "little")
    path.write_bytes(image)


@pytest.fixture
def service(tmp_path: Path) -> Any:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    svc = AnalysisService(settings)
    try:
        yield svc
    finally:
        svc.close_all()


def _session(service: AnalysisService, tmp_path: Path) -> str:
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None, created.error
    return str(created.data["session"]["id"])


class _FakeR2:
    """A radare2 client that answers every whitelisted call with a payload."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        pass

    def open(self, binary: Path, *, timeout: float = 30.0) -> dict[str, Any]:
        del binary, timeout
        return {"opened": True, "binary": "sample", "info": "elf"}

    def run(
        self, binary: Path, commands: list[str], *, timeout: float = 30.0
    ) -> dict[str, Any]:
        del binary, timeout
        return {"raw": "ok", "commands": list(commands), "items": [], "count": 0}

    def disasm(
        self, binary: Path, address: int, *, count: int = 32, timeout: float = 30.0
    ) -> dict[str, Any]:
        del binary, timeout
        return {"address": address, "count": count, "instructions": []}

    def xrefs(self, binary: Path, address: int, *, timeout: float = 30.0) -> dict[str, Any]:
        del binary, timeout
        return {"address": address, "xrefs": []}


class TestR2Success:
    def test_open_reports_backend_and_passes_payload_through(
        self, service: AnalysisService, tmp_path: Path, monkeypatch: MP
    ) -> None:
        monkeypatch.setattr(service_ext, "R2Client", _FakeR2)
        sid = _session(service, tmp_path)
        result = service.r2_open(sid)
        assert result.ok is True and result.data is not None, result.error
        assert result.data["opened"] is True
        assert result.meta["backend"] == "radare2"

    @pytest.mark.parametrize(
        "call",
        [
            lambda s, sid: s.r2_info(sid),
            lambda s, sid: s.r2_functions(sid),
            lambda s, sid: s.r2_strings(sid),
            lambda s, sid: s.r2_imports(sid),
            lambda s, sid: s.r2_exports(sid),
        ],
    )
    def test_whitelisted_request_calls_succeed(
        self,
        service: AnalysisService,
        tmp_path: Path,
        monkeypatch: MP,
        call: Any,
    ) -> None:
        monkeypatch.setattr(service_ext, "R2Client", _FakeR2)
        sid = _session(service, tmp_path)
        result = call(service, sid)
        assert result.ok is True and result.data is not None, result.error
        assert result.meta["backend"] == "radare2"
        assert "commands" in result.data

    def test_disasm_passes_address_and_count_through(
        self, service: AnalysisService, tmp_path: Path, monkeypatch: MP
    ) -> None:
        monkeypatch.setattr(service_ext, "R2Client", _FakeR2)
        sid = _session(service, tmp_path)
        result = service.r2_disasm(sid, address=0x401000, count=8)
        assert result.ok is True and result.data is not None, result.error
        assert result.data["address"] == 0x401000
        assert result.data["count"] == 8

    def test_xrefs_passes_address_through(
        self, service: AnalysisService, tmp_path: Path, monkeypatch: MP
    ) -> None:
        monkeypatch.setattr(service_ext, "R2Client", _FakeR2)
        sid = _session(service, tmp_path)
        result = service.r2_xrefs(sid, address=0x401234)
        assert result.ok is True and result.data is not None, result.error
        assert result.data["address"] == 0x401234


class TestR2ErrorMapping:
    @pytest.mark.parametrize(
        ("method", "call"),
        [
            ("open", lambda s, sid: s.r2_open(sid)),
            ("run", lambda s, sid: s.r2_functions(sid)),
            ("disasm", lambda s, sid: s.r2_disasm(sid, address=0x1000)),
            ("xrefs", lambda s, sid: s.r2_xrefs(sid, address=0x1000)),
        ],
    )
    def test_backend_error_becomes_a_structured_failure(
        self,
        service: AnalysisService,
        tmp_path: Path,
        monkeypatch: MP,
        method: str,
        call: Any,
    ) -> None:
        class _Err(_FakeR2):
            def _raise(self, *_a: object, **_k: object) -> dict[str, Any]:
                raise R2Error("capability_unavailable", "no radare2")

        setattr(_Err, method, _Err._raise)
        monkeypatch.setattr(service_ext, "R2Client", _Err)
        sid = _session(service, tmp_path)
        result = call(service, sid)
        assert result.ok is False and result.error is not None
        assert result.error.code == "capability_unavailable"

    def test_unexpected_error_is_captured(
        self, service: AnalysisService, tmp_path: Path, monkeypatch: MP
    ) -> None:
        class _Boom(_FakeR2):
            def run(self, *_a: object, **_k: object) -> dict[str, Any]:
                raise RuntimeError("kaboom")

        monkeypatch.setattr(service_ext, "R2Client", _Boom)
        sid = _session(service, tmp_path)
        assert service.r2_functions(sid).ok is False


class TestR2CloseRace:
    """The same close-race guard r2.open and Ghidra already enforce, on the
    r2 siblings that route through r2_disasm/r2_xrefs/_r2_request.

    A retained CLOSED session still resolves, and a session can close while the
    r2 call is in flight; either way the call must be refused and the backend
    must never be recorded against a session that can no longer use it. r2.open
    and both Ghidra entry points are already pinned; these extend the identical
    property to the remaining r2 doors so the guard cannot silently regress on
    one of them.
    """

    def test_disasm_on_a_closed_session_is_refused(
        self, service: AnalysisService, tmp_path: Path, monkeypatch: MP
    ) -> None:
        monkeypatch.setattr(service_ext, "R2Client", _FakeR2)
        sid = _session(service, tmp_path)
        assert service.close_session(sid).ok
        result = service.r2_disasm(sid, address=0x1000)
        assert result.ok is False and result.error is not None
        assert result.error.code == "invalid_request"
        assert "closed" in result.error.message

    def test_xrefs_on_a_closed_session_is_refused(
        self, service: AnalysisService, tmp_path: Path, monkeypatch: MP
    ) -> None:
        monkeypatch.setattr(service_ext, "R2Client", _FakeR2)
        sid = _session(service, tmp_path)
        assert service.close_session(sid).ok
        result = service.r2_xrefs(sid, address=0x1000)
        assert result.ok is False and result.error is not None
        assert result.error.code == "invalid_request"
        assert "closed" in result.error.message

    def test_disasm_closing_mid_run_is_refused(
        self, service: AnalysisService, tmp_path: Path, monkeypatch: MP
    ) -> None:
        sid = _session(service, tmp_path)

        class _CloseThenDisasm(_FakeR2):
            def disasm(
                self, binary: Path, address: int, *, count: int = 32, timeout: float = 30.0
            ) -> dict[str, Any]:
                service.close_session(sid)
                return super().disasm(binary, address, count=count, timeout=timeout)

        monkeypatch.setattr(service_ext, "R2Client", _CloseThenDisasm)
        result = service.r2_disasm(sid, address=0x1000)
        assert result.ok is False and result.error is not None
        assert result.error.code == "invalid_request"
        assert "closed" in result.error.message

    def test_xrefs_closing_mid_run_is_refused(
        self, service: AnalysisService, tmp_path: Path, monkeypatch: MP
    ) -> None:
        sid = _session(service, tmp_path)

        class _CloseThenXrefs(_FakeR2):
            def xrefs(
                self, binary: Path, address: int, *, timeout: float = 30.0
            ) -> dict[str, Any]:
                service.close_session(sid)
                return super().xrefs(binary, address, timeout=timeout)

        monkeypatch.setattr(service_ext, "R2Client", _CloseThenXrefs)
        result = service.r2_xrefs(sid, address=0x1000)
        assert result.ok is False and result.error is not None
        assert result.error.code == "invalid_request"
        assert "closed" in result.error.message

    def test_whitelisted_request_closing_mid_run_is_refused(
        self, service: AnalysisService, tmp_path: Path, monkeypatch: MP
    ) -> None:
        sid = _session(service, tmp_path)

        class _CloseThenRun(_FakeR2):
            def run(
                self, binary: Path, commands: list[str], *, timeout: float = 30.0
            ) -> dict[str, Any]:
                service.close_session(sid)
                return super().run(binary, commands, timeout=timeout)

        monkeypatch.setattr(service_ext, "R2Client", _CloseThenRun)
        result = service.r2_info(sid)
        assert result.ok is False and result.error is not None
        assert result.error.code == "invalid_request"
        assert "closed" in result.error.message


class _FakeGhidra:
    """A Ghidra client whose export helpers land a real file on disk."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        pass

    def analyze_binary(
        self, binary: Path, project: Path, *, timeout: float = 120.0
    ) -> dict[str, Any]:
        del binary, timeout
        return {"analyzed": True, "project_dir": str(project)}

    def _export(self, project: Path, mode: str) -> dict[str, Any]:
        project.mkdir(parents=True, exist_ok=True)
        export = project / f"{mode}.json"
        export.write_text('{"items": []}', encoding="utf-8")
        return {
            "items": [],
            "count": 0,
            "export_path": str(export),
            "project_dir": str(project),
        }

    def functions(
        self, binary: Path, project: Path, *, limit: int = 256, timeout: float = 180.0
    ) -> dict[str, Any]:
        del binary, limit, timeout
        return self._export(project, "functions")

    def symbols(
        self, binary: Path, project: Path, *, limit: int = 256, timeout: float = 180.0
    ) -> dict[str, Any]:
        del binary, limit, timeout
        return self._export(project, "symbols")

    def xrefs(
        self,
        binary: Path,
        project: Path,
        address: str | int,
        *,
        limit: int = 256,
        timeout: float = 180.0,
    ) -> dict[str, Any]:
        del binary, address, limit, timeout
        return self._export(project, "xrefs")

    def decompile(
        self, binary: Path, project: Path, address: str | int, *, timeout: float = 180.0
    ) -> dict[str, Any]:
        del binary, address, timeout
        # No export file on disk: the service must not invent an artifact_id.
        return {"decompiled": "int main(){}", "found": True}


class TestGhidraSuccess:
    def test_analyze_reports_backend(
        self, service: AnalysisService, tmp_path: Path, monkeypatch: MP
    ) -> None:
        monkeypatch.setattr(service_ext, "GhidraClient", _FakeGhidra)
        sid = _session(service, tmp_path)
        result = service.ghidra_analyze(sid)
        assert result.ok is True and result.data is not None, result.error
        assert result.data["analyzed"] is True
        assert result.meta["backend"] == "ghidra"

    @pytest.mark.parametrize("mode", ["functions", "symbols"])
    def test_listing_export_registers_an_artifact(
        self,
        service: AnalysisService,
        tmp_path: Path,
        monkeypatch: MP,
        mode: str,
    ) -> None:
        monkeypatch.setattr(service_ext, "GhidraClient", _FakeGhidra)
        sid = _session(service, tmp_path)
        result = getattr(service, f"ghidra_{mode}")(sid)
        assert result.ok is True and result.data is not None, result.error
        # The export landed on disk, so it is registered and handed back.
        assert result.data["artifact_id"]
        assert Path(result.data["export_path"]).is_file()

    def test_xrefs_export_registers_an_artifact(
        self, service: AnalysisService, tmp_path: Path, monkeypatch: MP
    ) -> None:
        monkeypatch.setattr(service_ext, "GhidraClient", _FakeGhidra)
        sid = _session(service, tmp_path)
        result = service.ghidra_xrefs(sid, address="0x401000")
        assert result.ok is True and result.data is not None, result.error
        assert result.data["artifact_id"]

    def test_decompile_without_a_file_has_no_artifact_id(
        self, service: AnalysisService, tmp_path: Path, monkeypatch: MP
    ) -> None:
        monkeypatch.setattr(service_ext, "GhidraClient", _FakeGhidra)
        sid = _session(service, tmp_path)
        result = service.ghidra_decompile(sid, address="0x401000")
        assert result.ok is True and result.data is not None, result.error
        assert result.data["found"] is True
        assert "artifact_id" not in result.data


class TestGhidraErrorAndParams:
    def test_analyze_backend_error_becomes_a_structured_failure(
        self, service: AnalysisService, tmp_path: Path, monkeypatch: MP
    ) -> None:
        class _Err(_FakeGhidra):
            def analyze_binary(self, *_a: object, **_k: object) -> dict[str, Any]:
                raise GhidraError("capability_unavailable", "no ghidra")

        monkeypatch.setattr(service_ext, "GhidraClient", _Err)
        sid = _session(service, tmp_path)
        result = service.ghidra_analyze(sid)
        assert result.ok is False and result.error is not None
        assert result.error.code == "capability_unavailable"

    def test_export_backend_error_becomes_a_structured_failure(
        self, service: AnalysisService, tmp_path: Path, monkeypatch: MP
    ) -> None:
        class _Err(_FakeGhidra):
            def functions(self, *_a: object, **_k: object) -> dict[str, Any]:
                raise GhidraError("backend_error", "analyzeHeadless failed")

        monkeypatch.setattr(service_ext, "GhidraClient", _Err)
        sid = _session(service, tmp_path)
        result = service.ghidra_functions(sid)
        assert result.ok is False and result.error is not None
        assert result.error.code == "backend_error"

    def test_xrefs_without_an_address_is_invalid_params(
        self, service: AnalysisService, tmp_path: Path, monkeypatch: MP
    ) -> None:
        monkeypatch.setattr(service_ext, "GhidraClient", _FakeGhidra)
        sid = _session(service, tmp_path)
        result = _ghidra_export(service, sid, "xrefs", address=None)
        assert result.ok is False and result.error is not None
        assert result.error.code == "invalid_params"

    def test_decompile_without_an_address_is_invalid_params(
        self, service: AnalysisService, tmp_path: Path, monkeypatch: MP
    ) -> None:
        monkeypatch.setattr(service_ext, "GhidraClient", _FakeGhidra)
        sid = _session(service, tmp_path)
        result = _ghidra_export(service, sid, "decompile", address=None)
        assert result.ok is False and result.error is not None
        assert result.error.code == "invalid_params"

    def test_unknown_export_mode_is_invalid_params(
        self, service: AnalysisService, tmp_path: Path, monkeypatch: MP
    ) -> None:
        monkeypatch.setattr(service_ext, "GhidraClient", _FakeGhidra)
        sid = _session(service, tmp_path)
        result = _ghidra_export(service, sid, "bogus")
        assert result.ok is False and result.error is not None
        assert result.error.code == "invalid_params"
