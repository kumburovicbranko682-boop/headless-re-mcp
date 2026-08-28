"""Device-free guard/error contract for the r2 and Ghidra service methods.

``ExtAnalysisMixin.r2_*``/``ghidra_*`` spawn radare2 / analyzeHeadless behind a
session. The happy paths run under the live gates and the analysis-pass seam is
pinned in test_r2_service_analysis_pass; the closed-session refusal is pinned for
r2.open and the shared _r2_request path in test_r2_closed_session. What was left,
and what this closes, are the same three guards on the methods that carry their
own copy of them -- disasm, xrefs, xrefs_to, xrefs_from -- plus r2.open's success
recording and the ghidra.analyze error map:

- a method invoked on a CLOSED session refuses before constructing the client,
  so a retained-but-dead session never starts a tool (fail-closed, pre-call);
- a session that closes *during* the spawn is not reported as analyzed, even
  though the backend returned data (fail-closed, post-call race);
- a backend R2Error/GhidraError surfaces as the same structured code the tool
  raised, not a bare exception.

Every backend is a fake, so this proves the service contract with no r2, no
Ghidra and no device.
"""

from __future__ import annotations

import struct
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.core.service_ext as service_ext
from headless_re_mcp.backends.ghidra.client import GhidraError
from headless_re_mcp.backends.r2.client import R2Error
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_R2_METHODS = ["r2_open", "r2_disasm", "r2_xrefs", "r2_xrefs_to", "r2_xrefs_from"]


def _write_minimal_elf(path: Path) -> None:
    # A 64-bit x86-64 ELF ident: enough for classify_target to route ELF and for
    # detect_elf_architecture to name x64. The r2 client is faked, so no real
    # program headers are needed -- the session just has to open as a native ELF.
    data = bytearray(64)
    data[:4] = b"\x7fELF"
    data[4] = 2  # 64-bit
    data[5] = 1  # little-endian
    struct.pack_into("<H", data, 18, 0x3E)  # EM_X86_64
    path.write_bytes(bytes(data))


class _FakeR2:
    """A stand-in R2Client that records calls, can raise, or run a side effect."""

    def __init__(
        self, *, error: Exception | None = None, side_effect: Callable[[], None] | None = None
    ) -> None:
        self.error = error
        self.side_effect = side_effect
        self.calls = 0

    def _run(self) -> dict[str, Any]:
        self.calls += 1
        if self.side_effect is not None:
            self.side_effect()
        if self.error is not None:
            raise self.error
        return {
            "opened": True,
            "binary": "x",
            "info": "i",
            "note": "faked",
            "raw": "ok",
            "commands": [],
        }

    def open(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return self._run()

    def disasm(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return self._run()

    def xrefs(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return self._run()

    def xrefs_to(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return self._run()

    def xrefs_from(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return self._run()


def _service(tmp_path: Path) -> AnalysisService:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    return AnalysisService(settings)


def _elf_session(service: AnalysisService, tmp_path: Path) -> str:
    binary = tmp_path / "sample.elf"
    _write_minimal_elf(binary)
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None, created.error
    return str(created.data["session"]["id"])


def _invoke(service: AnalysisService, method: str, session_id: str) -> Any:
    if method == "r2_open":
        return service.r2_open(session_id)
    if method == "r2_disasm":
        return service.r2_disasm(session_id, 0x1000)
    if method == "r2_xrefs":
        return service.r2_xrefs(session_id, 0x1000)
    if method == "r2_xrefs_to":
        return service.r2_xrefs_to(session_id, 0x1000)
    if method == "r2_xrefs_from":
        return service.r2_xrefs_from(session_id, 0x1000)
    raise AssertionError(method)


@pytest.mark.parametrize("method", _R2_METHODS)
def test_r2_method_refuses_a_closed_session_before_spawning(
    method: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _FakeR2()
    monkeypatch.setattr(service_ext, "R2Client", lambda *a, **k: fake)
    service = _service(tmp_path)
    try:
        session_id = _elf_session(service, tmp_path)
        assert service.close_session(session_id).ok
        result = _invoke(service, method, session_id)
        assert result.ok is False and result.error is not None
        assert result.error.code == "invalid_request", result.error
        assert "closed" in result.error.message.lower()
        assert fake.calls == 0  # the pre-call guard fired before touching the client
    finally:
        service.close_all()


@pytest.mark.parametrize("method", _R2_METHODS)
def test_r2_method_fails_closed_if_the_session_closes_mid_spawn(
    method: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    holder: dict[str, str] = {}
    fake = _FakeR2(side_effect=lambda: service.close_session(holder["session_id"]))
    monkeypatch.setattr(service_ext, "R2Client", lambda *a, **k: fake)
    try:
        session_id = _elf_session(service, tmp_path)
        holder["session_id"] = session_id
        result = _invoke(service, method, session_id)
        assert result.ok is False and result.error is not None
        assert result.error.code == "invalid_request", result.error
        # The spawn happened, but the post-call guard withheld success on a
        # session that closed underneath it.
        assert fake.calls == 1
    finally:
        service.close_all()


@pytest.mark.parametrize("method", _R2_METHODS)
def test_r2_method_maps_a_backend_error_to_its_code(
    method: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _FakeR2(error=R2Error("backend_error", "radare2 exploded"))
    monkeypatch.setattr(service_ext, "R2Client", lambda *a, **k: fake)
    service = _service(tmp_path)
    try:
        session_id = _elf_session(service, tmp_path)
        result = _invoke(service, method, session_id)
        assert result.ok is False and result.error is not None
        assert result.error.code == "backend_error", result.error
        assert "radare2 exploded" in result.error.message
    finally:
        service.close_all()


def test_r2_open_records_the_backend_on_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The success tail of r2.open: it records the radare2 backend and returns the
    # client's payload. Driven with a fake so it runs without radare2 on the box.
    fake = _FakeR2()
    monkeypatch.setattr(service_ext, "R2Client", lambda *a, **k: fake)
    service = _service(tmp_path)
    try:
        session_id = _elf_session(service, tmp_path)
        result = service.r2_open(session_id)
        assert result.ok and result.data is not None, result.error
        assert result.data["opened"] is True
        assert fake.calls == 1
    finally:
        service.close_all()


def test_ghidra_analyze_maps_a_backend_error_to_its_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _FakeGhidra:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def analyze_binary(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            raise GhidraError("backend_error", "analyzeHeadless failed")

    monkeypatch.setattr(service_ext, "GhidraClient", _FakeGhidra)
    service = _service(tmp_path)
    try:
        session_id = _elf_session(service, tmp_path)
        result = service.ghidra_analyze(session_id)
        assert result.ok is False and result.error is not None
        assert result.error.code == "backend_error", result.error
        assert "analyzeHeadless failed" in result.error.message
    finally:
        service.close_all()
