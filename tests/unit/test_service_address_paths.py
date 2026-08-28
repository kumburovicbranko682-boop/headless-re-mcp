"""Error-arm coverage for the address-resolution surface on AnalysisService.

``resolve_runtime_address`` and ``analyze_function_dynamic`` translate between
static, RVA, and runtime coordinate systems and must fail closed: a fatal
worker error has to tear the backend down, a non-fatal one must not, and a
malformed argument must never reach the mapping. The mapping and the runtime
teardown are stubbed so those arms run without a live IDA/x64dbg pair.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.ida.client import IdaWorkerError
from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import BackendKind
from headless_re_mcp.core.service import AnalysisService


def _write_minimal_pe(path: Path) -> None:
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
    image[0x200:0x202] = b"\xc3\x90"
    path.write_bytes(image)


def _service(tmp_path: Path) -> AnalysisService:
    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )
    return AnalysisService(settings)


def _session(service: AnalysisService, tmp_path: Path) -> str:
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None
    return str(created.data["session"]["id"])


# --------------------------------------------------------------------------- #
# resolve_runtime_address argument guards
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("address", [-1, True, 3.0, "0x1000"])
def test_resolve_rejects_a_malformed_address(tmp_path: Path, address: Any) -> None:
    service = _service(tmp_path)
    try:
        session_id = _session(service, tmp_path)
        result = service.resolve_runtime_address(session_id, address)
        assert result.ok is False
        assert result.error is not None
    finally:
        service.close_all()


def test_resolve_rejects_an_unknown_source(tmp_path: Path) -> None:
    service = _service(tmp_path)
    try:
        session_id = _session(service, tmp_path)
        result = service.resolve_runtime_address(session_id, 0x1000, source="galaxy")
        assert result.ok is False
        assert result.error is not None
    finally:
        service.close_all()


# --------------------------------------------------------------------------- #
# resolve_runtime_address worker-error arms
# --------------------------------------------------------------------------- #


def test_resolve_tears_down_ida_on_a_fatal_worker_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    try:
        session_id = _session(service, tmp_path)
        failed: list[tuple[str, BackendKind]] = []

        def raise_fatal(sid: str) -> Any:
            raise IdaWorkerError("worker_exited", "ida died")

        monkeypatch.setattr(service, "_main_module_mapping", raise_fatal)
        monkeypatch.setattr(
            service, "_fail_runtime", lambda sid, kind, **kw: failed.append((sid, kind))
        )

        result = service.resolve_runtime_address(session_id, 0x1000)

        assert result.ok is False
        assert failed == [(session_id, BackendKind.IDA)]
    finally:
        service.close_all()


def test_resolve_keeps_ida_alive_on_a_non_fatal_worker_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    try:
        session_id = _session(service, tmp_path)
        failed: list[Any] = []

        def raise_soft(sid: str) -> Any:
            raise IdaWorkerError("capability_unavailable", "no such feature")

        monkeypatch.setattr(service, "_main_module_mapping", raise_soft)
        monkeypatch.setattr(service, "_fail_runtime", lambda *a, **k: failed.append(a))

        result = service.resolve_runtime_address(session_id, 0x1000)

        assert result.ok is False
        assert failed == [], "a recoverable worker error must not tear the backend down"
    finally:
        service.close_all()


def test_resolve_tears_down_x64dbg_on_a_fatal_rpc_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    try:
        session_id = _session(service, tmp_path)
        failed: list[tuple[str, BackendKind]] = []

        def raise_fatal(sid: str) -> Any:
            raise XdbgRpcError("rpc_protocol_error", "garbled frame")

        monkeypatch.setattr(service, "_main_module_mapping", raise_fatal)
        monkeypatch.setattr(
            service, "_fail_runtime", lambda sid, kind, **kw: failed.append((sid, kind))
        )

        result = service.resolve_runtime_address(session_id, 0x1000)

        assert result.ok is False
        assert failed == [(session_id, BackendKind.X64DBG)]
    finally:
        service.close_all()


# --------------------------------------------------------------------------- #
# analyze_function_dynamic timeout guards
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("timeout", [True, "30", None])
def test_analyze_rejects_a_non_numeric_timeout(tmp_path: Path, timeout: Any) -> None:
    service = _service(tmp_path)
    try:
        session_id = _session(service, tmp_path)
        result = service.analyze_function_dynamic(session_id, 0x1000, timeout=timeout)
        assert result.ok is False
        assert result.error is not None
    finally:
        service.close_all()


@pytest.mark.parametrize("timeout", [0.0, -1.0, 10_000_000.0])
def test_analyze_rejects_an_out_of_range_timeout(tmp_path: Path, timeout: float) -> None:
    service = _service(tmp_path)
    try:
        session_id = _session(service, tmp_path)
        result = service.analyze_function_dynamic(session_id, 0x1000, timeout=timeout)
        assert result.ok is False
        assert result.error is not None
    finally:
        service.close_all()
